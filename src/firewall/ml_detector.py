from dataclasses import dataclass
from typing import Optional, Dict, Any
from pathlib import Path
import json
import time
import joblib

from src.pipeline.schema import ParsedRequest
from src.pipeline.feature_builder import build_features

ROOT = Path(__file__).resolve().parents[2]
FROZEN_MANIFEST_PATH = ROOT / "models/frozen/v1_0/model_manifest.json"
FROZEN_TFIDF_PATH = ROOT / "models/frozen/v1_0/tfidf/tfidf_logistic_baseline.joblib"
FROZEN_TRANSFORMER_DIR = ROOT / "models/frozen/v1_0/transformer"

DEFAULT_TFIDF_PATH = FROZEN_TFIDF_PATH if FROZEN_TFIDF_PATH.exists() else (ROOT / "models/saved/tfidf_logistic_baseline.joblib")
DEFAULT_TRANSFORMER_DIR = FROZEN_TRANSFORMER_DIR if FROZEN_TRANSFORMER_DIR.exists() else (ROOT / "models/saved/transformer_waf")
DEFAULT_CALIBRATED_PATH = ROOT / "models/saved/calibrated_thresholds.json"


@dataclass
class MLScoringResult:
    layer: str  # 'L2_TFIDF', 'L3_TRANSFORMER', or 'L2_FAST_PASS'
    risk_score: float  # [0.0, 1.0] probability of malicious
    is_malicious: bool
    latency_ms: float
    details: Dict[str, Any]


class MLDetector:
    """
    Middleware managing Layer 2 (Fast TF-IDF) and Layer 3 (Contextual Transformer).
    Provides hierarchical tiered inference:
    - Tier 1: Microsecond TF-IDF triage.
    - Tier 2: Deep Transformer contextual evaluation for suspicious or ambiguous requests.
    """

    def __init__(
        self,
        tfidf_model_path: Optional[str] = None,
        transformer_model_dir: Optional[str] = None,
        fast_pass_threshold: Optional[float] = None,    # Below this, L2 considers it definitively benign
        transformer_block_threshold: Optional[float] = None,
        device: Optional[str] = None,
        max_length: int = 192,
        use_fp16: bool = True,
    ):
        # Load calibrated thresholds if available
        calibrated_cfg = {}
        if DEFAULT_CALIBRATED_PATH.exists():
            try:
                with open(DEFAULT_CALIBRATED_PATH, "r", encoding="utf-8") as f:
                    calibrated_cfg = json.load(f)
            except Exception:
                pass

        if fast_pass_threshold is not None:
            self.fast_pass_threshold = fast_pass_threshold
        else:
            self.fast_pass_threshold = float(calibrated_cfg.get("tau_fast_pass", 0.05))

        if transformer_block_threshold is not None:
            self.transformer_block_threshold = transformer_block_threshold
        else:
            self.transformer_block_threshold = float(calibrated_cfg.get("tau_strict_block", 0.50))

        self.device = device
        self.max_length = max_length
        self.use_fp16 = use_fp16

        # Auto-detect TFIDF path
        if tfidf_model_path is None and DEFAULT_TFIDF_PATH.exists():
            tfidf_model_path = str(DEFAULT_TFIDF_PATH)

        self.tfidf_pipeline = None
        if tfidf_model_path and Path(tfidf_model_path).exists():
            self.tfidf_pipeline = joblib.load(tfidf_model_path)

        # Auto-detect Transformer dir
        if transformer_model_dir is None and DEFAULT_TRANSFORMER_DIR.exists():
            transformer_model_dir = str(DEFAULT_TRANSFORMER_DIR)

        self.transformer_model = None
        self.transformer_tokenizer = None
        self.transformer_model_dir = transformer_model_dir
        if transformer_model_dir and Path(transformer_model_dir).exists():
            self._load_transformer(transformer_model_dir)

    def _load_transformer(self, model_dir: str):
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            if self.device is None:
                self.device = "cuda" if torch.cuda.is_available() else "cpu"

            self.transformer_tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=Path(model_dir).exists())
            self.transformer_model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=Path(model_dir).exists())
            self.transformer_model.to(self.device)
            self.transformer_model.eval()

            if self.use_fp16 and self.device.startswith("cuda"):
                self.transformer_model = self.transformer_model.half()
        except Exception as e:
            print(f"[MLDetector] Warning: Could not load transformer from {model_dir}: {e}")
            self.transformer_model = None
            self.transformer_tokenizer = None

    def score_l2_tfidf(self, req: ParsedRequest) -> MLScoringResult:
        """
        Layer 2: Fast microsecond character TF-IDF evaluation.
        """
        t0 = time.perf_counter()
        if self.tfidf_pipeline is None:
            return MLScoringResult(
                layer="L2_TFIDF",
                risk_score=0.0,
                is_malicious=False,
                latency_ms=0.0,
                details={"status": "tfidf_model_not_loaded"},
            )

        feat = build_features(req, representation="structured")
        if not feat.strip():
            feat = "<EMPTY>"

        # Predict probability for 'malicious'
        classes = list(self.tfidf_pipeline.classes_)
        proba = self.tfidf_pipeline.predict_proba([feat])[0]
        mal_idx = classes.index("malicious") if "malicious" in classes else 1
        risk = float(proba[mal_idx])
        latency = (time.perf_counter() - t0) * 1000.0

        return MLScoringResult(
            layer="L2_TFIDF",
            risk_score=round(risk, 4),
            is_malicious=(risk >= 0.50),
            latency_ms=round(latency, 3),
            details={"classes": classes, "proba": proba.tolist()},
        )

    def score_l3_transformer(self, req: ParsedRequest) -> MLScoringResult:
        """
        Layer 3: Deep Context-Aware Transformer evaluation.
        """
        t0 = time.perf_counter()
        if self.transformer_model is None or self.transformer_tokenizer is None:
            # Fallback to L2 if transformer is not yet loaded
            l2_res = self.score_l2_tfidf(req)
            l2_res.layer = "L3_TRANSFORMER_FALLBACK"
            return l2_res

        import torch

        feat = build_features(req, representation="structured")
        if not feat.strip():
            feat = "[METHOD] GET [PATH] /"

        inputs = self.transformer_tokenizer(
            feat,
            max_length=self.max_length,
            padding=True,
            truncation=True,
            return_tensors="pt",
        ).to(self.device)

        with torch.inference_mode():
            outputs = self.transformer_model(**inputs)
            logits = outputs.logits
            if self.use_fp16 and self.device.startswith("cuda"):
                logits = logits.float()
            probs = torch.softmax(logits, dim=-1).squeeze().tolist()
            # Assumes class 1 is malicious
            risk = float(probs[1]) if isinstance(probs, list) and len(probs) > 1 else float(probs)

        latency = (time.perf_counter() - t0) * 1000.0
        return MLScoringResult(
            layer="L3_TRANSFORMER",
            risk_score=round(risk, 4),
            is_malicious=(risk >= self.transformer_block_threshold),
            latency_ms=round(latency, 3),
            details={"device": self.device},
        )

    def evaluate_hierarchical(self, req: ParsedRequest) -> MLScoringResult:
        """
        Hierarchical evaluation pipeline:
        1. Fast L2 TF-IDF filter.
        2. If risk is very low (< fast_pass_threshold), return immediately (sub-millisecond fast pass).
        3. Otherwise, escalate to L3 Transformer for deep contextual verification.
        """
        l2_result = self.score_l2_tfidf(req)

        # Fast-path shortcut for unambiguously benign traffic
        if self.tfidf_pipeline is not None and l2_result.risk_score < self.fast_pass_threshold:
            return MLScoringResult(
                layer="L2_FAST_PASS",
                risk_score=l2_result.risk_score,
                is_malicious=False,
                latency_ms=l2_result.latency_ms,
                details={"l2_score": l2_result.risk_score, "escalated": False},
            )

        # Escalate to Transformer
        l3_result = self.score_l3_transformer(req)
        l3_result.details["l2_pre_score"] = l2_result.risk_score
        l3_result.details["escalated"] = True
        return l3_result
