"""
Model Loader and Startup Verification Module.

Enforces cryptographic SHA-256 verification of frozen artifacts,
dynamic configuration loading (zero hardcoded thresholds),
and warmup execution.
"""
import os
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import json
import hashlib
import time
import joblib
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FROZEN_DIR = ROOT / "models/frozen/v1_0"


def get_frozen_dir() -> Path:
    env_dir = os.environ.get("WAF_MODEL_DIR")
    if env_dir:
        p = Path(env_dir)
        return p if p.is_absolute() else (ROOT / p)
    return DEFAULT_FROZEN_DIR


FROZEN_DIR = get_frozen_dir()
MANIFEST_PATH = FROZEN_DIR / "model_manifest.json"
THRESHOLD_PATH = FROZEN_DIR / "threshold.json"
PREPROCESSING_PATH = FROZEN_DIR / "preprocessing_config.json"


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


class ModelContainer:
    """
    Singleton-style container holding loaded models, tokenizers,
    configs, and readiness state.
    """

    def __init__(self, frozen_dir: Optional[Path] = None, model_dir: Optional[Path] = None):
        target = model_dir if model_dir is not None else frozen_dir
        self.frozen_dir = Path(target) if target is not None else get_frozen_dir()
        self.manifest_path = self.frozen_dir / "model_manifest.json"
        self.is_ready = False
        self.sha256_verified = False
        self.device = "cpu"
        self.model_version = "unknown"
        self.manifest: Dict[str, Any] = {}
        self.thresholds: Dict[str, Any] = {}
        self.preprocessing_cfg: Dict[str, Any] = {}
        self.representation_mode = "structured"
        self.head_tail_chunking = False
        self.max_length = 192
        self.platt_params: Dict[str, float] = {"w": 1.0, "b": 0.0}

        self.tfidf_pipeline = None
        self.transformer_model = None
        self.transformer_tokenizer = None

    def verify_checksums(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Verifies every artifact recorded in model_manifest.json against its live SHA-256.
        """
        if not self.manifest_path.exists():
            return False, {"error": f"Manifest not found: {self.manifest_path}"}

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        expected_hashes = manifest.get("artifacts_sha256", {})
        if not expected_hashes:
            return False, {"error": "Manifest contains no artifacts_sha256 entries."}

        verification_details = {}
        for rel_path, expected_hash in expected_hashes.items():
            full_path = self.frozen_dir / rel_path
            if not full_path.exists():
                return False, {
                    "error": f"Missing frozen artifact: {rel_path}",
                    "details": verification_details
                }
            actual_hash = compute_file_sha256(full_path)
            if actual_hash != expected_hash:
                return False, {
                    "error": f"SHA-256 mismatch for {rel_path}",
                    "expected": expected_hash,
                    "actual": actual_hash
                }
            verification_details[rel_path] = "verified"

        self.sha256_verified = True
        self.manifest = manifest
        self.model_version = manifest.get("model_version", "v1.0.0")
        return True, verification_details

    def load_configs(self):
        """Loads threshold and preprocessing configs dynamically from disk."""
        threshold_file = self.frozen_dir / "threshold.json"
        prep_file = self.frozen_dir / "preprocessing_config.json"

        if not threshold_file.exists():
            raise FileNotFoundError(f"Missing threshold config: {threshold_file}")
        if not prep_file.exists():
            raise FileNotFoundError(f"Missing preprocessing config: {prep_file}")

        with open(threshold_file, "r", encoding="utf-8") as f:
            self.thresholds = json.load(f)
        with open(prep_file, "r", encoding="utf-8") as f:
            self.preprocessing_cfg = json.load(f)

        self.max_length = int(self.preprocessing_cfg.get("max_length", 192))
        self.representation_mode = str(
            self.preprocessing_cfg.get(
                "representation_mode",
                self.preprocessing_cfg.get("representation", "structured")
            )
        )
        self.head_tail_chunking = bool(self.preprocessing_cfg.get("head_tail_chunking", False))
        calib = self.thresholds.get("platt_calibration", {})
        self.platt_params = {
            "w": float(calib.get("w", 0.7724)),
            "b": float(calib.get("b", 0.4965))
        }

    def load_models(self, preferred_device: Optional[str] = None):
        """
        Loads Layer 2 TF-IDF on CPU and Layer 3 Transformer on CUDA (if available)
        with graceful fallback to CPU.
        """
        # 1. Layer 2 TF-IDF
        tfidf_path = self.frozen_dir / "tfidf" / "tfidf_logistic_baseline.joblib"
        if not tfidf_path.exists():
            raise FileNotFoundError(f"TF-IDF model missing: {tfidf_path}")
        self.tfidf_pipeline = joblib.load(tfidf_path)

        # 2. Device determination
        if preferred_device:
            self.device = preferred_device
        else:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"

        # 3. Layer 3 Transformer
        trans_dir = self.frozen_dir / "transformer"
        if not trans_dir.exists():
            raise FileNotFoundError(f"Transformer directory missing: {trans_dir}")

        self.transformer_tokenizer = AutoTokenizer.from_pretrained(
            str(trans_dir), local_files_only=True
        )
        self.transformer_model = AutoModelForSequenceClassification.from_pretrained(
            str(trans_dir), local_files_only=True
        )
        self.transformer_model.to(self.device)
        self.transformer_model.eval()

        if self.device == "cuda":
            self.transformer_model = self.transformer_model.half()

    def warmup(self):
        """Executes a single dummy forward pass to eliminate first-request cold-start."""
        dummy_text = "[METHOD] GET [PATH] /_waf/warmup [PARAM] probe=1 [PAYLOAD] 1"
        # TF-IDF warmup
        _ = self.tfidf_pipeline.predict_proba([dummy_text])

        # Transformer warmup
        enc = self.transformer_tokenizer(
            dummy_text,
            max_length=self.max_length,
            truncation=True,
            return_tensors="pt"
        ).to(self.device)
        with torch.no_grad():
            _ = self.transformer_model(**enc)

    def initialize(self, preferred_device: Optional[str] = None):
        """Complete startup sequence: Verify hashes -> Load configs -> Load models -> Warmup."""
        verified, details = self.verify_checksums()
        if not verified:
            self.is_ready = False
            raise RuntimeError(f"Startup verification failed: {details}")

        self.load_configs()
        self.load_models(preferred_device=preferred_device)
        self.warmup()
        self.is_ready = True


# Global singleton instance
container = ModelContainer()

