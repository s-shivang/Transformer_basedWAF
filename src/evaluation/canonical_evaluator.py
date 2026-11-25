"""
Canonical Evaluator for Transformer-WAF Models.

Guarantees:
1. Exact HTTP payload syntax preservation (no string replacements, uncorrupted URL query strings and post bodies).
2. Manifest-declared representation alignment: each frozen model checkpoint (v1_0, v2_1, v2_2)
   is fed the exact representation string specified in its manifest/preprocessing_config.json
   and matches src/ml_service/inference_engine.py byte-for-byte.
3. Independent confusion matrix & classification metric recomputation from raw probability arrays.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import math
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

from src.ml_service.model_loader import ModelContainer
from src.ml_service.inference_engine import InferenceEngine
from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features


class CanonicalEvaluator:
    """
    Evaluates frozen WAF checkpoints with byte-for-byte preprocessing parity against InferenceEngine.
    """

    def __init__(self, model_dir: Path, preferred_device: Optional[str] = None):
        self.model_dir = Path(model_dir)
        self.container = ModelContainer(model_dir=self.model_dir)
        self.container.initialize(preferred_device=preferred_device)
        self.engine = InferenceEngine(self.container)

        self.representation_mode = self.container.representation_mode
        self.head_tail_chunking = self.container.head_tail_chunking
        self.max_length = self.container.max_length

    def preprocess_request(self, raw_http: str) -> str:
        """
        Parses raw HTTP and extracts structural representation exactly as runtime does.
        """
        try:
            parsed = parse_raw_http(raw_http)
            feat = build_features(parsed, representation=self.representation_mode)
        except Exception:
            feat = "[METHOD] GET [PATH] /"
        if not feat or not feat.strip():
            feat = "[METHOD] GET [PATH] /"
        return feat

    def predict_single(self, raw_http: str) -> float:
        """
        Predict probability for a single raw HTTP request using InferenceEngine directly.
        """
        from src.ml_service.schemas import PredictRequest
        res = self.engine.predict(PredictRequest(raw_http=raw_http))
        return float(res.malicious_probability)

    def predict_batch(self, raw_requests: List[str], batch_size: int = 128) -> np.ndarray:
        """
        High-throughput batch prediction mathematically identical to InferenceEngine.predict().
        """
        features = [self.preprocess_request(r) for r in raw_requests]
        out_probs = np.zeros(len(raw_requests), dtype=float)

        # Stage 1: TF-IDF Triage
        classes = list(self.container.tfidf_pipeline.classes_)
        mal_idx = classes.index("malicious") if "malicious" in classes else 1
        tfidf_probs = self.container.tfidf_pipeline.predict_proba(features)[:, mal_idx]

        tau_fast_pass = float(self.container.thresholds.get("fast_pass_allow", 0.04))
        fast_pass_mask = tfidf_probs <= tau_fast_pass

        # If head-tail chunking enabled, ensure oversized payloads are not fast-passed
        if self.head_tail_chunking:
            for idx in np.where(fast_pass_mask)[0]:
                toks = self.container.transformer_tokenizer.encode(
                    features[idx], add_special_tokens=True, truncation=False
                )
                if len(toks) > self.max_length:
                    fast_pass_mask[idx] = False

        out_probs[fast_pass_mask] = tfidf_probs[fast_pass_mask]

        # Stage 2: Transformer Inference
        remaining_indices = np.where(~fast_pass_mask)[0]
        if len(remaining_indices) > 0:
            std_idx = []
            std_feats = []
            ht_idx = []
            ht_feats = []

            cls_id = self.container.transformer_tokenizer.cls_token_id
            sep_id = self.container.transformer_tokenizer.sep_token_id

            for idx in remaining_indices:
                feat_text = features[idx]
                toks = self.container.transformer_tokenizer.encode(
                    feat_text, add_special_tokens=True, truncation=False
                )
                if self.head_tail_chunking and len(toks) > self.max_length:
                    ht_idx.append(idx)
                    ht_feats.append(toks)
                else:
                    std_idx.append(idx)
                    std_feats.append(feat_text)

            # Process standard items in batches
            for b_start in range(0, len(std_feats), batch_size):
                b_texts = std_feats[b_start : b_start + batch_size]
                b_indices = std_idx[b_start : b_start + batch_size]

                inputs = self.container.transformer_tokenizer(
                    b_texts,
                    padding=True,
                    truncation=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                ).to(self.container.device)

                with torch.inference_mode():
                    outputs = self.container.transformer_model(**inputs)
                    logits = outputs.logits
                    if self.container.device.startswith("cuda") and logits.dtype != torch.float32:
                        logits = logits.float()
                    probs = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()

                for idx, p in zip(b_indices, probs):
                    out_probs[idx] = p

            # Process head-tail items (if any)
            for idx, toks in zip(ht_idx, ht_feats):
                head_ids = list(toks[: self.max_length])
                if sep_id is not None and head_ids[-1] != sep_id:
                    head_ids[-1] = sep_id
                head_mask = [1] * len(head_ids)

                tail_core = list(toks[-(self.max_length - 1) :])
                tail_ids = ([cls_id] if cls_id is not None else [head_ids[0]]) + tail_core
                if len(tail_ids) > self.max_length:
                    tail_ids = tail_ids[: self.max_length]
                if sep_id is not None and tail_ids[-1] != sep_id:
                    tail_ids[-1] = sep_id
                tail_mask = [1] * len(tail_ids)

                input_ids_tensor = torch.tensor(
                    [head_ids, tail_ids], dtype=torch.long, device=self.container.device
                )
                attn_mask_tensor = torch.tensor(
                    [head_mask, tail_mask], dtype=torch.long, device=self.container.device
                )

                with torch.inference_mode():
                    outputs = self.container.transformer_model(
                        input_ids=input_ids_tensor, attention_mask=attn_mask_tensor
                    )
                    logits = outputs.logits
                    if self.container.device.startswith("cuda") and logits.dtype != torch.float32:
                        logits = logits.float()
                    probs = torch.softmax(logits, dim=-1)[:, 1]
                    raw_prob = float(torch.max(probs).item())
                    out_probs[idx] = raw_prob

            # Apply Platt Scaling
            calib_cfg = self.container.thresholds.get("platt_calibration", {})
            if calib_cfg.get("enabled", True):
                w = float(self.container.platt_params.get("w", 1.0))
                b = float(self.container.platt_params.get("b", 0.0))
                eps = 1e-7
                for idx in remaining_indices:
                    raw_p = out_probs[idx]
                    p_clipped = min(max(raw_p, eps), 1.0 - eps)
                    logit = math.log(p_clipped / (1.0 - p_clipped))
                    out_probs[idx] = 1.0 / (1.0 + math.exp(-(w * logit + b)))

        return out_probs

    @staticmethod
    def compute_metrics(
        y_true: np.ndarray, y_probs: np.ndarray, threshold: float = 0.50
    ) -> Dict[str, Any]:
        """
        Computes TP, TN, FP, FN, recall, precision, f1, fpr, fnr, roc_auc, pr_auc.
        """
        y_pred = (y_probs >= threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        try:
            auc = roc_auc_score(y_true, y_probs)
            prauc = average_precision_score(y_true, y_probs)
        except Exception:
            auc = 0.0
            prauc = 0.0

        return {
            "total_samples": int(len(y_true)),
            "threshold": float(threshold),
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4),
            "fnr": round(float(fnr), 4),
            "roc_auc": round(float(auc), 4),
            "pr_auc": round(float(prauc), 4),
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
        }
