"""
Phase 3 Step 3:
1. Read-only Diagnostic Pass on csic_held_out_test.parquet (30,532 samples)
2. Artifact Freeze into models/frozen/v1_0/ with SHA-256 checksums
3. Write models/frozen/v1_0/model_manifest.json
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
import shutil
import hashlib
import platform
import joblib
import torch
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import transformers

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features

HELD_OUT_PATH = ROOT / "data/processed/csic_held_out_test.parquet"
FROZEN_DIR = ROOT / "models/frozen/v1_0"
ACTIVE_TFIDF_PATH = ROOT / "models/saved/tfidf_logistic_baseline.joblib"
ACTIVE_TRANS_DIR = ROOT / "models/saved/transformer_waf"

def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("=" * 80)
    print("PHASE 3 STEP 3: READ-ONLY DIAGNOSTIC PASS & ARTIFACT FREEZE")
    print("=" * 80)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    # -------------------------------------------------------------
    # 1. Read-Only Diagnostic Pass on Held-Out CSIC Partition
    # -------------------------------------------------------------
    print("\n--- 1. READ-ONLY DIAGNOSTIC PASS (CSIC HELD-OUT: 30,532 samples) ---")
    print("[DISCLOSURE] The CSIC test partition was previously exposed during exploratory research.")
    print("This evaluation is executed ONCE strictly post-hoc as a diagnostic benchmark with ZERO tuning.")

    if not HELD_OUT_PATH.exists():
        raise FileNotFoundError(f"Missing {HELD_OUT_PATH}")

    df_held = pd.read_parquet(HELD_OUT_PATH)
    y_held = np.array([1 if str(l).lower() in ("malicious", "anomalous") else 0 for l in df_held["label"]])
    print(f"Loaded Held-Out Partition: {len(df_held):,} samples (Benign={sum(y_held==0):,}, Malicious={sum(y_held==1):,})")

    # Load active models
    tfidf_clf = joblib.load(ACTIVE_TFIDF_PATH)
    classes = list(tfidf_clf.classes_)
    mal_idx = classes.index("malicious") if "malicious" in classes else 1

    tokenizer = AutoTokenizer.from_pretrained(str(ACTIVE_TRANS_DIR), local_files_only=True)
    transformer = AutoModelForSequenceClassification.from_pretrained(str(ACTIVE_TRANS_DIR), local_files_only=True).to(device)
    transformer.eval()
    if device.type == "cuda":
        transformer = transformer.half()

    print("Building structured features for 30,532 requests...")
    parsed_reqs = [parse_raw_http(t) for t in df_held["request_text"]]
    held_texts = [build_features(p, "structured") for p in parsed_reqs]

    print("Executing 2-Stage Cascade on Held-Out Partition...")
    # Layer 2 Fast-Pass
    tau_fp = 0.04
    l2_probs = tfidf_clf.predict_proba(held_texts)[:, mal_idx]
    fast_pass_mask = l2_probs < tau_fp

    fast_pass_benign = int(np.sum(fast_pass_mask & (y_held == 0)))
    fast_pass_attacks = int(np.sum(fast_pass_mask & (y_held == 1)))

    # Layer 3 for escalated requests
    cascade_probs = np.zeros(len(y_held), dtype=float)
    escalated_indices = np.where(~fast_pass_mask)[0]
    print(f"  Fast-Passed requests: {np.sum(fast_pass_mask):,} (Clean benign: {fast_pass_benign:,}, Attacks leaked: {fast_pass_attacks})")
    print(f"  Escalated requests: {len(escalated_indices):,}")

    batch_size = 64
    for i in range(0, len(escalated_indices), batch_size):
        idx_batch = escalated_indices[i:i+batch_size]
        b_texts = [held_texts[j] for j in idx_batch]
        enc = tokenizer(b_texts, max_length=192, padding=True, truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            logits = transformer(**enc).logits
            if device.type == "cuda":
                logits = logits.float()
            p = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
            cascade_probs[idx_batch] = p

    # At Strict Block threshold tau=0.50
    preds_strict = (cascade_probs >= 0.50).astype(int)
    cm_strict = confusion_matrix(y_held, preds_strict, labels=[0, 1])
    tn_s, fp_s, fn_s, tp_s = cm_strict.ravel()
    rec_s = tp_s / (tp_s + fn_s)
    fpr_s = fp_s / (fp_s + tn_s)
    f1_s = 2 * (tp_s / (tp_s + fp_s)) * rec_s / ((tp_s / (tp_s + fp_s)) + rec_s)

    # At Alert threshold tau=0.05
    preds_alert = (cascade_probs >= 0.05).astype(int)
    cm_alert = confusion_matrix(y_held, preds_alert, labels=[0, 1])
    tn_a, fp_a, fn_a, tp_a = cm_alert.ravel()
    rec_a = tp_a / (tp_a + fn_a)
    fpr_a = fp_a / (fp_a + tn_a)

    roc_auc_val = float(roc_auc_score(y_held, cascade_probs))
    pr_auc_val = float(average_precision_score(y_held, cascade_probs))

    print(f"\nDiagnostic Results on Post-Hoc Held-Out CSIC Partition (30,532 requests):")
    print(f"  ROC-AUC: {roc_auc_val:.4f} | PR-AUC: {pr_auc_val:.4f}")
    print(f"  Strict Block (tau=0.50): Recall = {rec_s*100:.2f}% ({tp_s:,}/{tp_s+fn_s:,}), FPR = {fpr_s*100:.2f}% ({fp_s:,}/{fp_s+tn_s:,}), F1 = {f1_s:.4f}")
    print(f"    Confusion Matrix: [[TN: {tn_s}, FP: {fp_s}], [FN: {fn_s}, TP: {tp_s}]]")
    print(f"  Alert Monitor (tau=0.05): Recall = {rec_a*100:.2f}% ({tp_a:,}/{tp_a+fn_a:,}), FPR = {fpr_a*100:.2f}% ({fp_a:,}/{fp_a+tn_a:,})")

    # -------------------------------------------------------------
    # 2. Artifact Freeze into models/frozen/v1_0/
    # -------------------------------------------------------------
    print("\n--- 2. FREEZING ARTIFACTS INTO models/frozen/v1_0/ ---")
    FROZEN_DIR.mkdir(parents=True, exist_ok=True)
    frozen_trans_dir = FROZEN_DIR / "transformer"
    frozen_tfidf_dir = FROZEN_DIR / "tfidf"
    frozen_trans_dir.mkdir(parents=True, exist_ok=True)
    frozen_tfidf_dir.mkdir(parents=True, exist_ok=True)

    # Copy TF-IDF
    frozen_tfidf_file = frozen_tfidf_dir / "tfidf_logistic_baseline.joblib"
    shutil.copy2(ACTIVE_TFIDF_PATH, frozen_tfidf_file)
    print(f"Copied Layer 2 TF-IDF to: {frozen_tfidf_file}")

    # Copy Transformer
    for item in ACTIVE_TRANS_DIR.iterdir():
        if item.is_file():
            shutil.copy2(item, frozen_trans_dir / item.name)
    print(f"Copied Layer 3 Transformer files to: {frozen_trans_dir}")

    # Compute SHA-256 Checksums
    checksums = {}
    for p in FROZEN_DIR.rglob("*"):
        if p.is_file() and p.name != "model_manifest.json":
            rel_path = str(p.relative_to(FROZEN_DIR)).replace("\\", "/")
            checksums[rel_path] = compute_sha256(p)

    # Generate Manifest
    manifest = {
        "model_version": "v1.0.0",
        "freeze_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "architecture": "2-Stage Cascade (Layer 2 Fast-Pass TF-IDF + Layer 3 Contextual all-MiniLM-L6-v2)",
        "representation_mode": "structured (Representation D)",
        "max_length": 192,
        "special_structural_tokens": ["[METHOD]", "[PATH]", "[PARAM]", "[PAYLOAD]", "[HEADERS]"],
        "calibration_policy": {
            "method": "Platt Scaling (Logistic Sigmoid)",
            "slope": 0.7724,
            "intercept": 0.4965,
            "brier_score": 0.01109,
            "ece": 0.0048
        },
        "threshold_tiers": {
            "tau_fast_pass": 0.04,
            "tau_alert": 0.05,
            "tau_block": 0.50
        },
        "environment": {
            "os": platform.platform(),
            "python_version": platform.python_version(),
            "pytorch_version": torch.__version__,
            "transformers_version": transformers.__version__,
            "cuda_available": torch.cuda.is_available(),
            "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"
        },
        "artifacts_sha256": checksums,
        "diagnostic_held_out_metrics": {
            "dataset": "csic_held_out_test.parquet (30,532 requests)",
            "notice": "Previously exposed diagnostic set evaluated strictly post-hoc with zero tuning",
            "roc_auc": roc_auc_val,
            "pr_auc": pr_auc_val,
            "strict_block_tau_0_50": {
                "recall": round(rec_s, 4),
                "fpr": round(fpr_s, 4),
                "f1": round(f1_s, 4),
                "confusion_matrix": [[int(tn_s), int(fp_s)], [int(fn_s), int(tp_s)]]
            },
            "alert_monitor_tau_0_05": {
                "recall": round(rec_a, 4),
                "fpr": round(fpr_a, 4),
                "confusion_matrix": [[int(tn_a), int(fp_a)], [int(fn_a), int(tp_a)]]
            }
        }
    }

    manifest_path = FROZEN_DIR / "model_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest successfully written to: {manifest_path}")

    # Also save diagnostic results
    diag_file = ROOT / "reports/phase3_step3_diagnostic_and_manifest.json"
    with open(diag_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Report saved to: {diag_file}")

if __name__ == "__main__":
    main()
