"""
Decision Threshold Calibration Module.

Calibrates classification thresholds exclusively on the Development Validation split
(strictly sealing the held-out test partition). Sweeps operating boundaries to determine:
- Strict Production Point: Best achievable recall at FPR <= 0.5%
- Standard Production Point: Best achievable recall at FPR <= 1.0%
- Monitor / Balanced Point: Optimal F1 operating point
- Default Baseline: Standard 0.50 threshold comparison

Saves frozen calibrated thresholds to `reports/threshold_calibration_report.json`
and `models/saved/calibrated_thresholds.json`.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    precision_recall_curve,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
)

from src.evaluation.group_cv import load_development_pool

REPORT_PATH = ROOT / "reports/threshold_calibration_report.json"
CONFIG_OUTPUT_PATH = ROOT / "models/saved/calibrated_thresholds.json"
MODEL_DIR = ROOT / "models/saved/transformer_waf"

RANDOM_SEED = 42


def evaluate_threshold_point(y_true: np.ndarray, y_prob: np.ndarray, tau: float) -> Dict[str, Any]:
    y_pred = (y_prob >= tau).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    return {
        "threshold": round(tau, 4),
        "recall": round(rec, 4),
        "precision": round(prec, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def run_threshold_calibration() -> Dict[str, Any]:
    print("=" * 70)
    print("TASK E: THRESHOLD CALIBRATION ON DEVELOPMENT VALIDATION SPLIT")
    print("=" * 70)

    # 1. Load development pool and carve out a strictly isolated validation fold
    df = load_development_pool()
    sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_SEED)
    train_idx, val_idx = next(sgkf.split(df, df["label"], df["group_id"]))

    dev_val_df = df.iloc[val_idx].copy().reset_index(drop=True)
    print(f"Calibration Data Source: Development Validation Split (Group-Isolated)")
    print(f"  Total Validation Requests: {len(dev_val_df):,}")
    print(f"  Benign: {sum(dev_val_df['label'] == 0):,}, Malicious: {sum(dev_val_df['label'] == 1):,}")

    # 2. Score with Transformer
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\nScoring calibration set with Transformer ({device})...")

    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR), local_files_only=True)
    model.to(device)
    model.eval()

    probs = []
    batch_size = 64
    texts = dev_val_df["feat_structured"].tolist()

    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i : i + batch_size]
            inputs = tokenizer(
                batch_texts,
                max_length=128,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            ).to(device)

            logits = model(**inputs).logits
            p = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
            probs.extend(p.tolist())

    y_true = dev_val_df["label"].to_numpy()
    y_prob = np.array(probs)

    # 3. Sweep candidate thresholds from 0.01 to 0.99
    threshold_candidates = np.linspace(0.01, 0.99, 99)
    sweep_results = []
    for tau in threshold_candidates:
        res = evaluate_threshold_point(y_true, y_prob, float(tau))
        sweep_results.append(res)

    # 4. Identify Target Operating Points
    # A: Strict Production (FPR <= 0.005)
    strict_candidates = [r for r in sweep_results if r["fpr"] <= 0.005]
    if strict_candidates:
        strict_op = max(strict_candidates, key=lambda x: x["recall"])
    else:
        # Lowest achievable FPR
        strict_op = min(sweep_results, key=lambda x: x["fpr"])
        strict_op["note"] = "Constraint FPR <= 0.5% could not be strictly met; selected lowest achievable FPR"

    # B: Standard Production (FPR <= 0.01)
    std_candidates = [r for r in sweep_results if r["fpr"] <= 0.010]
    if std_candidates:
        std_op = max(std_candidates, key=lambda x: x["recall"])
    else:
        std_op = min(sweep_results, key=lambda x: x["fpr"])
        std_op["note"] = "Constraint FPR <= 1.0% could not be strictly met; selected lowest achievable FPR"

    # C: Monitor / Max-F1 Operating Point
    monitor_op = max(sweep_results, key=lambda x: x["f1"])

    # D: Default Baseline (tau = 0.50)
    default_op = next(r for r in sweep_results if abs(r["threshold"] - 0.50) < 1e-4)

    print("\n--- Calibration Operating Points ---")
    print(
        f"1. Strict Production (FPR <= 0.5%):  tau={strict_op['threshold']} | "
        f"Recall={strict_op['recall'] * 100:.2f}%, FPR={strict_op['fpr'] * 100:.2f}%, Prec={strict_op['precision'] * 100:.2f}%, F1={strict_op['f1']:.4f}"
    )
    print(
        f"2. Standard Production (FPR <= 1.0%): tau={std_op['threshold']} | "
        f"Recall={std_op['recall'] * 100:.2f}%, FPR={std_op['fpr'] * 100:.2f}%, Prec={std_op['precision'] * 100:.2f}%, F1={std_op['f1']:.4f}"
    )
    print(
        f"3. Monitor / Optimal F1:             tau={monitor_op['threshold']} | "
        f"Recall={monitor_op['recall'] * 100:.2f}%, FPR={monitor_op['fpr'] * 100:.2f}%, Prec={monitor_op['precision'] * 100:.2f}%, F1={monitor_op['f1']:.4f}"
    )
    print(
        f"4. Default Baseline (tau = 0.50):    tau={default_op['threshold']} | "
        f"Recall={default_op['recall'] * 100:.2f}%, FPR={default_op['fpr'] * 100:.2f}%, Prec={default_op['precision'] * 100:.2f}%, F1={default_op['f1']:.4f}"
    )

    # Compile report
    report = {
        "calibration_name": "Development Split Threshold Calibration",
        "dataset": "Development Pool Validation Fold (Group-Isolated)",
        "sample_counts": {
            "total": len(dev_val_df),
            "benign": int(sum(y_true == 0)),
            "malicious": int(sum(y_true == 1)),
        },
        "operating_points": {
            "strict_production_fpr_0_5pct": strict_op,
            "standard_production_fpr_1_0pct": std_op,
            "monitor_optimal_f1": monitor_op,
            "default_baseline_0_50": default_op,
        },
        "threshold_sweep_curve": sweep_results,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Save frozen threshold config for firewall middleware
    frozen_config = {
        "tau_strict_block": strict_op["threshold"],
        "tau_standard_block": std_op["threshold"],
        "tau_monitor": monitor_op["threshold"],
        "tau_fast_pass": 0.05,
        "calibrated_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "calibration_source": "Development Validation Fold (Isolated)",
    }
    with open(CONFIG_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(frozen_config, f, indent=2)

    print(f"\n[Saved] Calibration Report saved to: {REPORT_PATH}")
    print(f"[Saved] Frozen Calibrated Thresholds saved to: {CONFIG_OUTPUT_PATH}")
    return report


if __name__ == "__main__":
    run_threshold_calibration()
