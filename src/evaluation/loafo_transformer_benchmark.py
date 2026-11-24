"""
LOAFO Benchmark: Zero-Exposure Attack Family Generalization for the Fine-Tuned Transformer.

Evaluates the fine-tuned all-MiniLM-L6-v2 Transformer on all 4 attack families from HttpParams:
- SQL Injection (sqli, 10,852 test attacks)
- Cross-Site Scripting (xss, 532 test attacks)
- Path Traversal (path-traversal, 290 test attacks)
- Command Injection (cmdi, 89 test attacks)
against 6,435 held-out benign requests (0 group overlap).
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
from typing import List, Dict, Any, Tuple
import torch
import numpy as np
import pandas as pd
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import recall_score, precision_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix

from src.evaluation.loafo_benchmark import load_http_params_data, ATTACK_FAMILIES
from sklearn.model_selection import StratifiedGroupKFold

REPORT_PATH = ROOT / "reports/loafo_transformer_comparison_report.json"
MODEL_DIR = ROOT / "models/saved/transformer_waf"
RANDOM_SEED = 42


def evaluate_transformer_loafo() -> Dict[str, Any]:
    print("=" * 70)
    print("PHASE 2B: LOAFO GENERALIZATION BENCHMARK ON FINE-TUNED TRANSFORMER")
    print("=" * 70)

    # 1. Load HttpParams data and isolate benign test set
    df = load_http_params_data()
    norm_df = df[df["attack_type"] == "norm"].copy().reset_index(drop=True)
    sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_SEED)
    tr_idx, te_idx = next(sgkf.split(norm_df, norm_df["label"], norm_df["group_id"]))
    benign_test = norm_df.iloc[te_idx].copy().reset_index(drop=True)

    print(f"Loaded HttpParams: {len(df):,} total samples.")
    print(f"Held-Out Benign Evaluation Samples: {len(benign_test):,}")

    # 2. Load fine-tuned Transformer on GPU
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Loading Fine-Tuned Transformer from {MODEL_DIR} on {device}...")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR), local_files_only=True)
    model.to(device)
    model.eval()

    def score_payload_texts(payload_list: List[str], batch_size: int = 128) -> np.ndarray:
        all_probs = []
        structured_texts = [f"[METHOD] GET [PATH] /search [PARAM] q={p} [PAYLOAD] {p}" for p in payload_list]
        with torch.no_grad():
            for i in range(0, len(structured_texts), batch_size):
                b_texts = structured_texts[i : i + batch_size]
                inputs = tokenizer(
                    b_texts,
                    max_length=192,
                    padding="max_length",
                    truncation=True,
                    return_tensors="pt",
                ).to(device)
                logits = model(**inputs).logits
                p_mal = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
                all_probs.extend(p_mal.tolist())
        return np.array(all_probs)

    print("\nPre-scoring 6,435 held-out benign samples...")
    benign_probs = score_payload_texts(benign_test["canonical_payload"].tolist())

    results = {}

    for fam in ATTACK_FAMILIES:
        print(f"\nEvaluating Held-Out Attack Family: [{fam.upper()}]...")
        attack_test = df[df["attack_type"] == fam].copy().reset_index(drop=True)
        print(f"  Scoring {len(attack_test):,} {fam} attack samples...")
        attack_probs = score_payload_texts(attack_test["canonical_payload"].tolist())

        y_true = np.array([0] * len(benign_probs) + [1] * len(attack_probs))
        y_prob = np.concatenate([benign_probs, attack_probs])
        y_pred = (y_prob >= 0.50).astype(int)

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        roc_auc = float(roc_auc_score(y_true, y_prob))
        pr_auc = float(average_precision_score(y_true, y_prob))

        results[fam] = {
            "attack_family": fam,
            "attack_samples_count": len(attack_test),
            "benign_samples_count": len(benign_test),
            "metrics": {
                "recall": round(rec, 4),
                "precision": round(prec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4),
            },
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "mean_attack_confidence": round(float(np.mean(attack_probs)), 4),
            "mean_benign_confidence": round(float(np.mean(benign_probs)), 4),
        }

        print(
            f"  [Transformer Result] Recall={rec * 100:.2f}%, FPR={fpr * 100:.2f}%, "
            f"Precision={prec * 100:.2f}%, F1={f1:.4f}, ROC-AUC={roc_auc:.4f}, PR-AUC={pr_auc:.4f}"
        )

    output = {
        "benchmark_name": "Contextual Transformer LOAFO Attack Family Generalization",
        "model": "all-MiniLM-L6-v2 (Fine-Tuned with max_length=192)",
        "results_by_family": results,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\n[Saved] Transformer LOAFO Report saved to: {REPORT_PATH}")
    return output


if __name__ == "__main__":
    evaluate_transformer_loafo()
