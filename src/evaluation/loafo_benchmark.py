"""
Leave-One-Attack-Family-Out (LOAFO) Generalization Benchmark.

Evaluates model generalization to completely unseen attack families using fine-grained
ground-truth labels from HttpParams:
- SQL Injection (sqli)
- Cross-Site Scripting (xss)
- Path Traversal (path-traversal)
- Command Injection (cmdi)

For each attack family:
1. The target family is completely removed from attack training data (0 samples in train).
2. The model trains on the remaining 3 attack families plus benign training data.
3. The model is evaluated on the held-out attack family against held-out benign traffic.
4. Group-aware splitting prevents benign payload leakage between train and test.
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

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

from src.pipeline.canonicalizer import canonicalize_value

REPORT_PATH = ROOT / "reports/loafo_generalization_report.json"
HTTP_PARAMS_DIR = ROOT / "data/raw/http_params"

RANDOM_SEED = 42
ATTACK_FAMILIES = ["sqli", "xss", "path-traversal", "cmdi"]


def load_http_params_data() -> pd.DataFrame:
    """
    Loads and unifies payload_train.csv and payload_test.csv from http_params,
    canonicalizing values and assigning deterministic payload cluster groups.
    """
    train_path = HTTP_PARAMS_DIR / "payload_train.csv"
    test_path = HTTP_PARAMS_DIR / "payload_test.csv"

    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(f"HttpParams dataset files missing in {HTTP_PARAMS_DIR}")

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    df = pd.concat([df_train, df_test], ignore_index=True).dropna(subset=["payload", "attack_type"])
    df["payload"] = df["payload"].astype(str).str.strip()
    df["attack_type"] = df["attack_type"].astype(str).str.strip().str.lower()
    df = df[df["payload"].ne("")].copy()

    # Binary label: 0 for norm, 1 for attacks
    df["label"] = (df["attack_type"] != "norm").astype(int)

    # Canonicalize and derive group hash (groups identical payloads together)
    canonical_payloads = []
    groups = []
    for p in df["payload"]:
        canon, _ = canonicalize_value(p)
        canonical_payloads.append(canon)
        # Group by canonical prefix/stem to prevent near-duplicate leakage
        norm_stem = canon.lower().split()[0] if canon.strip() else "empty"
        groups.append(norm_stem[:16])

    df["canonical_payload"] = canonical_payloads
    df["group_id"] = groups
    return df


def run_loafo_benchmark() -> Dict[str, Any]:
    print("=" * 70)
    print("TASK D: LEAVE-ONE-ATTACK-FAMILY-OUT (LOAFO) GENERALIZATION BENCHMARK")
    print("=" * 70)

    df = load_http_params_data()
    print(f"Loaded unified HttpParams dataset: {len(df):,} total samples.")
    print("Attack Family Breakdown:")
    for fam, cnt in df["attack_type"].value_counts().items():
        print(f"  - {fam}: {cnt:,} samples")

    # Split benign (norm) samples 70/30 using StratifiedGroupKFold to prevent benign leakage
    norm_df = df[df["attack_type"] == "norm"].copy().reset_index(drop=True)
    sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_SEED)
    tr_idx, te_idx = next(sgkf.split(norm_df, norm_df["label"], norm_df["group_id"]))

    benign_train = norm_df.iloc[tr_idx]
    benign_test = norm_df.iloc[te_idx]

    # Verify no group overlap between benign train and test
    benign_tr_groups = set(benign_train["group_id"])
    benign_te_groups = set(benign_test["group_id"])
    benign_overlap = benign_tr_groups.intersection(benign_te_groups)
    print(f"\n[Leakage Verification] Benign train: {len(benign_train):,}, Benign test: {len(benign_test):,}")
    print(f"  Benign group overlap: {len(benign_overlap)} (strictly zero)")

    results_per_family = {}

    for held_out_family in ATTACK_FAMILIES:
        print(f"\nEvaluating Held-Out Attack Family: [{held_out_family.upper()}]...")

        # 1. Training Attack Data: All attacks EXCEPT held_out_family
        attack_train = df[(df["attack_type"] != "norm") & (df["attack_type"] != held_out_family)]
        # 2. Testing Attack Data: STRICTLY held_out_family
        attack_test = df[df["attack_type"] == held_out_family]

        # Verify strict zero-exposure:
        assert len(attack_train[attack_train["attack_type"] == held_out_family]) == 0, (
            f"FATAL: Held-out family {held_out_family} found in training set!"
        )

        train_pool = pd.concat([benign_train, attack_train], ignore_index=True)
        test_pool = pd.concat([benign_test, attack_test], ignore_index=True)

        print(
            f"  Train: Total={len(train_pool):,} (Benign={len(benign_train):,}, "
            f"Trained Attacks={len(attack_train):,})"
        )
        print(
            f"  Test:  Total={len(test_pool):,} (Benign={len(benign_test):,}, "
            f"Unseen Attacks ({held_out_family})={len(attack_test):,})"
        )

        # Baseline TF-IDF + Logistic Regression
        pipeline = Pipeline([
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=100_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=RANDOM_SEED,
                ),
            ),
        ])

        t0 = time.perf_counter()
        pipeline.fit(train_pool["canonical_payload"], train_pool["label"])
        fit_duration = time.perf_counter() - t0

        y_prob = pipeline.predict_proba(test_pool["canonical_payload"])[:, 1]
        y_pred = (y_prob >= 0.50).astype(int)

        y_true = test_pool["label"].to_numpy()
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
        prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        roc_auc = float(roc_auc_score(y_true, y_prob))
        pr_auc = float(average_precision_score(y_true, y_prob))

        results_per_family[held_out_family] = {
            "held_out_family": held_out_family,
            "trained_families": [f for f in ATTACK_FAMILIES if f != held_out_family],
            "train_counts": {
                "total": len(train_pool),
                "benign": len(benign_train),
                "malicious": len(attack_train),
            },
            "test_counts": {
                "total": len(test_pool),
                "benign": len(benign_test),
                "held_out_attacks": len(attack_test),
            },
            "metrics": {
                "recall": round(rec, 4),
                "precision": round(prec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4),
            },
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
            "fit_time_seconds": round(fit_duration, 2),
            "generalization_diagnosis": (
                "High Generalization" if rec >= 0.70 else
                "Moderate Generalization" if rec >= 0.40 else
                "Severe Generalization Failure (<40% Recall)"
            ),
        }

        print(
            f"  [Result] Recall={rec * 100:.2f}%, FPR={fpr * 100:.2f}%, Prec={prec * 100:.2f}%, "
            f"F1={f1:.4f}, PR-AUC={pr_auc:.4f} | Diagnosis: {results_per_family[held_out_family]['generalization_diagnosis']}"
        )

    # Save comprehensive report
    final_output = {
        "benchmark": "Leave-One-Attack-Family-Out (LOAFO) Generalization Benchmark",
        "description": (
            "Measures zero-exposure attack generalization across SQLi, XSS, Path Traversal, and Command Injection. "
            "Evaluates whether a model trained strictly on other attack families can recognize an entirely unseen attack family syntax."
        ),
        "scientific_disclaimer": (
            "This benchmark evaluates unseen attack-family generalization on the HttpParams dataset. "
            "It does NOT claim proof of generalized zero-day detection in arbitrary wild environments."
        ),
        "attack_families": ATTACK_FAMILIES,
        "results": results_per_family,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2)

    print(f"\n[Saved] LOAFO Generalization Report saved to: {REPORT_PATH}")
    return final_output


if __name__ == "__main__":
    run_loafo_benchmark()
