"""
Group-Aware Cross-Validation Module.

Implements StratifiedGroupKFold cross-validation to ensure that request templates
and endpoint signatures do not cross train/validation split boundaries within any fold.
Evaluates traditional ML baselines across representations and provides a pilot
runtime estimate for Transformer cross-validation on local GPU hardware.
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

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features

ROOT = Path(__file__).resolve().parents[2]
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_DEV_PATH = ROOT / "data/processed/csic_dev.parquet"
REPORT_PATH = ROOT / "reports/group_cv_report.json"

RANDOM_SEED = 42


def load_development_pool() -> pd.DataFrame:
    """
    Loads the development pool (AI WAF + CSIC Dev), assembling the 16,000-sample
    development dataset used for cross-validation without touching held-out test data.
    """
    records = []

    # 1. AI WAF (6,000 benign, 3,000 malicious)
    if not AI_WAF_PATH.exists():
        raise FileNotFoundError(f"AI WAF dataset not found: {AI_WAF_PATH}")
    ai_df = pd.read_parquet(AI_WAF_PATH)[["text", "label"]].dropna().copy()
    ai_df["text"] = ai_df["text"].astype(str).str.strip()
    ai_df["label"] = ai_df["label"].astype(str).str.strip().str.lower()
    ai_df = ai_df[ai_df["text"].ne("")].copy()
    ai_df["norm"] = ai_df["text"].str.split().str.join(" ").str.lower()
    ai_df = ai_df.drop_duplicates("norm").reset_index(drop=True)

    ai_benign = ai_df[ai_df["label"] == "benign"].sample(
        min(len(ai_df[ai_df["label"] == "benign"]), 6000), random_state=RANDOM_SEED
    )
    ai_mal = ai_df[ai_df["label"] == "malicious"].sample(
        min(len(ai_df[ai_df["label"] == "malicious"]), 3000), random_state=RANDOM_SEED
    )

    for t in ai_benign["text"]:
        records.append(("ai_waf", t, 0))
    for t in ai_mal["text"]:
        records.append(("ai_waf", t, 1))

    # 2. CSIC Dev (4,000 benign, 3,000 malicious)
    if not CSIC_DEV_PATH.exists():
        raise FileNotFoundError(f"CSIC Dev dataset not found: {CSIC_DEV_PATH}")
    csic_dev = pd.read_parquet(CSIC_DEV_PATH)
    csic_benign = csic_dev[csic_dev["label"].str.lower() == "benign"].sample(
        min(len(csic_dev[csic_dev["label"].str.lower() == "benign"]), 4000), random_state=RANDOM_SEED
    )
    csic_mal = csic_dev[csic_dev["label"].str.lower().isin(["malicious", "anomalous"])].sample(
        min(len(csic_dev[csic_dev["label"].str.lower().isin(["malicious", "anomalous"])]), 3000), random_state=RANDOM_SEED
    )

    for t in csic_benign["request_text"]:
        records.append(("csic_dev", t, 0))
    for t in csic_mal["request_text"]:
        records.append(("csic_dev", t, 1))

    # Parse and extract features & deterministic group IDs
    parsed_records = []
    for src, raw_text, lbl in records:
        p = parse_raw_http(raw_text, label=lbl, source=src)
        param_keys = sorted(list(p.query_params.keys()) + list(p.body_params.keys()))
        group_id = f"{src}::{p.path}?{','.join(param_keys)}"
        feat_raw = p.raw_text
        feat_structured = build_features(p, "structured")
        parsed_records.append({
            "source": src,
            "raw_text": raw_text,
            "feat_raw": feat_raw,
            "feat_structured": feat_structured,
            "label": lbl,
            "group_id": group_id,
        })

    df = pd.DataFrame(parsed_records)
    return df


def evaluate_predictions(
    y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray
) -> Dict[str, Any]:
    """Computes comprehensive classification metrics."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        roc_auc = 0.5
    try:
        pr_auc = float(average_precision_score(y_true, y_prob))
    except Exception:
        pr_auc = 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def run_group_cv(n_splits: int = 3) -> Dict[str, Any]:
    """
    Executes 3-Fold Stratified Group Cross-Validation on the development pool.
    """
    print("=" * 70)
    print("TASK C: 3-FOLD STRATIFIED GROUP CROSS-VALIDATION")
    print("=" * 70)

    df = load_development_pool()
    print(f"Loaded Development Pool: {len(df):,} total requests.")
    print(f"  Class Distribution: Benign={sum(df['label'] == 0):,}, Malicious={sum(df['label'] == 1):,}")
    print(f"  Unique Template Groups: {df['group_id'].nunique():,}")

    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_SEED)

    # Validate that no groups cross boundaries
    fold_splits = []
    for fold, (train_idx, val_idx) in enumerate(sgkf.split(df, df["label"], df["group_id"])):
        train_groups = set(df.iloc[train_idx]["group_id"])
        val_groups = set(df.iloc[val_idx]["group_id"])
        overlap = train_groups.intersection(val_groups)
        if overlap:
            raise ValueError(f"FATAL: Group leakage detected in Fold {fold}! Overlapping groups: {len(overlap)}")
        fold_splits.append((train_idx, val_idx))

    print(f"[Verification] Confirmed: 0 groups cross train/validation boundaries across all {n_splits} folds.")

    experiments = {
        "tfidf_structured": "feat_structured",
        "tfidf_raw": "feat_raw",
    }

    results = {}

    for exp_name, feat_col in experiments.items():
        print(f"\nEvaluating Model Pipeline: {exp_name} (Feature column: {feat_col})...")
        fold_metrics = []
        all_val_preds = []

        for fold, (train_idx, val_idx) in enumerate(fold_splits):
            train_df = df.iloc[train_idx]
            val_df = df.iloc[val_idx]

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

            t0_train = time.perf_counter()
            pipeline.fit(train_df[feat_col], train_df["label"])
            train_duration_s = time.perf_counter() - t0_train

            t0_eval = time.perf_counter()
            y_prob = pipeline.predict_proba(val_df[feat_col])[:, 1]
            y_pred = (y_prob >= 0.50).astype(int)
            eval_duration_s = time.perf_counter() - t0_eval

            metrics = evaluate_predictions(val_df["label"].to_numpy(), y_pred, y_prob)
            metrics["fold"] = fold
            metrics["train_size"] = len(train_df)
            metrics["val_size"] = len(val_df)
            metrics["val_benign"] = int(sum(val_df["label"] == 0))
            metrics["val_malicious"] = int(sum(val_df["label"] == 1))
            metrics["train_time_seconds"] = round(train_duration_s, 2)
            metrics["eval_time_seconds"] = round(eval_duration_s, 2)
            fold_metrics.append(metrics)

            print(
                f"  Fold {fold}: Acc={metrics['accuracy']:.4f}, Prec={metrics['precision']:.4f}, "
                f"Rec={metrics['recall']:.4f}, F1={metrics['f1']:.4f}, FPR={metrics['fpr']:.4f}, "
                f"PR-AUC={metrics['pr_auc']:.4f} (Train: {train_duration_s:.1f}s, Val: {eval_duration_s:.1f}s)"
            )

        # Aggregate mean & std
        def calc_stat(key):
            vals = [m[key] for m in fold_metrics]
            return {"mean": round(float(np.mean(vals)), 4), "std": round(float(np.std(vals)), 4)}

        results[exp_name] = {
            "folds": fold_metrics,
            "aggregate": {
                "accuracy": calc_stat("accuracy"),
                "precision": calc_stat("precision"),
                "recall": calc_stat("recall"),
                "f1": calc_stat("f1"),
                "fpr": calc_stat("fpr"),
                "fnr": calc_stat("fnr"),
                "roc_auc": calc_stat("roc_auc"),
                "pr_auc": calc_stat("pr_auc"),
            },
        }

    # Pilot Transformer runtime estimate
    pilot_estimate = run_transformer_pilot_estimate(df)
    results["transformer_cv_pilot_estimate"] = pilot_estimate

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[Saved] Group Cross-Validation Report saved to: {REPORT_PATH}")
    return results


def run_transformer_pilot_estimate(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Runs a tiny pilot forward/backward benchmark on GPU to estimate full 3-fold Transformer CV runtime.
    """
    print("\n--- Running Transformer CV Pilot Runtime Benchmark (RTX 2050 GPU) ---")
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model_name = "sentence-transformers/all-MiniLM-L6-v2"
    local_model_path = ROOT / "models/saved/transformer_waf"

    if local_model_path.exists():
        tokenizer = AutoTokenizer.from_pretrained(str(local_model_path), local_files_only=True)
        model = AutoModelForSequenceClassification.from_pretrained(str(local_model_path), local_files_only=True)
    else:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    model.to(device)
    model.train()

    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5)
    sample_texts = df["feat_structured"].iloc[:32].tolist()
    sample_labels = torch.tensor(df["label"].iloc[:32].tolist(), device=device)

    inputs = tokenizer(sample_texts, max_length=128, padding="max_length", truncation=True, return_tensors="pt")
    inputs = {k: v.to(device) for k, v in inputs.items()}

    # Warmup
    for _ in range(2):
        out = model(**inputs, labels=sample_labels)
        out.loss.backward()
        optimizer.step()
        optimizer.zero_grad()

    # Timed steps
    torch.cuda.synchronize() if torch.cuda.is_available() else None
    t0 = time.perf_counter()
    n_batches = 5
    for _ in range(n_batches):
        out = model(**inputs, labels=sample_labels)
        out.loss.backward()
        optimizer.step()
        optimizer.zero_grad()
    torch.cuda.synchronize() if torch.cuda.is_available() else None
    dur = time.perf_counter() - t0

    sec_per_batch = dur / n_batches
    batch_size = 32
    fold_train_size = int(len(df) * (2 / 3))  # ~10,666
    batches_per_epoch = fold_train_size // batch_size
    sec_per_epoch = batches_per_epoch * sec_per_batch
    epochs = 3
    sec_per_fold = sec_per_epoch * epochs
    total_3_fold_sec = sec_per_fold * 3

    estimate = {
        "hardware_device": str(device),
        "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU",
        "batch_size": batch_size,
        "seconds_per_batch_32": round(sec_per_batch, 4),
        "seconds_per_epoch_est": round(sec_per_epoch, 2),
        "seconds_per_fold_est": round(sec_per_fold, 2),
        "total_3_fold_hours_est": round(total_3_fold_sec / 3600.0, 3),
        "staging_rationale": (
            f"Full 3-fold cross-validation of all-MiniLM-L6-v2 takes approx. {total_3_fold_sec / 60.0:.1f} minutes "
            "on the local RTX 2050 GPU. Staging full transformer retraining for Phase 3 preserves local compute "
            "budget while group-aware traditional ML baselines provide immediate rigorous leakage bounds."
        ),
    }

    print(f"  Device: {estimate['gpu_name']}")
    print(f"  Step Latency (bs=32): {sec_per_batch * 1000:.1f} ms")
    print(f"  Estimated Epoch Duration: {sec_per_epoch:.1f} s")
    print(f"  Estimated 3-Fold Total Duration: {total_3_fold_sec / 60.0:.1f} minutes")
    return estimate


if __name__ == "__main__":
    run_group_cv(n_splits=3)
