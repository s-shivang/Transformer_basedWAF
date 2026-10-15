from pathlib import Path
import json
import time
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features

ROOT = Path(__file__).resolve().parents[2]
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_DEV_PATH = ROOT / "data/processed/csic_dev.parquet"
REPORT_DIR = ROOT / "reports"
OUTPUT_REPORT = REPORT_DIR / "representation_benchmark_report.json"

RANDOM_STATE = 42


def evaluate_model(model, X_test, y_test, dataset_name: str, representation: str) -> Dict[str, Any]:
    preds = model.predict(X_test)
    labels = ["benign", "malicious"]
    cm = confusion_matrix(y_test, preds, labels=labels)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    acc = float(accuracy_score(y_test, preds))
    prec = float(precision_score(y_test, preds, pos_label="malicious", zero_division=0))
    rec = float(recall_score(y_test, preds, pos_label="malicious", zero_division=0))
    f1 = float(f1_score(y_test, preds, pos_label="malicious", zero_division=0))

    print(f"  [{dataset_name}] Accuracy: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f} | FPR: {fpr:.4f}")
    print(f"    Confusion Matrix [[TN, FP], [FN, TP]]: [[{tn:,}, {fp:,}], [{fn:,}, {tp:,}]]")

    return {
        "dataset": dataset_name,
        "representation": representation,
        "rows": len(y_test),
        "accuracy": acc,
        "precision_malicious": prec,
        "recall_malicious": rec,
        "f1_malicious": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": cm.tolist(),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    if not AI_WAF_PATH.exists():
        raise FileNotFoundError(f"AI WAF dataset not found: {AI_WAF_PATH}")
    if not CSIC_DEV_PATH.exists():
        raise FileNotFoundError(f"CSIC Dev dataset not found: {CSIC_DEV_PATH}")

    print("Loading AI WAF dataset...")
    ai_df = pd.read_parquet(AI_WAF_PATH)[["text", "label"]].dropna().copy()
    ai_df["text"] = ai_df["text"].astype(str).str.strip()
    ai_df["label"] = ai_df["label"].astype(str).str.strip().str.lower()
    ai_df = ai_df[ai_df["text"].ne("")].copy()

    # Deduplicate normalized text
    ai_df["norm"] = ai_df["text"].str.split().str.join(" ").str.lower()
    ai_df = ai_df.drop_duplicates("norm").reset_index(drop=True)
    print(f"AI WAF rows after deduplication: {len(ai_df):,}")

    ai_train, ai_val = train_test_split(
        ai_df,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=ai_df["label"],
    )

    print("Loading CSIC Development Partition...")
    csic_dev = pd.read_parquet(CSIC_DEV_PATH)
    print(f"CSIC Dev rows: {len(csic_dev):,}")

    # Parse all datasets into ParsedRequest objects
    print("\nParsing raw requests into ParsedRequest objects...")
    t0 = time.time()
    ai_train_parsed = [parse_raw_http(t, request_id=f"ai_tr_{i}", label=1 if l=="malicious" else 0) for i, (t, l) in enumerate(zip(ai_train["text"], ai_train["label"]))]
    ai_val_parsed = [parse_raw_http(t, request_id=f"ai_val_{i}", label=1 if l=="malicious" else 0) for i, (t, l) in enumerate(zip(ai_val["text"], ai_val["label"]))]
    csic_dev_parsed = [parse_raw_http(t, request_id=f"csic_dev_{i}", label=1 if l=="malicious" else 0) for i, (t, l) in enumerate(zip(csic_dev["request_text"], csic_dev["label"]))]
    print(f"Parsing complete in {time.time()-t0:.2f}s")

    y_train = [p.label for p in ai_train_parsed]
    y_val = [p.label for p in ai_val_parsed]
    y_csic = [p.label for p in csic_dev_parsed]
    
    # Map integer labels back to text for consistent metrics
    label_map = {0: "benign", 1: "malicious"}
    y_train = [label_map[y] for y in y_train]
    y_val = [label_map[y] for y in y_val]
    y_csic = [label_map[y] for y in y_csic]

    representations = [
        ("A_raw", "raw"),
        ("B_target_payload", "target_payload"),
        ("C_payload_only", "payload_only"),
        ("D_structured", "structured"),
    ]

    all_results = {}

    for rep_key, rep_name in representations:
        print(f"\n{'='*70}")
        print(f"Testing Representation: {rep_key} ({rep_name})")
        print(f"{'='*70}")

        X_train = [build_features(p, rep_name) for p in ai_train_parsed]
        X_val = [build_features(p, rep_name) for p in ai_val_parsed]
        X_csic = [build_features(p, rep_name) for p in csic_dev_parsed]

        # Handle empty features in payload_only by replacing with placeholder
        X_train = [f if f.strip() else "<EMPTY>" for f in X_train]
        X_val = [f if f.strip() else "<EMPTY>" for f in X_val]
        X_csic = [f if f.strip() else "<EMPTY>" for f in X_csic]

        pipeline = Pipeline([
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=200_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                ),
            ),
        ])

        print(f"Training TF-IDF + Logistic Regression on {rep_key}...")
        pipeline.fit(X_train, y_train)

        print("\nEvaluating:")
        val_metrics = evaluate_model(pipeline, X_val, y_val, "AI WAF Validation (In-Domain)", rep_key)
        csic_metrics = evaluate_model(pipeline, X_csic, y_csic, "CSIC Dev (Cross-Dataset)", rep_key)

        all_results[rep_key] = {
            "representation": rep_name,
            "in_domain_validation": val_metrics,
            "cross_dataset_csic_dev": csic_metrics,
        }

    # Save summary report
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(
            {
                "experiment": "Cross-Dataset Representation Benchmark (Phase 2)",
                "random_state": RANDOM_STATE,
                "training_source": "AI WAF Training Set",
                "validation_source": "AI WAF Validation Set",
                "cross_dataset_source": "CSIC Development Partition",
                "results": all_results,
            },
            f,
            indent=2,
        )

    print(f"\nSaved Comparative Benchmark Report to: {OUTPUT_REPORT}")


if __name__ == "__main__":
    main()

