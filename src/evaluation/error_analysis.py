from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "models/saved/tfidf_logistic_baseline.joblib"
DEV_DATA_PATH = ROOT / "data/processed/csic_dev.parquet"
REPORT_DIR = ROOT / "reports"
OUTPUT_REPORT = REPORT_DIR / "false_positive_error_analysis.json"


def analyze_errors(top_n_samples: int = 25, top_n_features: int = 10):
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Run train_baseline.py first.")
    
    if not DEV_DATA_PATH.exists():
        raise FileNotFoundError(f"Development partition not found at {DEV_DATA_PATH}. Run partition_dataset.py first.")

    print("Loading baseline model...")
    pipeline = joblib.load(MODEL_PATH)
    tfidf = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["classifier"]

    feature_names = np.array(tfidf.get_feature_names_out())
    malicious_idx = list(clf.classes_).index("malicious")
    coefficients = clf.coef_[0] if clf.coef_.shape[0] == 1 else clf.coef_[malicious_idx]
    intercept = float(clf.intercept_[0])

    print("Loading CSIC Development Partition...")
    df = pd.read_parquet(DEV_DATA_PATH)
    print(f"Total CSIC Dev requests: {len(df):,}")
    print("Class distribution:", df["label"].value_counts().to_dict())

    X_texts = df["request_text"].tolist()
    y_true = df["label"].tolist()

    print("\nRunning model inference on Development partition...")
    X_tfidf = tfidf.transform(X_texts)
    probs = clf.predict_proba(X_tfidf)[:, malicious_idx]
    preds = clf.predict(X_tfidf)

    df["malicious_prob"] = probs
    df["prediction"] = preds

    # Overall metrics on Dev partition
    labels = ["benign", "malicious"]
    cm = confusion_matrix(y_true, preds, labels=labels)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    metrics = {
        "accuracy": float(accuracy_score(y_true, preds)),
        "precision": float(precision_score(y_true, preds, pos_label="malicious", zero_division=0)),
        "recall": float(recall_score(y_true, preds, pos_label="malicious", zero_division=0)),
        "f1": float(f1_score(y_true, preds, pos_label="malicious", zero_division=0)),
        "false_positive_rate": fpr,
        "confusion_matrix": cm.tolist(),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

    print("\n=== Baseline Performance on CSIC Development Partition ===")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Malicious Precision: {metrics['precision']:.4f}")
    print(f"Malicious Recall: {metrics['recall']:.4f}")
    print(f"Malicious F1: {metrics['f1']:.4f}")
    print(f"False Positive Rate (FPR): {metrics['false_positive_rate']:.4f} ({fp:,} / {fp+tn:,} benign requests)")
    print("Confusion Matrix [[TN, FP], [FN, TP]]:", cm.tolist())

    # Extract False Positives
    fps = df[(df["label"] == "benign") & (df["prediction"] == "malicious")].copy()
    fps = fps.sort_values(by="malicious_prob", ascending=False)

    print(f"\nAnalyzing top {top_n_samples} False Positives...")
    fp_details = []
    global_ngram_weights = {}
    path_fp_counts = fps["canonical_path"].value_counts().head(10).to_dict()

    for idx, (_, row) in enumerate(fps.head(top_n_samples).iterrows()):
        req_text = row["request_text"]
        prob = float(row["malicious_prob"])
        
        row_tfidf = tfidf.transform([req_text])
        nonzero = row_tfidf.indices
        tfidf_vals = row_tfidf.data

        # contribution = tfidf_value * coefficient
        contributions = tfidf_vals * coefficients[nonzero]
        top_contrib_order = np.argsort(contributions)[::-1][:top_n_features]

        top_features = []
        for c_idx in top_contrib_order:
            feat_idx = nonzero[c_idx]
            n_gram = str(feature_names[feat_idx])
            contrib = float(contributions[c_idx])
            top_features.append({
                "n_gram": n_gram,
                "contribution_score": round(contrib, 4),
            })
            global_ngram_weights[n_gram] = global_ngram_weights.get(n_gram, 0.0) + contrib

        fp_details.append({
            "rank": idx + 1,
            "canonical_path": row.get("canonical_path", ""),
            "template_signature": row.get("template_signature", ""),
            "malicious_probability": round(prob, 4),
            "top_contributing_malicious_ngrams": top_features,
            "request_preview": req_text[:250].replace("\r\n", "\n"),
        })

    # Sort global n-grams by total contribution score
    sorted_global_ngrams = sorted(global_ngram_weights.items(), key=lambda x: x[1], reverse=True)[:20]

    report = {
        "analysis_name": "CSIC Development Partition False Positive Error Analysis",
        "dataset_path": str(DEV_DATA_PATH),
        "total_requests": len(df),
        "baseline_metrics": metrics,
        "intercept": intercept,
        "top_paths_in_false_positives": path_fp_counts,
        "most_influential_malicious_ngrams_in_fps": [
            {"n_gram": ng, "total_contribution": round(score, 4)} for ng, score in sorted_global_ngrams
        ],
        "top_false_positive_samples": fp_details,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nSaved Error Analysis Report: {OUTPUT_REPORT}")
    print("\nTop 10 N-Grams Driving Benign Traffic to be Classified as Malicious:")
    for item in report["most_influential_malicious_ngrams_in_fps"][:10]:
        print(f"  {repr(item['n_gram'])}: total contribution = {item['total_contribution']}")

    print("\nTop Paths with Most False Positives:")
    for p, c in path_fp_counts.items():
        print(f"  {p}: {c:,} false alarms")

    return report


if __name__ == "__main__":
    analyze_errors()
