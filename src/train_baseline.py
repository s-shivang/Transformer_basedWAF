from pathlib import Path
import json

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
MODEL_DIR = ROOT / "models/saved"
RESULTS_DIR = ROOT / "reports"

RANDOM_STATE = 42
TEST_SIZE = 0.20


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_parquet(DATA_PATH)

    required_columns = {"text", "label"}
    if not required_columns.issubset(df.columns):
        raise ValueError(
            f"Expected columns {required_columns}; found {set(df.columns)}"
        )

    df = df[["text", "label"]].copy()
    df = df.dropna(subset=["text", "label"])

    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    allowed_labels = {"benign", "malicious"}
    unexpected = set(df["label"].unique()) - allowed_labels
    if unexpected:
        raise ValueError(f"Unexpected labels found: {unexpected}")

    df = df[df["text"] != ""].copy()

    # Normalize whitespace and case for duplicate detection.
    df["normalized_text"] = (
        df["text"].str.split().str.join(" ").str.lower()
    )

    # Stop rather than silently choose a label if duplicates conflict.
    label_counts = df.groupby("normalized_text")["label"].nunique()
    conflicting = label_counts[label_counts > 1]

    if not conflicting.empty:
        raise ValueError(
            f"Found {len(conflicting)} duplicate texts with conflicting labels."
        )

    before = len(df)
    df = df.drop_duplicates(subset=["normalized_text"]).reset_index(drop=True)
    removed = before - len(df)

    X = df["text"]
    y = df["label"]

    if y.nunique() != 2:
        raise ValueError("Training requires both benign and malicious labels.")

    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

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

    print("Dataset:", DATA_PATH)
    print("Rows before deduplication:", before)
    print("Exact normalized duplicates removed:", removed)
    print("Rows after deduplication:", len(df))
    print("\nClass distribution:")
    print(y.value_counts().to_string())
    print("\nTraining rows:", len(X_train))
    print("Validation rows:", len(X_val))
    print("\nTraining TF-IDF + Logistic Regression...")

    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_val)

    labels = ["benign", "malicious"]
    matrix = confusion_matrix(y_val, predictions, labels=labels)

    # With labels ordered benign, malicious:
    # matrix = [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = matrix.ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        "dataset": "AI WAF",
        "model": "character TF-IDF + Logistic Regression",
        "random_state": RANDOM_STATE,
        "validation_fraction": TEST_SIZE,
        "rows_before_deduplication": int(before),
        "duplicates_removed": int(removed),
        "rows_after_deduplication": int(len(df)),
        "train_rows": int(len(X_train)),
        "validation_rows": int(len(X_val)),
        "accuracy": float(accuracy_score(y_val, predictions)),
        "precision_malicious": float(
            precision_score(y_val, predictions, pos_label="malicious")
        ),
        "recall_malicious": float(
            recall_score(y_val, predictions, pos_label="malicious")
        ),
        "f1_malicious": float(
            f1_score(y_val, predictions, pos_label="malicious")
        ),
        "false_positive_rate": float(false_positive_rate),
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_val, predictions, labels=labels, output_dict=True
        ),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODEL_DIR / "tfidf_logistic_baseline.joblib"
    metrics_path = RESULTS_DIR / "baseline_metrics.json"

    joblib.dump(pipeline, model_path)

    with metrics_path.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2)

    print("\nClassification report:")
    print(classification_report(y_val, predictions, labels=labels))

    print("Confusion matrix (rows=true, columns=predicted)")
    print("Labels:", labels)
    print(matrix)

    print(f"\nFalse-positive rate: {false_positive_rate:.4f}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Malicious precision: {metrics['precision_malicious']:.4f}")
    print(f"Malicious recall: {metrics['recall_malicious']:.4f}")
    print(f"Malicious F1-score: {metrics['f1_malicious']:.4f}")

    print("\nSaved model:", model_path)
    print("Saved metrics:", metrics_path)


if __name__ == "__main__":
    main()
