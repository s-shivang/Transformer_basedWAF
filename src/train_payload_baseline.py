

import json
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "raw" / "http_params"
MODEL_DIR = ROOT / "models" / "saved"
REPORT_DIR = ROOT / "reports"

TRAIN_FILE = DATA_DIR / "payload_train.csv"
TEST_FILE = DATA_DIR / "payload_test.csv"
LEXICAL_TEST_FILE = DATA_DIR / "payload_test_lexical.csv"

MODEL_FILE = MODEL_DIR / "payload_tfidf_logistic.joblib"
REPORT_FILE = REPORT_DIR / "payload_baseline_metrics.json"


def load_dataset(path):
    df = pd.read_csv(path)

    required = {"payload", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path.name} is missing columns: {missing}")

    df = df.dropna(subset=["payload", "label"]).copy()
    df["payload"] = df["payload"].astype(str)
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    df = df[df["payload"].str.strip().ne("")]
    df = df[df["label"].isin(["norm", "anom"])]

    if df.empty:
        raise ValueError(f"No usable rows in {path}")

    return df


def evaluate(model, df, name):
    X = df["payload"]
    y = df["label"]
    predictions = model.predict(X)

    cm = confusion_matrix(y, predictions, labels=["norm", "anom"])
    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "dataset": name,
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y, predictions)),
        "malicious_precision": float(
            precision_score(y, predictions, pos_label="anom", zero_division=0)
        ),
        "malicious_recall": float(
            recall_score(y, predictions, pos_label="anom", zero_division=0)
        ),
        "malicious_f1": float(
            f1_score(y, predictions, pos_label="anom", zero_division=0)
        ),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix_labels": ["norm", "anom"],
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y,
            predictions,
            labels=["norm", "anom"],
            target_names=["benign", "malicious"],
            output_dict=True,
            zero_division=0,
        ),
    }

    print(f"\n{'=' * 60}")
    print(name)
    print(f"Rows: {len(df)}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Malicious precision: {metrics['malicious_precision']:.4f}")
    print(f"Malicious recall: {metrics['malicious_recall']:.4f}")
    print(f"Malicious F1: {metrics['malicious_f1']:.4f}")
    print(f"False-positive rate: {metrics['false_positive_rate']:.4f}")
    print("Confusion matrix (true rows, predicted columns):")
    print(cm)
    print("\nClassification report:")
    print(classification_report(
        y,
        predictions,
        labels=["norm", "anom"],
        target_names=["benign", "malicious"],
        zero_division=0,
    ))

    return metrics


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    train_df = load_dataset(TRAIN_FILE)
    test_df = load_dataset(TEST_FILE)
    lexical_df = load_dataset(LEXICAL_TEST_FILE)

    # The provided training split is the only data used for fitting.
    # Neither test file is used for fitting or tuning.
    model = Pipeline([
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
                random_state=42,
            ),
        ),
    ])

    print("Training payload classifier...")
    print(f"Training rows: {len(train_df)}")
    print("Training label counts:")
    print(train_df["label"].value_counts().to_dict())

    model.fit(train_df["payload"], train_df["label"])

    # Save model locally; model files are excluded from Git.
    import joblib
    joblib.dump(model, MODEL_FILE)

    test_metrics = evaluate(model, test_df, "HttpParamsDataset standard test")
    lexical_metrics = evaluate(
        model, lexical_df, "HttpParamsDataset lexical test"
    )

    report = {
        "experiment": "payload_tfidf_logistic_baseline",
        "features": ["payload"],
        "excluded_features": ["length", "attack_type"],
        "model": "character TF-IDF (3-5 grams) + Logistic Regression",
        "training_rows": int(len(train_df)),
        "training_label_counts": {
            str(k): int(v)
            for k, v in train_df["label"].value_counts().items()
        },
        "test_results": test_metrics,
        "lexical_test_results": lexical_metrics,
    }

    REPORT_FILE.write_text(json.dumps(report, indent=2))
    print(f"\nModel saved to: {MODEL_FILE}")
    print(f"Metrics saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
