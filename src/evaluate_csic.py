from pathlib import Path
import json

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data/processed/waf_requests.csv"
MODEL_PATH = ROOT / "models/saved/tfidf_logistic_baseline.joblib"
OUTPUT_PATH = ROOT / "reports/csic_evaluation.json"


def main():
    for path in (DATA_PATH, MODEL_PATH):
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    df = pd.read_csv(DATA_PATH)

    required = {"request_text", "label", "split"}
    if not required.issubset(df.columns):
        raise ValueError(f"Missing required columns: {required - set(df.columns)}")

    # Evaluate only the pre-existing CSIC test split.
    test = df[df["split"] == "test"].copy()

    if test.empty:
        raise ValueError("No rows found in the CSIC test split.")

    test = test.dropna(subset=["request_text", "label"])
    test["request_text"] = test["request_text"].astype(str)
    test["label"] = test["label"].astype(str).str.strip().str.lower()

    expected_labels = {"benign", "malicious"}
    if set(test["label"].unique()) != expected_labels:
        raise ValueError(
            f"Unexpected CSIC test labels: {test['label'].value_counts().to_dict()}"
        )

    # Preserve the saved model; do not fit or tune anything here.
    model = joblib.load(MODEL_PATH)

    X_test = test["request_text"]
    y_test = test["label"]
    predictions = model.predict(X_test)

    labels = ["benign", "malicious"]
    matrix = confusion_matrix(y_test, predictions, labels=labels)
    tn, fp, fn, tp = matrix.ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    results = {
        "dataset": "CSIC 2010",
        "split": "test",
        "model": "AI WAF-trained character TF-IDF + Logistic Regression",
        "test_rows": int(len(test)),
        "true_label_counts": {
            key: int(value)
            for key, value in y_test.value_counts().items()
        },
        "accuracy": float(accuracy_score(y_test, predictions)),
        "malicious_precision": float(
            precision_score(y_test, predictions, pos_label="malicious")
        ),
        "malicious_recall": float(
            recall_score(y_test, predictions, pos_label="malicious")
        ),
        "malicious_f1": float(
            f1_score(y_test, predictions, pos_label="malicious")
        ),
        "false_positive_rate": float(fpr),
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_test, predictions, labels=labels, output_dict=True
        ),
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("Evaluation dataset: CSIC 2010 test split")
    print("Test rows:", len(test))
    print("\nClassification report:")
    print(classification_report(y_test, predictions, labels=labels))

    print("Confusion matrix (rows=true, columns=predicted)")
    print("Labels:", labels)
    print(matrix)
    print(f"\nFalse-positive rate: {fpr:.4f}")
    print(f"Accuracy: {results['accuracy']:.4f}")
    print(f"Malicious precision: {results['malicious_precision']:.4f}")
    print(f"Malicious recall: {results['malicious_recall']:.4f}")
    print(f"Malicious F1-score: {results['malicious_f1']:.4f}")
    print("\nSaved evaluation:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
