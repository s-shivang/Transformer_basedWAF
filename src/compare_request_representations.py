
from pathlib import Path
import re
import json

import joblib
import pandas as pd
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

ROOT = Path(__file__).resolve().parents[1]

AI_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_PATH = ROOT / "data/processed/waf_requests.csv"
REPORT_PATH = ROOT / "reports/request_representation_diagnostic.json"

RANDOM_STATE = 42


def normalize_whitespace(text):
    return " ".join(str(text).split())


def extract_target(request):
    """Extract the target from the first HTTP request line."""
    lines = normalize_whitespace(request).splitlines()
    if not lines:
        return ""

    first = lines[0].split()
    if len(first) < 2:
        return first[0] if first else ""

    return first[1]


def remove_host_header(request):
    """Remove Host header lines, preserving the rest of the request."""
    return re.sub(
        r"(?im)^Host\s*:\s*[^\r\n]*(?:\r?\n)?",
        "",
        str(request),
    )


def metrics(model, df, representation, dataset_name):
    predictions = model.predict(df["feature"])
    y = df["label"]

    labels = ["benign", "malicious"]
    matrix = confusion_matrix(y, predictions, labels=labels)
    tn, fp, fn, tp = matrix.ravel()

    result = {
        "representation": representation,
        "dataset": dataset_name,
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y, predictions)),
        "malicious_precision": float(
            precision_score(y, predictions, pos_label="malicious",
                            zero_division=0)
        ),
        "malicious_recall": float(
            recall_score(y, predictions, pos_label="malicious",
                         zero_division=0)
        ),
        "malicious_f1": float(
            f1_score(y, predictions, pos_label="malicious",
                     zero_division=0)
        ),
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else 0.0,
        "confusion_matrix": matrix.tolist(),
    }

    print(f"\n{representation} | {dataset_name}")
    print("Confusion matrix (true rows, predicted columns):")
    print(matrix)
    print(f"Accuracy: {result['accuracy']:.4f}")
    print(f"Malicious precision: {result['malicious_precision']:.4f}")
    print(f"Malicious recall: {result['malicious_recall']:.4f}")
    print(f"Malicious F1: {result['malicious_f1']:.4f}")
    print(f"False-positive rate: {result['false_positive_rate']:.4f}")

    return result


def main():
    ai = pd.read_parquet(AI_PATH)[["text", "label"]].dropna().copy()
    ai["text"] = ai["text"].astype(str).str.strip()
    ai["label"] = ai["label"].astype(str).str.strip().str.lower()
    ai = ai[ai["text"].ne("")].copy()

    ai["normalized"] = ai["text"].map(
        lambda x: normalize_whitespace(x).lower()
    )
    ai = ai.drop_duplicates("normalized").reset_index(drop=True)

    if set(ai["label"].unique()) != {"benign", "malicious"}:
        raise ValueError("AI WAF must contain benign and malicious labels.")

    ai_train, ai_val = train_test_split(
        ai,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=ai["label"],
    )

    csic = pd.read_csv(CSIC_PATH)
    csic = csic[csic["split"].eq("test")][
        ["request_text", "label"]
    ].dropna().copy()

    csic = csic.rename(columns={"request_text": "text"})
    csic["text"] = csic["text"].astype(str).str.strip()
    csic["label"] = csic["label"].astype(str).str.strip().str.lower()
    csic = csic[csic["text"].ne("")].copy()

    representations = {
        "full_request": lambda x: x,
        "request_target": extract_target,
        "without_host_header": remove_host_header,
    }

    results = []

    for name, transform in representations.items():
        train = ai_train[["text", "label"]].copy()
        validation = ai_val[["text", "label"]].copy()
        csic_eval = csic[["text", "label"]].copy()

        train["feature"] = train["text"].map(transform)
        validation["feature"] = validation["text"].map(transform)
        csic_eval["feature"] = csic_eval["text"].map(transform)

        model = Pipeline([
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

        print(f"\nTraining representation: {name}")
        model.fit(train["feature"], train["label"])

        results.append(metrics(
            model, validation, name, "AI WAF validation"
        ))
        results.append(metrics(
            model, csic_eval, name, "CSIC diagnostic test"
        ))

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(
            {
                "experiment": "request_representation_diagnostic",
                "random_state": RANDOM_STATE,
                "results": results,
                "note": (
                    "CSIC results are diagnostic only; they have already "
                    "been used for model comparisons and must not be treated "
                    "as an untouched final benchmark."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\nSaved diagnostic report:", REPORT_PATH)


if __name__ == "__main__":
    main()
