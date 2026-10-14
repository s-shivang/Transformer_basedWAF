
from pathlib import Path
import json

import joblib
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
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parents[1]
AI_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_PATH = ROOT / "data/processed/waf_requests.csv"

MODEL_DIR = ROOT / "models/saved"
REPORT_DIR = ROOT / "reports"

MODEL_PATH = MODEL_DIR / "tfidf_logistic_mixed.joblib"
REPORT_PATH = REPORT_DIR / "mixed_baseline_metrics.json"

RANDOM_STATE = 42
VALIDATION_SIZE = 0.20


def normalize_text(series):
    return series.astype(str).str.split().str.join(" ").str.lower()


def check_conflicting_duplicates(df, text_col, label_col, description):
    normalized = normalize_text(df[text_col])
    counts = pd.DataFrame({
        "normalized": normalized,
        "label": df[label_col].to_numpy(),
    }).groupby("normalized")["label"].nunique()

    conflicts = counts[counts > 1]
    if not conflicts.empty:
        raise ValueError(
            f"{description}: found {len(conflicts)} normalized texts "
            "with conflicting labels. Investigate before training."
        )


def evaluate(model, df, dataset_name):
    X = df["text"]
    y = df["label"]
    predictions = model.predict(X)

    labels = ["benign", "malicious"]
    matrix = confusion_matrix(y, predictions, labels=labels)
    tn, fp, fn, tp = matrix.ravel()

    metrics = {
        "dataset": dataset_name,
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y, predictions)),
        "precision_malicious": float(
            precision_score(y, predictions, pos_label="malicious",
                            zero_division=0)
        ),
        "recall_malicious": float(
            recall_score(y, predictions, pos_label="malicious",
                         zero_division=0)
        ),
        "f1_malicious": float(
            f1_score(y, predictions, pos_label="malicious",
                     zero_division=0)
        ),
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else 0.0,
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y, predictions, labels=labels,
            target_names=["benign", "malicious"],
            output_dict=True, zero_division=0,
        ),
    }

    print(f"\n{'=' * 65}")
    print(dataset_name)
    print("Rows:", len(df))
    print(classification_report(
        y, predictions, labels=labels,
        target_names=["benign", "malicious"], zero_division=0,
    ))
    print("Confusion matrix (true rows, predicted columns):")
    print(matrix)
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Malicious precision: {metrics['precision_malicious']:.4f}")
    print(f"Malicious recall: {metrics['recall_malicious']:.4f}")
    print(f"Malicious F1: {metrics['f1_malicious']:.4f}")
    print(f"False-positive rate: {metrics['false_positive_rate']:.4f}")

    return metrics


def main():
    if not AI_PATH.exists() or not CSIC_PATH.exists():
        raise FileNotFoundError("AI WAF or prepared CSIC dataset is missing.")

    # Load and validate AI WAF.
    ai = pd.read_parquet(AI_PATH)[["text", "label"]].dropna().copy()
    ai["text"] = ai["text"].astype(str).str.strip()
    ai["label"] = ai["label"].astype(str).str.strip().str.lower()
    ai = ai[ai["text"].ne("")].copy()

    if not set(ai["label"].unique()).issubset({"benign", "malicious"}):
        raise ValueError("Unexpected labels in AI WAF.")

    check_conflicting_duplicates(ai, "text", "label", "AI WAF")

    ai["normalized"] = normalize_text(ai["text"])
    ai = ai.drop_duplicates("normalized").reset_index(drop=True)

    if ai["label"].nunique() != 2:
        raise ValueError("AI WAF must contain both classes.")

    # Split AI WAF before adding CSIC training data.
    ai_train, ai_val = train_test_split(
        ai,
        test_size=VALIDATION_SIZE,
        random_state=RANDOM_STATE,
        stratify=ai["label"],
    )

    # Load only the designated CSIC training split for fitting.
    csic = pd.read_csv(CSIC_PATH)
    required = {"request_text", "label", "split"}
    if not required.issubset(csic.columns):
        raise ValueError(f"CSIC file must contain columns: {required}")

    csic_train = csic[csic["split"].eq("train")][
        ["request_text", "label"]
    ].dropna().copy()

    csic_test = csic[csic["split"].eq("test")][
        ["request_text", "label"]
    ].dropna().copy()

    csic_train = csic_train.rename(columns={"request_text": "text"})
    csic_test = csic_test.rename(columns={"request_text": "text"})

    for frame in (csic_train, csic_test):
        frame["text"] = frame["text"].astype(str).str.strip()
        frame["label"] = frame["label"].astype(str).str.strip().str.lower()
        frame.drop(frame[frame["text"].eq("")].index, inplace=True)

    if set(csic_train["label"].unique()) != {"benign"}:
        raise ValueError(
            "Expected CSIC training split to contain benign requests only."
        )

    if not set(csic_test["label"].unique()).issubset({"benign", "malicious"}):
        raise ValueError("Unexpected labels in CSIC test split.")

    # Protect the AI validation set from overlap with CSIC training data.
    ai_val_norm = set(normalize_text(ai_val["text"]))
    csic_train["normalized"] = normalize_text(csic_train["text"])
    validation_overlap = csic_train["normalized"].isin(ai_val_norm).sum()
    csic_train = csic_train[
        ~csic_train["normalized"].isin(ai_val_norm)
    ].copy()

    # Check combined training labels before deduplication.
    ai_train = ai_train[["text", "label"]].copy()
    csic_train = csic_train[["text", "label"]].copy()
    combined = pd.concat([ai_train, csic_train], ignore_index=True)
    combined["normalized"] = normalize_text(combined["text"])

    check_conflicting_duplicates(
        combined, "text", "label", "Combined training data"
    )

    rows_before_dedup = len(combined)
    combined = combined.drop_duplicates("normalized").reset_index(drop=True)
    duplicates_removed = rows_before_dedup - len(combined)

    # Independent AI validation data.
    ai_val = ai_val[["text", "label"]].copy()

    # CSIC test remains untouched: never fit or tune on it.
    csic_test = csic_test[["text", "label"]].copy()

    # Guard against any normalized overlap between training and CSIC test.
    train_norm = set(normalize_text(combined["text"]))
    csic_test_norm = set(normalize_text(csic_test["text"]))
    overlap_with_csic_test = train_norm.intersection(csic_test_norm)

    if overlap_with_csic_test:
        raise ValueError(
            f"Found {len(overlap_with_csic_test)} normalized training "
            "requests overlapping CSIC test. Investigate before evaluation."
        )

    print("AI WAF original rows:", len(pd.read_parquet(AI_PATH)))
    print("AI WAF after deduplication:", len(ai))
    print("AI training rows:", len(ai_train))
    print("AI validation rows:", len(ai_val))
    print("CSIC benign training rows loaded:", len(csic_train) + validation_overlap)
    print("CSIC training rows overlapping AI validation and excluded:",
          int(validation_overlap))
    print("CSIC benign training rows retained:", len(csic_train))
    print("Combined training rows before deduplication:", rows_before_dedup)
    print("Duplicate training rows removed:", duplicates_removed)
    print("Final combined training rows:", len(combined))
    print("\nCombined training labels:")
    print(combined["label"].value_counts().to_string())
    print("CSIC test rows reserved for evaluation:", len(csic_test))

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=200_000,
            sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        )),
    ])

    print("\nTraining mixed full-request model...")
    model.fit(combined["text"], combined["label"])

    # Evaluate both datasets only after fitting is complete.
    ai_metrics = evaluate(model, ai_val, "AI WAF held-out validation")
    csic_metrics = evaluate(model, csic_test, "CSIC untouched test split")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    report = {
        "experiment": "mixed_full_request_tfidf_logistic",
        "features": ["full request text"],
        "training_sources": ["AI WAF training partition",
                             "CSIC benign training split"],
        "model": "character TF-IDF + Logistic Regression",
        "random_state": RANDOM_STATE,
        "validation_fraction_of_ai_waf": VALIDATION_SIZE,
        "training_rows": int(len(combined)),
        "training_label_counts": {
            str(k): int(v)
            for k, v in combined["label"].value_counts().items()
        },
        "duplicates_removed": int(duplicates_removed),
        "csic_train_ai_validation_overlap_excluded": int(validation_overlap),
        "ai_validation": ai_metrics,
        "csic_test": csic_metrics,
        "notes": [
            "CSIC test split was not used for fitting or tuning.",
            "CSIC training data supplied benign examples only.",
            "Evaluation does not establish real-world WAF effectiveness.",
        ],
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nSaved model:", MODEL_PATH)
    print("Saved report:", REPORT_PATH)


if __name__ == "__main__":
    main()
