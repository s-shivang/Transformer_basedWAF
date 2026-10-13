
from pathlib import Path
import pandas as pd

folder = Path("data/raw/http_params")

train = pd.read_csv(folder / "payload_train.csv")
test = pd.read_csv(folder / "payload_test.csv")
lexical = pd.read_csv(folder / "payload_test_lexical.csv")

for name, df in [
    ("TRAIN", train),
    ("TEST", test),
    ("LEXICAL TEST", lexical),
]:
    print(f"\n{'=' * 50}")
    print(name)
    print("Rows:", len(df))
    print("Labels:", df["label"].value_counts().to_dict())
    print("Duplicate payload rows:", df["payload"].duplicated().sum())

    invalid = set(df["label"].dropna().unique()) - {"norm", "anom"}
    print("Unexpected labels:", invalid)

    assert df["payload"].notna().all(), f"{name}: missing payload"
    assert df["label"].notna().all(), f"{name}: missing label"
    assert not invalid, f"{name}: unexpected labels"

train_payloads = set(train["payload"].astype(str))
test_payloads = set(test["payload"].astype(str))
lexical_payloads = set(lexical["payload"].astype(str))

print("\n" + "=" * 50)
print("Cross-split overlap")
print("Train/test overlap:", len(train_payloads & test_payloads))
print("Train/lexical overlap:", len(train_payloads & lexical_payloads))
print("Test/lexical overlap:", len(test_payloads & lexical_payloads))

print("\nValidation checks passed.")

