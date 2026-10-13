
from pathlib import Path
import pandas as pd

folder = Path("data/raw/http_params")

for filename in [
    "payload_train.csv",
    "payload_test.csv",
    "payload_test_lexical.csv",
]:
    path = folder / filename
    df = pd.read_csv(path)

    print("\n" + "=" * 60)
    print("FILE:", filename)
    print("Shape:", df.shape)
    print("Columns:", df.columns.tolist())

    print("\nLabel counts:")
    if "label" in df.columns:
        print(df["label"].value_counts(dropna=False))
    else:
        print("No 'label' column found")

    print("\nAttack-type counts:")
    if "attack_type" in df.columns:
        print(df["attack_type"].value_counts(dropna=False))

    print("\nMissing values:")
    print(df.isna().sum())

    print("\nFirst 3 rows:")
    print(df.head(3).to_string(index=False))

print("\nInspection complete.")
