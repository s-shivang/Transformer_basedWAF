
from pathlib import Path
import pandas as pd

path = Path(
    "data/raw/ai_waf/train-00000-of-00001.parquet"
)

if not path.exists():
    raise FileNotFoundError(f"Dataset not found: {path}")

df = pd.read_parquet(path)

print("Shape:", df.shape)
print("\nColumns:")
print(df.columns.tolist())

print("\nFirst five rows:")
print(df.head().to_string())

print("\nData types:")
print(df.dtypes)

print("\nMissing values:")
print(df.isna().sum())

for col in df.columns:
    if any(word in col.lower() for word in ("label", "class", "attack", "category")):
        print(f"\nValues in {col}:")
        print(df[col].value_counts(dropna=False).head(30))
