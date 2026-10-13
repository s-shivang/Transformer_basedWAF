
from pathlib import Path
import pandas as pd

root = Path(__file__).resolve().parents[1]

csic_path = root / "data/processed/waf_requests.csv"
ai_path = root / "data/raw/ai_waf/train-00000-of-00001.parquet"

csic = pd.read_csv(csic_path)
ai = pd.read_parquet(ai_path)

print("CSIC columns:", csic.columns.tolist())
print("AI WAF columns:", ai.columns.tolist())

print("\nCSIC rows:", len(csic))
print("AI WAF rows:", len(ai))

print("\nCSIC labels:")
print(csic["label"].value_counts(dropna=False))

print("\nCSIC splits:")
print(csic["split"].value_counts(dropna=False))

print("\nAI WAF labels:")
print(ai["label"].value_counts(dropna=False))

# Compare normalized text to detect exact request overlap.
def normalize(value):
    return " ".join(str(value).split()).strip().lower()

if "request_text" not in csic.columns:
    raise ValueError("CSIC CSV has no request_text column.")

csic_texts = set(csic["request_text"].dropna().map(normalize))
ai_texts = set(ai["text"].dropna().map(normalize))

overlap = csic_texts & ai_texts

print("\nUnique CSIC request texts:", len(csic_texts))
print("Unique AI WAF request texts:", len(ai_texts))
print("Exact normalized text overlap:", len(overlap))

print("\nOverlap check complete.")
