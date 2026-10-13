
from pathlib import Path
import re
import pandas as pd

DATA_DIR = Path("data/raw/csic2010")
OUTPUT_DIR = Path("data/processed")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

REQUEST_START = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+",
    re.IGNORECASE,
)

SOURCES = [
    ("normalTrafficTraining.txt", "benign", "train"),
    ("normalTrafficTest.txt", "benign", "test"),
    ("anomalousTrafficTest.txt", "malicious", "test"),
]


def parse_requests(path):
    requests = []
    current = []

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for raw_line in file:
            line = raw_line.rstrip("\r\n")

            if REQUEST_START.match(line):
                if current:
                    requests.append("\n".join(current).strip())
                current = [line]
            elif current:
                current.append(line)

    if current:
        requests.append("\n".join(current).strip())

    return [request for request in requests if request]


rows = []

for filename, label, split in SOURCES:
    path = DATA_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    requests = parse_requests(path)

    if not requests:
        raise ValueError(f"No HTTP requests parsed from {path}")

    for request in requests:
        rows.append({
            "request_text": request,
            "label": label,
            "split": split,
            "source_file": filename,
        })

    print(f"{filename}: {len(requests):,} requests parsed")

df = pd.DataFrame(rows)

if df["request_text"].isna().any() or (df["request_text"].str.strip() == "").any():
    raise ValueError("Empty request text found; stopping.")

output_path = OUTPUT_DIR / "waf_requests.csv"
df.to_csv(output_path, index=False, encoding="utf-8")

print("\nDataset prepared.")
print(f"Output: {output_path}")
print(f"Total requests: {len(df):,}")

print("\nCounts by split and label:")
print(df.groupby(["split", "label"]).size().to_string())

print(f"\nExact duplicate request texts: {df['request_text'].duplicated().sum():,}")
