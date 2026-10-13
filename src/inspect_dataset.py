
from pathlib import Path
from collections import Counter

DATA_DIR = Path("data/raw/csic2010")

FILES = [
    "normalTrafficTraining.txt",
    "normalTrafficTest.txt",
    "anomalousTrafficTest.txt",
]

for filename in FILES:
    path = DATA_DIR / filename

    print(f"\n{'=' * 60}")
    print(f"File: {filename}")
    print(f"Size: {path.stat().st_size:,} bytes")

    with path.open("r", encoding="utf-8", errors="replace") as file:
        lines = [line.rstrip("\r\n") for line in file]

    nonempty_lines = [line for line in lines if line.strip()]

    methods = Counter()
    for line in nonempty_lines:
        first_word = line.split(maxsplit=1)[0].upper()
        if first_word in {
            "GET", "POST", "PUT", "DELETE",
            "PATCH", "HEAD", "OPTIONS"
        }:
            methods[first_word] += 1

    print(f"Total lines: {len(lines):,}")
    print(f"Nonempty lines: {len(nonempty_lines):,}")
    print(f"HTTP method lines: {sum(methods.values()):,}")
    print(f"Method counts: {dict(methods)}")

    print("\nFirst 12 nonempty lines:")
    for line in nonempty_lines[:12]:
        print(line[:200])
