
from pathlib import Path
import re

DATA_DIR = Path("data/raw/csic2010")

FILES = {
    "normalTrafficTraining.txt": "benign",
    "normalTrafficTest.txt": "benign",
    "anomalousTrafficTest.txt": "malicious",
}

REQUEST_START = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+",
    re.IGNORECASE,
)

for filename, expected_label in FILES.items():
    path = DATA_DIR / filename

    request_count = 0
    blocks = []
    current_block = []
    malformed_starts = 0

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            line = line.rstrip("\r\n")

            if REQUEST_START.match(line):
                if current_block:
                    blocks.append(current_block)
                current_block = [line]
                request_count += 1
            elif current_block:
                current_block.append(line)

        if current_block:
            blocks.append(current_block)

    empty_blocks = sum(
        not any(line.strip() for line in block)
        for block in blocks
    )

    print(f"\nFile: {filename}")
    print(f"Expected label from file role: {expected_label}")
    print(f"Request-start lines: {request_count:,}")
    print(f"Grouped blocks: {len(blocks):,}")
    print(f"Empty blocks: {empty_blocks:,}")

    print("First 3 grouped request starts:")
    for block in blocks[:3]:
        print(" ", block[0][:180])

    print("Last grouped request start:")
    if blocks:
        print(" ", blocks[-1][0][:180])
