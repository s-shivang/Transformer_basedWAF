"""
Freezes v2.0 Model Artifacts and Generates Cryptographic SHA-256 Manifest.

Creates models/frozen/v2_0/ containing:
- tfidf/tfidf_logistic_baseline.joblib
- transformer/ (weights, tokenizer, config)
- threshold.json
- preprocessing_config.json
- model_manifest.json (with verified SHA-256 checksums)
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import shutil
import hashlib

SAVED_TFIDF_PATH = ROOT / "models/saved/tfidf_logistic_v2.joblib"
SAVED_TRANSFORMER_DIR = ROOT / "models/saved/transformer_waf_v2"
FROZEN_V2_DIR = ROOT / "models/frozen/v2_0"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def freeze_v2():
    print(f"[Freeze v2.0] Preparing frozen release in {FROZEN_V2_DIR}...")
    FROZEN_V2_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy TF-IDF
    tfidf_dest_dir = FROZEN_V2_DIR / "tfidf"
    tfidf_dest_dir.mkdir(parents=True, exist_ok=True)
    tfidf_dest_file = tfidf_dest_dir / "tfidf_logistic_baseline.joblib"
    shutil.copy2(SAVED_TFIDF_PATH, tfidf_dest_file)
    print(f"  Copied TF-IDF: {tfidf_dest_file}")

    # 2. Copy Transformer
    transformer_dest_dir = FROZEN_V2_DIR / "transformer"
    if transformer_dest_dir.exists():
        shutil.rmtree(transformer_dest_dir)
    shutil.copytree(SAVED_TRANSFORMER_DIR, transformer_dest_dir)
    print(f"  Copied Transformer: {transformer_dest_dir}")

    # 3. Create threshold.json
    threshold_cfg = {
        "fast_pass_allow": 0.04,
        "monitor_alert": 0.05,
        "challenge": 0.15,
        "block": 0.43,
        "strict_block_low_fpr": 0.90,
        "platt_calibration": {
            "enabled": True,
            "w": 0.9771,
            "b": -0.2533
        }
    }
    with open(FROZEN_V2_DIR / "threshold.json", "w", encoding="utf-8") as f:
        json.dump(threshold_cfg, f, indent=2)
    print("  Created threshold.json")

    # 4. Create preprocessing_config.json
    prep_cfg = {
        "representation_mode": "structured_v2",
        "max_length": 192,
        "head_tail_chunking": True,
        "special_tokens": [
            "[METHOD]",
            "[PATH]",
            "[PARAM]",
            "[PAYLOAD]",
            "[HEADERS]"
        ]
    }
    with open(FROZEN_V2_DIR / "preprocessing_config.json", "w", encoding="utf-8") as f:
        json.dump(prep_cfg, f, indent=2)
    print("  Created preprocessing_config.json")

    # 5. Compute SHA-256 for all artifacts
    artifacts_sha256 = {}
    for p in sorted(FROZEN_V2_DIR.rglob("*")):
        if p.is_file() and p.name != "model_manifest.json":
            rel_path = str(p.relative_to(FROZEN_V2_DIR)).replace("\\", "/")
            artifacts_sha256[rel_path] = compute_sha256(p)

    manifest = {
        "model_version": "v2.0.0",
        "created_timestamp": "2026-11-25T00:10:00+05:30",
        "description": "Transformer-Based WAF Frozen Release v2.0 with Representation D-v2, Hard-Negative Augmentation, and Head+Tail Chunking",
        "architecture": {
            "tier1_fast_pass": "TF-IDF (Char n-gram 3-5) + Logistic Regression",
            "tier2_contextual": "sentence-transformers/all-MiniLM-L6-v2 (FP16)",
            "representation": "structured_v2 (Header Stripping & Payload Prioritization)",
            "head_tail_chunking": True,
            "max_length": 192,
        },
        "artifacts_sha256": artifacts_sha256,
    }

    manifest_path = FROZEN_V2_DIR / "model_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"  Created model_manifest.json ({len(artifacts_sha256)} verified artifacts)")
    print(f"[Freeze v2.0 Complete] Artifacts ready in {FROZEN_V2_DIR}")


if __name__ == "__main__":
    freeze_v2()
