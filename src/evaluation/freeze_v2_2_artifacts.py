"""
Freezes v2.2 Model Artifacts and Generates Cryptographic SHA-256 Manifest.

Creates models/frozen/v2_2/ containing:
- tfidf/tfidf_logistic_baseline.joblib
- transformer/ (weights, tokenizer, config)
- threshold.json (locked policy thresholds: fast_pass 0.04, monitor 0.05, challenge 0.50, block 0.85)
- preprocessing_config.json (representation_mode: structured_v2_2)
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

SAVED_TFIDF_PATH = ROOT / "models/saved/tfidf_logistic_v2_2.joblib"
SAVED_TRANSFORMER_DIR = ROOT / "models/saved/transformer_waf_v2_2"
TRAIN_REPORT_PATH = ROOT / "reports/transformer_v2_2_training_report.json"
FROZEN_V2_2_DIR = ROOT / "models/frozen/v2_2"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def freeze_v2_2():
    print(f"[Freeze v2.2] Preparing frozen release in {FROZEN_V2_2_DIR}...")
    FROZEN_V2_2_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy TF-IDF
    tfidf_dest_dir = FROZEN_V2_2_DIR / "tfidf"
    tfidf_dest_dir.mkdir(parents=True, exist_ok=True)
    tfidf_dest_file = tfidf_dest_dir / "tfidf_logistic_baseline.joblib"
    shutil.copy2(SAVED_TFIDF_PATH, tfidf_dest_file)
    print(f"  Copied TF-IDF: {tfidf_dest_file}")

    # 2. Copy Transformer
    transformer_dest_dir = FROZEN_V2_2_DIR / "transformer"
    if transformer_dest_dir.exists():
        shutil.rmtree(transformer_dest_dir)
    shutil.copytree(SAVED_TRANSFORMER_DIR, transformer_dest_dir)
    print(f"  Copied Transformer: {transformer_dest_dir}")

    # Read Platt calibration from report if present
    w_platt = 1.0
    b_platt = 0.0
    if TRAIN_REPORT_PATH.exists():
        with open(TRAIN_REPORT_PATH, "r", encoding="utf-8") as f:
            tr_rep = json.load(f)
            w_platt = tr_rep.get("platt_w", 1.0)
            b_platt = tr_rep.get("platt_b", 0.0)

    # 3. Create threshold.json with locked policy thresholds
    threshold_cfg = {
        "fast_pass_allow": 0.04,
        "monitor_alert": 0.05,
        "challenge": 0.50,
        "block": 0.85,
        "strict_block_low_fpr": 0.90,
        "platt_calibration": {
            "enabled": True,
            "w": w_platt,
            "b": b_platt
        }
    }
    with open(FROZEN_V2_2_DIR / "threshold.json", "w", encoding="utf-8") as f:
        json.dump(threshold_cfg, f, indent=2)
    print("  Created threshold.json")

    # 4. Create preprocessing_config.json
    prep_cfg = {
        "representation_mode": "structured_v2_2",
        "max_length": 192,
        "head_tail_chunking": True,
        "strip_noisy_headers": True,
        "normalize_path": True,
        "normalize_parameter_keys": True,
        "special_tokens": [
            "[METHOD]",
            "[PATH]",
            "[PARAM]",
            "[PAYLOAD]",
            "[HEADERS]"
        ]
    }
    with open(FROZEN_V2_2_DIR / "preprocessing_config.json", "w", encoding="utf-8") as f:
        json.dump(prep_cfg, f, indent=2)
    print("  Created preprocessing_config.json")

    # 5. Compute SHA-256 for all artifacts
    artifacts_sha256 = {}
    for p in sorted(FROZEN_V2_2_DIR.rglob("*")):
        if p.is_file() and p.name != "model_manifest.json":
            rel_path = str(p.relative_to(FROZEN_V2_2_DIR)).replace("\\", "/")
            artifacts_sha256[rel_path] = compute_sha256(p)

    manifest = {
        "model_version": "v2.2",
        "description": "Transformer WAF v2.2 - Smart Path & Param-Key Normalization + Balanced HttpParams Augmentation",
        "representation": "structured_v2_2",
        "artifacts": artifacts_sha256
    }
    with open(FROZEN_V2_2_DIR / "model_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"  Created model_manifest.json with {len(artifacts_sha256)} verified artifacts.")
    print("Freeze v2.2 complete!")


if __name__ == "__main__":
    freeze_v2_2()
