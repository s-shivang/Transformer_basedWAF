"""
Dataset Generator for Model v2.2 Upgrade.

Builds:
1. data/processed/dev_v2_2_augmented.parquet:
   - AI WAF baseline (6,000 benign, 3,000 malicious)
   - CSIC Dev baseline (4,000 benign, 3,000 malicious)
   - HttpParams BALANCED: 2,000 benign ('norm') + 2,000 malicious ('anom')
   - Hard-negative training pool (~4,400 benign + ~400 modern API attacks)
   - Pristine 500-sample hard-negative validation set kept isolated.
   - Computes feat_structured_v2_2 for all records.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import random
import pandas as pd
import numpy as np

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features

RANDOM_SEED = 42

OUTPUT_DIR = ROOT / "data/processed"
DEV_POOL_PATH = ROOT / "data/processed/csic_dev.parquet"
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
HTTP_PARAMS_PATH = ROOT / "data/raw/http_params/payload_train.csv"
HARD_NEG_TRAIN_PATH = OUTPUT_DIR / "hard_negatives_train.parquet"
DEV_V2_2_AUGMENTED_PATH = OUTPUT_DIR / "dev_v2_2_augmented.parquet"

def build_dev_v2_2_augmented():
    print("=" * 70)
    print("BUILDING BALANCED AUGMENTED DEVELOPMENT POOL (v2.2)")
    print("=" * 70)

    records = []

    # 1. AI WAF Baseline
    if AI_WAF_PATH.exists():
        print("1. Processing AI WAF baseline...")
        ai_df = pd.read_parquet(AI_WAF_PATH)[["text", "label"]].dropna().copy()
        ai_df["text"] = ai_df["text"].astype(str).str.strip()
        ai_df["label"] = ai_df["label"].astype(str).str.strip().str.lower()
        ai_df = ai_df[ai_df["text"].ne("")].copy()
        ai_df["norm"] = ai_df["text"].str.split().str.join(" ").str.lower()
        ai_df = ai_df.drop_duplicates("norm").reset_index(drop=True)

        sample_ai_benign = ai_df[ai_df["label"] == "benign"].sample(
            min(len(ai_df[ai_df["label"] == "benign"]), 6000), random_state=RANDOM_SEED
        )
        sample_ai_mal = ai_df[ai_df["label"] == "malicious"].sample(
            min(len(ai_df[ai_df["label"] == "malicious"]), 3000), random_state=RANDOM_SEED
        )

        for t in sample_ai_benign["text"]:
            p = parse_raw_http(t, label=0, source="ai_waf")
            records.append({
                "source": "ai_waf",
                "raw_text": t,
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": 0,
                "group_id": f"ai_waf::{p.path}",
            })
        for t in sample_ai_mal["text"]:
            p = parse_raw_http(t, label=1, source="ai_waf")
            records.append({
                "source": "ai_waf",
                "raw_text": t,
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": 1,
                "group_id": f"ai_waf::{p.path}",
            })
        print(f"   Added {len(sample_ai_benign)} benign, {len(sample_ai_mal)} malicious from AI WAF.")

    # 2. CSIC Dev Baseline
    if DEV_POOL_PATH.exists():
        print("2. Processing CSIC Dev baseline...")
        csic_dev = pd.read_parquet(DEV_POOL_PATH)
        csic_benign = csic_dev[csic_dev["label"].str.lower() == "benign"]
        csic_mal = csic_dev[csic_dev["label"].str.lower().isin(["malicious", "anomalous"])]

        sample_csic_benign = csic_benign.sample(min(len(csic_benign), 4000), random_state=RANDOM_SEED)
        sample_csic_mal = csic_mal.sample(min(len(csic_mal), 3000), random_state=RANDOM_SEED)

        for t in sample_csic_benign["request_text"]:
            p = parse_raw_http(t, label=0, source="csic_dev")
            records.append({
                "source": "csic_dev",
                "raw_text": t,
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": 0,
                "group_id": f"csic_dev::{p.path}",
            })
        for t in sample_csic_mal["request_text"]:
            p = parse_raw_http(t, label=1, source="csic_dev")
            records.append({
                "source": "csic_dev",
                "raw_text": t,
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": 1,
                "group_id": f"csic_dev::{p.path}",
            })
        print(f"   Added {len(sample_csic_benign)} benign, {len(sample_csic_mal)} malicious from CSIC Dev.")

    # 3. HttpParams BALANCED (2,000 benign + 2,000 malicious)
    if HTTP_PARAMS_PATH.exists():
        print("3. Processing HttpParams (BALANCED 2,000 norm + 2,000 anom)...")
        hp_df = pd.read_csv(HTTP_PARAMS_PATH).dropna().copy()
        is_mal = hp_df["label"].astype(str).str.strip().str.lower().isin(["anom", "1", "malicious"])
        is_benign = hp_df["label"].astype(str).str.strip().str.lower().isin(["norm", "0", "benign"])

        hp_mal = hp_df[is_mal].sample(min(len(hp_df[is_mal]), 2000), random_state=RANDOM_SEED)
        hp_benign = hp_df[is_benign].sample(min(len(hp_df[is_benign]), 2000), random_state=RANDOM_SEED)

        # In Representation D-v2.2, safe param keys ('q') normalize to P1
        for pl in hp_benign["payload"]:
            raw_text = f"GET /search?q={pl} HTTP/1.1\r\nHost: example.com\r\n\r\n"
            p = parse_raw_http(raw_text, label=0, source="http_params")
            records.append({
                "source": "http_params",
                "raw_text": raw_text,
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": 0,
                "group_id": "http_params::search_benign",
            })

        for pl in hp_mal["payload"]:
            raw_text = f"GET /search?q={pl} HTTP/1.1\r\nHost: example.com\r\n\r\n"
            p = parse_raw_http(raw_text, label=1, source="http_params")
            records.append({
                "source": "http_params",
                "raw_text": raw_text,
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": 1,
                "group_id": "http_params::search_mal",
            })
        print(f"   Added {len(hp_benign)} benign and {len(hp_mal)} malicious from HttpParams.")

    # 4. Hard-Negative Training Pool
    if HARD_NEG_TRAIN_PATH.exists():
        print("4. Processing Hard-Negative Training Pool...")
        hn_train = pd.read_parquet(HARD_NEG_TRAIN_PATH)
        for _, r in hn_train.iterrows():
            p = parse_raw_http(r["raw_text"], label=r["label"], source="hard_negative_aug")
            records.append({
                "source": "hard_negative_aug",
                "raw_text": r["raw_text"],
                "feat_structured_v2_2": build_features(p, "structured_v2_2"),
                "label": r["label"],
                "group_id": r["group_id"],
            })
        print(f"   Added {len(hn_train)} samples from Hard-Negative Training Pool.")

    df_dev_v2_2 = pd.DataFrame(records)
    df_dev_v2_2.to_parquet(DEV_V2_2_AUGMENTED_PATH, index=False)
    print("\n" + "=" * 70)
    print(f"Combined Augmented Development Pool v2.2 SAVED: {len(df_dev_v2_2):,} records")
    print(f"  -> Path: {DEV_V2_2_AUGMENTED_PATH}")
    print(f"  -> Benign (0): {(df_dev_v2_2['label']==0).sum():,} ({(df_dev_v2_2['label']==0).mean()*100:.2f}%)")
    print(f"  -> Malicious (1): {(df_dev_v2_2['label']==1).sum():,} ({(df_dev_v2_2['label']==1).mean()*100:.2f}%)")
    print(f"  -> Sources breakdown:\n{df_dev_v2_2.groupby(['source', 'label']).size()}")
    print("=" * 70)

if __name__ == "__main__":
    build_dev_v2_2_augmented()
