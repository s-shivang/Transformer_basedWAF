from pathlib import Path
import json
import random
from typing import Dict, List, Set, Tuple
import pandas as pd
import numpy as np

from src.pipeline.parser import parse_raw_http
from src.pipeline.schema import ParsedRequest

ROOT = Path(__file__).resolve().parents[2]
RAW_PROCESSED_CSV = ROOT / "data/processed/waf_requests.csv"
OUTPUT_DIR = ROOT / "data/processed"
REPORT_DIR = ROOT / "reports"
AUDIT_REPORT_PATH = REPORT_DIR / "partition_audit_report.json"

RANDOM_SEED = 42


def extract_request_signatures(df: pd.DataFrame) -> pd.DataFrame:
    """
    Parse each raw request and extract its structural template signature
    and normalized payload values.
    """
    print(f"Extracting signatures for {len(df):,} requests...")
    methods = []
    canonical_paths = []
    template_signatures = []
    payload_lists = []

    for idx, row in df.iterrows():
        raw_text = row["request_text"]
        req_id = f"req_{idx}"
        label_int = 1 if str(row["label"]).lower() == "malicious" else 0
        parsed = parse_raw_http(raw_text, request_id=req_id, label=label_int)

        # Collect parameter keys from query and body
        param_keys = set(parsed.query_params.keys())
        if isinstance(parsed.body_params, dict):
            param_keys.update(k for k in parsed.body_params.keys() if not k.startswith("_"))

        sorted_param_keys = sorted(list(param_keys))
        template_sig = f"{parsed.method}:{parsed.path}:{','.join(sorted_param_keys)}"

        methods.append(parsed.method)
        canonical_paths.append(parsed.path)
        template_signatures.append(template_sig)
        payload_lists.append(tuple(parsed.canonical_payloads))

    df["parsed_method"] = methods
    df["canonical_path"] = canonical_paths
    df["template_signature"] = template_signatures
    df["canonical_payloads"] = payload_lists
    return df


def audit_and_partition():
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    if not RAW_PROCESSED_CSV.exists():
        raise FileNotFoundError(f"Source CSV not found: {RAW_PROCESSED_CSV}")

    df_all = pd.read_csv(RAW_PROCESSED_CSV)
    print(f"Total raw CSIC records loaded: {len(df_all):,}")

    # Isolate test pool (36,000 benign + 25,065 malicious = 61,065)
    test_pool = df_all[df_all["split"] == "test"].copy().reset_index(drop=True)
    print(f"Test pool size: {len(test_pool):,} requests")
    print(test_pool["label"].value_counts().to_dict())

    # Extract template signatures and canonical payloads
    test_pool = extract_request_signatures(test_pool)

    # 1. Audit template signatures and label conflicts
    template_groups = test_pool.groupby("template_signature")
    print(f"\nTotal unique template signatures: {len(template_groups):,}")

    template_labels: Dict[str, Set[str]] = {}
    conflict_templates: Dict[str, Dict[str, int]] = {}

    for sig, group in template_groups:
        labels = set(group["label"].unique())
        template_labels[sig] = labels
        if len(labels) > 1:
            conflict_templates[sig] = group["label"].value_counts().to_dict()

    print(f"Templates with both benign and malicious traffic: {len(conflict_templates)}")
    if conflict_templates:
        print("Note: These represent shared application endpoints receiving both benign input and attack payloads.")

    # 2. Balanced Group Partitioning (Indivisible assignment)
    # Stratify templates to achieve ~50/50 balance between Dev and Held-Out
    dev_indices: List[int] = []
    held_out_indices: List[int] = []

    # Sort templates by size descending for greedy balanced partition
    sorted_sigs = sorted(template_groups.groups.keys(), key=lambda s: len(template_groups.get_group(s)), reverse=True)

    dev_benign, dev_mal = 0, 0
    held_benign, held_mal = 0, 0

    target_benign = (test_pool["label"] == "benign").sum() // 2
    target_mal = (test_pool["label"] == "malicious").sum() // 2

    for sig in sorted_sigs:
        group = template_groups.get_group(sig)
        g_benign = (group["label"] == "benign").sum()
        g_mal = (group["label"] == "malicious").sum()
        g_indices = group.index.tolist()

        # Decide whether to assign to dev or held-out based on current balance
        dev_deficit = (target_benign - dev_benign) + (target_mal - dev_mal)
        held_deficit = (target_benign - held_benign) + (target_mal - held_mal)

        if dev_deficit >= held_deficit:
            dev_indices.extend(g_indices)
            dev_benign += g_benign
            dev_mal += g_mal
        else:
            held_out_indices.extend(g_indices)
            held_benign += g_benign
            held_mal += g_mal

    dev_df = test_pool.loc[dev_indices].copy().reset_index(drop=True)
    held_out_df = test_pool.loc[held_out_indices].copy().reset_index(drop=True)

    dev_df["partition"] = "csic_development"
    held_out_df["partition"] = "post_hoc_held_out"

    print("\n=== Partitioning Results ===")
    print(f"CSIC Development Partition: {len(dev_df):,} requests")
    print(dev_df["label"].value_counts().to_dict())
    print(f"Post-Hoc Held-Out Partition: {len(held_out_df):,} requests")
    print(held_out_df["label"].value_counts().to_dict())

    # 3. Cross-Boundary Verification
    dev_sigs = set(dev_df["template_signature"])
    held_sigs = set(held_out_df["template_signature"])
    boundary_template_overlap = dev_sigs & held_sigs
    print(f"\nBoundary template overlap count: {len(boundary_template_overlap)} (Must be 0)")
    assert len(boundary_template_overlap) == 0, "Template overlap detected across partitions!"

    # 4. Exact Text Overlap Audit
    dev_raw_texts = set(dev_df["request_text"])
    held_raw_texts = set(held_out_df["request_text"])
    exact_overlap = dev_raw_texts & held_raw_texts
    print(f"Exact raw request text overlap: {len(exact_overlap)} (Must be 0)")
    assert len(exact_overlap) == 0, "Exact text overlap detected across partitions!"

    # 5. Payload Value Overlap Audit (Tracking attack vectors appearing across endpoints)
    dev_payloads = set(p for sub in dev_df["canonical_payloads"] for p in sub if p)
    held_payloads = set(p for sub in held_out_df["canonical_payloads"] for p in sub if p)
    shared_payload_values = dev_payloads & held_payloads
    print(f"Unique payload values in Dev: {len(dev_payloads):,}")
    print(f"Unique payload values in Held-Out: {len(held_payloads):,}")
    print(f"Shared payload values (across different endpoints): {len(shared_payload_values):,}")

    # 6. Save Data Partitions
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    dev_out_path = OUTPUT_DIR / "csic_dev.parquet"
    held_out_path = OUTPUT_DIR / "csic_held_out_test.parquet"

    # Save compact columns
    cols_to_save = ["request_text", "label", "canonical_path", "template_signature", "partition", "source_file"]
    dev_df[cols_to_save].to_parquet(dev_out_path, index=False)
    held_out_df[cols_to_save].to_parquet(held_out_path, index=False)

    print(f"\nSaved Development Partition: {dev_out_path}")
    print(f"Saved Held-Out Test Partition: {held_out_path}")

    # 7. Generate Audit Report
    audit_data = {
        "audit_name": "CSIC Indivisible Template Grouping and Partition Audit",
        "random_seed": RANDOM_SEED,
        "total_requests_partitioned": len(test_pool),
        "total_unique_templates": len(template_groups),
        "templates_with_label_conflicts": len(conflict_templates),
        "conflict_templates_detail": {k: v for k, v in list(conflict_templates.items())[:20]},
        "development_partition": {
            "total_rows": len(dev_df),
            "label_distribution": dev_df["label"].value_counts().to_dict(),
            "unique_templates": len(dev_sigs),
        },
        "held_out_test_partition": {
            "total_rows": len(held_out_df),
            "label_distribution": held_out_df["label"].value_counts().to_dict(),
            "unique_templates": len(held_sigs),
        },
        "cross_boundary_metrics": {
            "template_signature_overlap": len(boundary_template_overlap),
            "exact_raw_text_overlap": len(exact_overlap),
            "shared_payload_values_count": len(shared_payload_values),
        },
        "scientific_notes": [
            "Template groups assigned indivisibly to prevent structural template leakage.",
            "Prior exposure to official CSIC test data is formally disclosed; held-out partition is designated as Post-Hoc Held-Out.",
            "Shared payload values reflect common SQLi/XSS attack vectors (e.g. ' OR 1=1) and generic parameters tested against distinct endpoints.",
        ]
    }

    with open(AUDIT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2)

    print(f"Saved Audit Report: {AUDIT_REPORT_PATH}")
    return audit_data


if __name__ == "__main__":
    audit_and_partition()
