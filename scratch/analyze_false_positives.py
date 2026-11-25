"""
False-Positive Root-Cause Analysis for Model v1.0.
Extracts False Positives on:
1. 2,865-sample dev validation split
2. data/processed/csic_held_out_test.parquet (exposed diagnostic dataset)
Categorizes root causes into deterministic categories.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import csv
import re
import urllib.parse
from typing import Tuple, List, Dict
import pandas as pd
import numpy as np

from src.evaluation.canonical_evaluator import CanonicalEvaluator
from src.evaluation.evaluate_v1_vs_v2_1_vs_v2_2 import load_fixed_dev_val_split
from src.pipeline.parser import parse_raw_http

V1_DIR = ROOT / "models/frozen/v1_0"
CSIC_HELD_OUT_PATH = ROOT / "data/processed/csic_held_out_test.parquet"
OUTPUT_CSV = ROOT / "reports/phase7_3_false_positive_analysis.csv"

# Regex / keywords for root-cause classification
SQL_KEYWORDS = re.compile(r"\b(select|union|insert|update|delete|drop|table|from|where|or|and|order\s+by|group\s+by|exec|execute|declare)\b", re.IGNORECASE)
HTML_JS_KEYWORDS = re.compile(r"(<script|<img|<svg|onerror=|onload=|javascript:|alert\(|eval\(|<iframe|<body)", re.IGNORECASE)
CODE_KEYWORDS = re.compile(r"(function|var|const|let|return|import|class|public|private|def|print)", re.IGNORECASE)
ENCODING_PATTERN = re.compile(r"(%[0-9a-fA-F]{2}|\+|\\u[0-9a-fA-F]{4})")
SPECIAL_CHARS = re.compile(r"['\";<>()*#|&]")

print("Initializing Canonical Evaluator for Model v1.0...")
evaluator = CanonicalEvaluator(V1_DIR)


def classify_false_positive(parsed_req, raw_http: str, score: float, token_count: int, source_dataset: str) -> Tuple[str, str]:
    """
    Deterministic rule-based root cause classifier for False Positives.
    """
    path = parsed_req.path or "/"
    query_str = " ".join(f"{k}={v}" for k, v in parsed_req.query_params.items())
    body_str = " ".join(f"{k}={v}" for k, v in parsed_req.body_params.items())
    headers = parsed_req.headers or {}
    
    # 1. Truncation (> 192 tokens)
    if token_count > 192:
        return "LONG_PAYLOAD_TRUNCATION", f"Token count ({token_count}) exceeds max_length 192"

    # Combine inspectable text
    inspect_text = f"{path} {query_str} {body_str} " + " ".join(f"{k}: {v}" for k, v in headers.items())
    
    # Check for encoding artifacts
    enc_matches = ENCODING_PATTERN.findall(raw_http)
    has_heavy_encoding = len(enc_matches) > 3 or "%" in query_str or "%" in body_str

    # 2. Lexical Collision with SQL / HTML / Code words
    sql_hits = SQL_KEYWORDS.findall(inspect_text)
    html_hits = HTML_JS_KEYWORDS.findall(inspect_text)
    code_hits = CODE_KEYWORDS.findall(inspect_text)
    total_lexical = sql_hits + html_hits + code_hits
    if total_lexical:
        unique_hits = list(dict.fromkeys(total_lexical))[:4]
        return "LEXICAL_COLLISION", f"Lexical collision with keyword(s): {', '.join(unique_hits)}"

    # 3. Encoding Artifacts
    if has_heavy_encoding and ("%" in query_str or "%" in body_str or "+" in query_str):
        return "ENCODING_ARTIFACT", f"Heavy URL/percent encoding or special chars: {enc_matches[:3]}"

    # 4. Endpoint Memorization (e.g. repeated Spanish ecommerce paths /tienda/cart /login /comprar)
    csic_known_paths = ["/tienda", "/cart", "/login", "/comprar", "/registro", "/modificar", "/ver", "/anadir"]
    if any(p in path.lower() for p in csic_known_paths):
        return "ENDPOINT_MEMORIZATION", f"Path matched known training template endpoint: {path[:40]}"

    # 5. Domain Shift or Param Format (e.g. non-standard cookie, UUIDs, nested format)
    if source_dataset == "csic_held_out":
        return "DOMAIN_SHIFT_OR_PARAM_FORMAT", f"CSIC domain shift / Spanish e-commerce param pattern"

    return "POTENTIAL_LABEL_OR_PARSE_ISSUE", f"Unclassified anomalous benign token pattern"


fp_rows = []

# --- 1. Dev Validation Split ---
print("\nScanning 2,865 Dev Validation Split...")
raw_dev, y_dev = load_fixed_dev_val_split()
dev_benign_indices = [i for i, y in enumerate(y_dev) if y == 0]
dev_benign_requests = [raw_dev[i] for i in dev_benign_indices]

dev_probs = evaluator.predict_batch(dev_benign_requests, batch_size=128)

for i, (orig_idx, raw_http, prob) in enumerate(zip(dev_benign_indices, dev_benign_requests, dev_probs)):
    if prob >= 0.50:
        p = parse_raw_http(raw_http)
        feat = evaluator.preprocess_request(raw_http)
        tok_len = len(evaluator.container.transformer_tokenizer.encode(feat, add_special_tokens=True, truncation=False))
        
        category, reason = classify_false_positive(p, raw_http, prob, tok_len, "dev_val_split")
        
        band = "BLOCK" if prob >= 0.85 else "CHALLENGE"
        snippet = raw_http.replace("\r", " ").replace("\n", " ")[:120]
        
        param_keys = list(p.query_params.keys()) + ([k for k in p.body_params.keys()] if hasattr(p, 'body_params') else [])
        
        fp_rows.append({
            "sample_id": f"dev_val_{orig_idx}",
            "source_dataset": "dev_val_split",
            "actual_label": "benign",
            "model_version": "v1_0",
            "score": round(float(prob), 5),
            "threshold_band": band,
            "http_method": p.method or "GET",
            "endpoint_path": p.path or "/",
            "param_keys": ";".join(param_keys[:5]),
            "payload_len": len(raw_http),
            "encoding_flags": "encoded" if "%" in raw_http else "raw",
            "root_cause_category": category,
            "sanitized_snippet": snippet.strip(),
        })

print(f"Dev Validation False Positives (@ 0.50): {len(fp_rows)} out of {len(dev_benign_requests)} benign ({len(fp_rows)/len(dev_benign_requests)*100:.2f}%)")

# --- 2. CSIC Held-Out Diagnostic Dataset ---
if CSIC_HELD_OUT_PATH.exists():
    print(f"\nScanning CSIC Held-Out Diagnostic Dataset ({CSIC_HELD_OUT_PATH})...")
    df_csic = pd.read_parquet(CSIC_HELD_OUT_PATH)
    print(f"Loaded {len(df_csic):,} samples from CSIC held-out")
    
    # Filter benign samples
    benign_mask = df_csic["label"].astype(str).str.strip().str.lower() == "benign"
    df_benign = df_csic[benign_mask].reset_index(drop=True)
    print(f"Scanning {len(df_benign):,} benign requests from CSIC held-out (diagnostic)...")
    
    csic_raw = df_benign["request_text"].tolist()
    csic_probs = evaluator.predict_batch(csic_raw, batch_size=128)
    
    csic_fp_count = 0
    for idx, (raw_http, prob) in enumerate(zip(csic_raw, csic_probs)):
        if prob >= 0.50:
            csic_fp_count += 1
            p = parse_raw_http(raw_http)
            feat = evaluator.preprocess_request(raw_http)
            tok_len = len(evaluator.container.transformer_tokenizer.encode(feat, add_special_tokens=True, truncation=False))
            
            category, reason = classify_false_positive(p, raw_http, prob, tok_len, "csic_held_out")
            band = "BLOCK" if prob >= 0.85 else "CHALLENGE"
            snippet = raw_http.replace("\r", " ").replace("\n", " ")[:120]
            param_keys = list(p.query_params.keys()) + ([k for k in p.body_params.keys()] if hasattr(p, 'body_params') else [])
            
            fp_rows.append({
                "sample_id": f"csic_held_out_{idx}",
                "source_dataset": "csic_held_out (exposed diagnostic)",
                "actual_label": "benign",
                "model_version": "v1_0",
                "score": round(float(prob), 5),
                "threshold_band": band,
                "http_method": p.method or "GET",
                "endpoint_path": p.path or "/",
                "param_keys": ";".join(param_keys[:5]),
                "payload_len": len(raw_http),
                "encoding_flags": "encoded" if "%" in raw_http else "raw",
                "root_cause_category": category,
                "sanitized_snippet": snippet.strip(),
            })
    print(f"CSIC Held-Out False Positives (@ 0.50): {csic_fp_count} out of {len(df_benign)} ({csic_fp_count/len(df_benign)*100:.2f}%)")

# Write CSV
OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
fieldnames = [
    "sample_id", "source_dataset", "actual_label", "model_version", "score",
    "threshold_band", "http_method", "endpoint_path", "param_keys",
    "payload_len", "encoding_flags", "root_cause_category", "sanitized_snippet"
]

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(fp_rows)

print(f"\nWrote {len(fp_rows)} False Positive records to {OUTPUT_CSV}")

# Summary breakdown
summary = {}
for r in fp_rows:
    cat = r["root_cause_category"]
    summary[cat] = summary.get(cat, 0) + 1

print("\n--- False Positive Category Breakdown ---")
for cat, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
    print(f"  {cat:32s}: {count:5d} ({count/len(fp_rows)*100:6.2f}%)")
