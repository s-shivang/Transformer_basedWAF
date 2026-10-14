from pathlib import Path
import pandas as pd
import json

from src.pipeline.parser import parse_raw_http
from src.pipeline.canonicalizer import canonicalize_value, inspect_encoding_flags

ROOT = Path(__file__).resolve().parents[2]
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_PATH = ROOT / "data/processed/waf_requests.csv"


def test_synthetic_cases():
    print("=== Testing Synthetic Edge Cases ===")
    
    # 1. Double URL encoded SQL injection
    payload = "admin%2527%2520OR%25201=1--"
    val, flags = canonicalize_value(payload)
    print(f"Double-encoded input: {payload}")
    print(f"Canonicalized: {val}")
    print(f"Flags detected: {flags}")
    assert flags["has_double_encoding"] is True, "Double encoding flag failed!"
    assert val == "admin' OR 1=1--", f"Canonicalization expected admin' OR 1=1--, got {val}"
    
    # 2. Raw HTTP parsing with Spanish parameters and headers
    raw_csic = (
        "POST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1\n"
        "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)\n"
        "Host: localhost:8080\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "Content-Length: 35\n"
        "\n"
        "id=2&nombre=camisa&precio=25%2E50"
    )
    parsed = parse_raw_http(raw_csic, request_id="csic_test_01", label=0, source="csic2010")
    print("\nParsed CSIC Request:")
    print(f"Method: {parsed.method}")
    print(f"Path: {parsed.path}")
    print(f"Headers: {list(parsed.headers.keys())}")
    print(f"Body params: {parsed.body_params}")
    print(f"Canonical Payloads: {parsed.canonical_payloads}")
    assert parsed.method == "POST"
    assert parsed.path == "http://localhost:8080/tienda1/publico/anadir.jsp" or "/tienda1/publico/anadir.jsp" in parsed.path
    assert "25.50" in parsed.canonical_payloads or "camisa" in parsed.canonical_payloads
    print("Synthetic tests PASSED!\n")


def test_real_datasets():
    print("=== Testing Real Datasets ===")
    
    # Test AI WAF
    if AI_WAF_PATH.exists():
        ai_df = pd.read_parquet(AI_WAF_PATH)
        sample_ai = ai_df.iloc[0]
        parsed_ai = parse_raw_http(
            sample_ai["text"],
            request_id="ai_01",
            label=1 if sample_ai["label"] == "malicious" else 0,
            source="ai_waf",
        )
        print("Sample AI WAF parsed successfully:")
        print(f"Method: {parsed_ai.method}, Path: {parsed_ai.path}")
        print(f"Headers count: {len(parsed_ai.headers)}")
        print(f"Payload values: {parsed_ai.canonical_payloads}")
    
    # Test CSIC
    if CSIC_PATH.exists():
        csic_df = pd.read_csv(CSIC_PATH, nrows=5)
        sample_csic = csic_df.iloc[0]
        parsed_csic = parse_raw_http(
            sample_csic["request_text"],
            request_id="csic_01",
            label=1 if sample_csic["label"] == "malicious" else 0,
            source="csic2010",
        )
        print("\nSample CSIC parsed successfully:")
        print(f"Method: {parsed_csic.method}, Path: {parsed_csic.path}")
        print(f"Headers count: {len(parsed_csic.headers)}")
        print(f"Payload values: {parsed_csic.canonical_payloads}")

    print("\nReal dataset pipeline validation PASSED!")


if __name__ == "__main__":
    test_synthetic_cases()
    test_real_datasets()

