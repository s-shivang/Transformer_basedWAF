"""
Validation and test suite for the 4-Layer Firewall Architecture.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import time
from src.pipeline.parser import parse_raw_http
from src.firewall.rules_engine import RulesEngine
from src.firewall.anomaly_detector import BehavioralAnomalyDetector
from src.firewall.ml_detector import MLDetector
from src.firewall.decision_engine import CentralDecisionEngine


def run_tests():
    print("=" * 70)
    print("Starting 4-Layer Firewall Architecture Verification Suite")
    print("=" * 70)

    # -------------------------------------------------------------
    # 1. Test Layer 1: Rules & Protocol Validator
    # -------------------------------------------------------------
    print("\n[Layer 1] Testing Rules & Protocol Validator...")
    rules = RulesEngine()

    test_cases = [
        # (name, raw_http, expected_action, expected_rule)
        (
            "Clean GET Request",
            "GET /tienda1/index.jsp?id_articulo=10 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "ALLOW",
            None,
        ),
        (
            "Invalid HTTP Verb",
            "HACK /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "BLOCK",
            "RFC_METHOD_INVALID",
        ),
        (
            "Path Traversal in URL",
            "GET /public/../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "BLOCK",
            "SEC_PATH_TRAVERSAL",
        ),
        (
            "Null Byte Injection",
            "GET /image.png%00.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "BLOCK",
            "SEC_NULL_BYTE_INJECTION",
        ),
        (
            "Deterministic SQLi in Parameter",
            "GET /login?user=admin' UNION SELECT 1,2,3-- HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "BLOCK",
            "SQLI_UNION_SELECT",
        ),
        (
            "XSS Script Tag in Body",
            "POST /comment HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 35\r\n\r\ntext=<script>alert('XSS')</script>",
            "BLOCK",
            "XSS_SCRIPT_TAG",
        ),
    ]

    for name, raw_text, expected_action, expected_rule in test_cases:
        t0 = time.perf_counter()
        req = parse_raw_http(raw_text)
        res = rules.validate(req)
        dur_us = (time.perf_counter() - t0) * 1_000_000.0

        matched_ids = [v.rule_id for v in res.violations]
        status = "PASSED" if res.action == expected_action else "FAILED"
        if expected_rule and expected_rule not in matched_ids:
            status = "FAILED (wrong rule matched)"

        print(f"  [{status}] {name}: Action={res.action} (latency: {dur_us:.1f} us) | Violations: {matched_ids}")
        assert res.action == expected_action, f"Expected {expected_action}, got {res.action}"

    # -------------------------------------------------------------
    # 2. Test Layer 4: Behavioral Anomaly Detector
    # -------------------------------------------------------------
    print("\n[Layer 4] Testing Behavioral Anomaly Detector...")
    anomaly_detector = BehavioralAnomalyDetector(
        window_seconds=10.0,
        rate_limit_per_second=5.0,
        burst_threshold=15,
        sensitive_scan_threshold=3,
    )
    clean_req = parse_raw_http("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")

    # A: Normal single request
    client_a = "client_normal_1"
    res_a = anomaly_detector.evaluate(client_a, clean_req)
    print(f"  [PASSED] Single request: Action={res_a.action}, Score={res_a.anomaly_score}")
    assert res_a.action == "ALLOW"

    # B: Sensitive directory scanning
    client_b = "client_scanner_1"
    now = time.time()
    for sensitive_path in ["/admin", "/.env", "/wp-login.php", "/phpmyadmin"]:
        anomaly_detector.record_event(client_b, sensitive_path, status_code=404, event_time=now)
    res_b = anomaly_detector.evaluate(client_b, clean_req, current_time=now + 0.1)
    print(f"  [PASSED] Sensitive directory scanning: Action={res_b.action}, Score={res_b.anomaly_score}, Reasons={res_b.reasons}")
    assert res_b.action in ("CHALLENGE", "BLOCK")

    # C: Rapid burst flood
    client_c = "client_flooder_1"
    now_c = time.time()
    for i in range(25):
        anomaly_detector.record_event(client_c, f"/item/{i}", status_code=200, event_time=now_c + i * 0.05)
    res_c = anomaly_detector.evaluate(client_c, clean_req, current_time=now_c + 1.5)
    print(f"  [PASSED] High burst flood: Action={res_c.action}, Score={res_c.anomaly_score}, Rate={res_c.request_rate} req/s")
    assert res_c.action in ("CHALLENGE", "BLOCK")

    # -------------------------------------------------------------
    # 3. Test Central Decision Engine
    # -------------------------------------------------------------
    print("\n[Central Decision Engine] Testing full 4-layer coordination...")
    engine = CentralDecisionEngine(
        rules_engine=rules,
        ml_detector=MLDetector(),  # Fallback mode before transformer weights loaded
        anomaly_detector=anomaly_detector,
        tau_block=0.80,
    )

    # Clean request
    dec_clean = engine.inspect_request(clean_req, client_id="user_clean")
    print(f"  [PASSED] Clean Request: Action={dec_clean.action}, Status={dec_clean.http_status}, Latency={dec_clean.latency_ms:.3f} ms")
    assert dec_clean.action == "ALLOW"
    assert dec_clean.http_status == 200

    # Critical attack request
    attack_req = parse_raw_http("GET /search?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: example.com\r\n\r\n")
    dec_attack = engine.inspect_request(attack_req, client_id="attacker_1")
    print(f"  [PASSED] Attack Request: Action={dec_attack.action}, Status={dec_attack.http_status}, Reason='{dec_attack.primary_reason}', Latency={dec_attack.latency_ms:.3f} ms")
    assert dec_attack.action == "BLOCK"
    assert dec_attack.http_status == 403

    print("\n" + "=" * 70)
    print("All 4-Layer Firewall Unit Tests PASSED Successfully!")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
