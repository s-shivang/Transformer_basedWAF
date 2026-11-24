"""
Comprehensive Test Suite for WAF Core & Decision Engine (Phase 6).

Covers:
1. Policy configuration & constraints (size limits, disallowed methods, path exclusions).
2. Inspection modes: disabled, monitor (safe by default), blocking, strict.
3. Layer 1 deterministic rules short-circuiting.
4. Multi-signal fusion: Layer 2/3 ML + Layer 4 behavioral anomaly escalation.
5. Challenge band (0.50 - 0.90) and anomaly escalation to BLOCK.
6. Degraded mode / ML failure handling: fail_open vs fail_closed and anomaly protection floor.
7. Decision output schema compliance (WAFDecision).
"""
import pytest
import time
from unittest.mock import MagicMock

from src.firewall.policy import FirewallPolicy, ThresholdConfig
from src.firewall.rules_engine import RulesEngine
from src.firewall.anomaly_detector import BehavioralAnomalyDetector
from src.firewall.ml_client import MLClient, MLClientResult
from src.firewall.decision_engine import CentralDecisionEngine, WAFDecision
from src.ml_service.model_loader import container
from src.ml_service.inference_engine import InferenceEngine


@pytest.fixture(scope="module")
def shared_inference_engine():
    """Initializes in-process ModelContainer and InferenceEngine for hermetic tests."""
    if not container.is_ready:
        container.initialize()
    return InferenceEngine(container)


@pytest.fixture
def in_process_ml_client(shared_inference_engine):
    """Returns an MLClient using the fast in-process InferenceEngine adapter."""
    return MLClient(in_process_engine=shared_inference_engine)


# ============================================================================
# 1. Policy & Request Validation Tests
# ============================================================================

def test_default_policy_is_monitor_mode():
    """Confirms default inspection_mode is 'monitor' (zero automated disruption)."""
    policy = FirewallPolicy()
    assert policy.inspection_mode == "monitor"
    assert policy.rules_enabled is True
    assert policy.ml_enabled is True
    assert policy.anomaly_enabled is True
    assert policy.ml_failure_mode == "fail_open"


def test_inspection_disabled_mode(in_process_ml_client):
    """When inspection_mode is 'disabled', all requests return ALLOW immediately."""
    policy = FirewallPolicy(inspection_mode="disabled")
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    attack_http = "GET /login?user=admin' UNION SELECT 1,2,3-- HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(attack_http)

    assert decision.action == "ALLOW"
    assert decision.would_action == "ALLOW"
    assert decision.reason == "INSPECTION_DISABLED"
    assert decision.risk_score == 0.0


def test_disallowed_http_method_rejection(in_process_ml_client):
    """Disallowed HTTP methods are rejected by the protocol validator."""
    policy = FirewallPolicy(
        inspection_mode="blocking",
        allowed_methods=["GET", "POST"]
    )
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    put_req = "PUT /upload HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(put_req)

    assert decision.action == "BLOCK"
    assert "DISALLOWED_HTTP_METHOD_PUT" in decision.reason
    assert "RFC_METHOD_DISALLOWED" in decision.rule_matches


def test_oversized_payload_rejection(in_process_ml_client):
    """Requests exceeding max_request_size_bytes are rejected."""
    policy = FirewallPolicy(
        inspection_mode="blocking",
        max_request_size_bytes=1000
    )
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    oversized_body = "x=" + ("A" * 2000)
    req = f"POST /submit HTTP/1.1\r\nHost: test.local\r\n\r\n{oversized_body}"
    decision = engine.inspect_request(req)

    assert decision.action == "BLOCK"
    assert decision.reason == "REQUEST_SIZE_LIMIT_EXCEEDED"
    assert "RFC_PAYLOAD_TOO_LARGE" in decision.rule_matches


def test_path_exclusions_bypass_ml(in_process_ml_client):
    """Path matching path_exclusions skips ML and returns ALLOW."""
    policy = FirewallPolicy(
        inspection_mode="blocking",
        path_exclusions=["/healthcheck", "/api/v1/health"]
    )
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    req = "GET /healthcheck?probe=1 HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(req)

    assert decision.action == "ALLOW"
    assert decision.reason == "PATH_EXCLUDED_FROM_ML"
    assert decision.stage_used == "path_exclusion"


# ============================================================================
# 2. Layer 1 Deterministic Rules Short-Circuit Tests
# ============================================================================

def test_layer1_rules_short_circuit_in_blocking_mode(in_process_ml_client):
    """Deterministic attack triggers Layer 1 BLOCK and short-circuits before ML."""
    policy = FirewallPolicy(inspection_mode="blocking")
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    # Classic SQLi union
    sqli_req = "GET /search?id=1%20UNION%20SELECT%20user,pass%20FROM%20users-- HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(sqli_req)

    assert decision.action == "BLOCK"
    assert decision.would_action == "BLOCK"
    assert "LAYER1_RULE_SQLI_UNION_SELECT" in decision.reason
    assert "SQLI_UNION_SELECT" in decision.rule_matches
    assert decision.stage_used == "rules_engine"


def test_layer1_rules_in_monitor_mode(in_process_ml_client):
    """In monitor mode, Layer 1 violation records would_action=BLOCK but action=MONITOR."""
    policy = FirewallPolicy(inspection_mode="monitor")
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    path_trav = "GET /files/../../etc/passwd HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(path_trav)

    assert decision.action == "MONITOR"
    assert decision.would_action == "BLOCK"
    assert "LAYER1_RULE_SEC_PATH_TRAVERSAL" in decision.reason


# ============================================================================
# 3. Layer 2/3 ML + Layer 4 Behavioral Anomaly Fusion Tests
# ============================================================================

def test_fast_pass_clean_traffic(in_process_ml_client):
    """Benign canonical traffic triggers fast-pass TF-IDF and returns ALLOW."""
    policy = FirewallPolicy(inspection_mode="blocking")
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    clean_req = "GET /tienda1/index.jsp HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(clean_req)

    assert decision.action == "ALLOW"
    assert decision.reason == "FAST_PASS_CLEAN"
    assert decision.stage_used == "fast_pass_tfidf"
    assert decision.risk_score <= 0.04


def test_blocking_mode_high_risk_attack(in_process_ml_client):
    """When Layer 1 rules are bypassed/disabled, ML catches attack and triggers BLOCK (>=0.50)."""
    policy = FirewallPolicy(inspection_mode="blocking", rules_enabled=False)
    engine = CentralDecisionEngine(policy=policy, ml_client=in_process_ml_client)

    attack_req = (
        "POST /api/authenticate HTTP/1.1\r\nHost: test.local\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "auth_token=eyJhbGciOi' OR 1=1--"
    )
    decision = engine.inspect_request(attack_req)

    assert decision.action == "BLOCK"
    assert decision.stage_used == "transformer"
    assert decision.risk_score >= 0.50


def test_challenge_band_without_anomaly():
    """Mock ML score in [0.50, 0.90) without anomaly triggers CHALLENGE."""
    policy = FirewallPolicy(inspection_mode="blocking")
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=True,
        risk_score=0.72,
        stage_used="transformer",
        model_version="v1.0.0",
    )
    anomaly_detector = BehavioralAnomalyDetector()

    engine = CentralDecisionEngine(
        policy=policy,
        ml_client=mock_ml,
        anomaly_detector=anomaly_detector,
    )

    req = "POST /api/data HTTP/1.1\r\nHost: test.local\r\n\r\nquery=test"
    decision = engine.inspect_request(req, client_id="client_normal")

    assert decision.action == "CHALLENGE"
    assert decision.would_action == "CHALLENGE"
    assert decision.reason == "ML_CHALLENGE_BAND"
    assert decision.risk_score == 0.72


def test_challenge_band_escalation_with_anomaly():
    """Mock ML score in [0.50, 0.90) WITH active behavioral anomaly escalates to BLOCK."""
    policy = FirewallPolicy(inspection_mode="blocking")
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=True,
        risk_score=0.72,
        stage_used="transformer",
        model_version="v1.0.0",
    )

    # Prime anomaly detector with directory brute-forcing
    anomaly_detector = BehavioralAnomalyDetector()
    client = "attacker_scanner"
    t_base = time.time()
    for sensitive_p in ["/admin", "/.env", "/wp-login.php", "/config.php"]:
        anomaly_detector.record_event(client, sensitive_p, status_code=404, event_time=t_base)

    engine = CentralDecisionEngine(
        policy=policy,
        ml_client=mock_ml,
        anomaly_detector=anomaly_detector,
    )

    req = "POST /api/data HTTP/1.1\r\nHost: test.local\r\n\r\nquery=test"
    decision = engine.inspect_request(req, client_id=client, event_time=t_base + 1.0)

    assert decision.action == "BLOCK"
    assert decision.would_action == "BLOCK"
    assert decision.reason == "ML_AND_ANOMALY_ESCALATION"
    assert len(decision.anomaly_flags) > 0


def test_monitor_mode_never_blocks_live_traffic():
    """In monitor mode, ML attacks receive action=MONITOR and would_action=BLOCK."""
    policy = FirewallPolicy(inspection_mode="monitor", rules_enabled=False)
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=True,
        risk_score=0.98,
        stage_used="transformer",
        model_version="v1.0.0",
    )

    engine = CentralDecisionEngine(policy=policy, ml_client=mock_ml)
    req = "POST /login HTTP/1.1\r\nHost: test.local\r\n\r\nuser=admin' OR 1=1--"
    decision = engine.inspect_request(req)

    assert decision.action == "MONITOR"
    assert decision.would_action == "BLOCK"
    assert decision.reason == "ML_THRESHOLD_EXCEEDED"


def test_strict_mode_blocks_at_lower_threshold():
    """Strict mode blocks at strict_block threshold (0.50)."""
    policy = FirewallPolicy(inspection_mode="strict")
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=True,
        risk_score=0.55,
        stage_used="transformer",
        model_version="v1.0.0",
    )

    engine = CentralDecisionEngine(policy=policy, ml_client=mock_ml)
    req = "GET /item?id=123 HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(req)

    assert decision.action == "BLOCK"
    assert decision.reason == "STRICT_ML_BLOCK"


# ============================================================================
# 4. Degraded Mode & ML Failure Handling Tests
# ============================================================================

def test_ml_failure_fail_open_mode():
    """When ML fails and failure_mode is fail_open, clean requests return ALLOW with degraded_mode=True."""
    policy = FirewallPolicy(inspection_mode="blocking", ml_failure_mode="fail_open")
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=False,
        failure_domain="timeout",
        error_message="Read timeout after 250ms",
    )

    engine = CentralDecisionEngine(policy=policy, ml_client=mock_ml)
    clean_req = "GET /index.html HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(clean_req)

    assert decision.action == "ALLOW"
    assert decision.degraded_mode is True
    assert decision.reason == "ML_UNAVAILABLE_FAIL_OPEN"


def test_ml_failure_fail_closed_mode():
    """When ML fails and failure_mode is fail_closed, requests return BLOCK in blocking mode."""
    policy = FirewallPolicy(inspection_mode="blocking", ml_failure_mode="fail_closed")
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=False,
        failure_domain="connection_refused",
        error_message="Connection refused to 127.0.0.1:8000",
    )

    engine = CentralDecisionEngine(policy=policy, ml_client=mock_ml)
    req = "GET /index.html HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(req)

    assert decision.action == "BLOCK"
    assert decision.degraded_mode is True
    assert decision.reason == "ML_UNAVAILABLE_FAIL_CLOSED"


def test_ml_failure_with_active_anomaly_escalates_to_challenge():
    """During ML outage, client with active behavioral anomaly is challenged even if fail_open."""
    policy = FirewallPolicy(inspection_mode="blocking", ml_failure_mode="fail_open")
    mock_ml = MagicMock()
    mock_ml.predict.return_value = MLClientResult(
        success=False,
        failure_domain="timeout",
        error_message="Timeout",
    )

    anomaly_detector = BehavioralAnomalyDetector()
    client = "scanner_during_outage"
    t_now = time.time()
    for p in ["/actuator", "/.git", "/wp-admin", "/console"]:
        anomaly_detector.record_event(client, p, status_code=404, event_time=t_now)

    engine = CentralDecisionEngine(
        policy=policy,
        ml_client=mock_ml,
        anomaly_detector=anomaly_detector,
    )
    req = "GET /home HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(req, client_id=client, event_time=t_now + 1.0)

    assert decision.action == "CHALLENGE"
    assert decision.degraded_mode is True
    assert decision.reason == "ML_DEGRADED_ANOMALY_ACTIVE"


def test_layer1_rules_protect_during_ml_outage():
    """Deterministic attacks are still BLOCKED by Layer 1 even if ML service is completely down."""
    policy = FirewallPolicy(inspection_mode="blocking", ml_failure_mode="fail_open")
    mock_ml = MagicMock()
    mock_ml.predict.side_effect = RuntimeError("Fatal network crash")

    engine = CentralDecisionEngine(policy=policy, ml_client=mock_ml)
    attack_req = "GET /login?user=admin'%20UNION%20SELECT%201,2-- HTTP/1.1\r\nHost: test.local\r\n\r\n"
    decision = engine.inspect_request(attack_req)

    # Layer 1 intercepted before ML was ever invoked
    assert decision.action == "BLOCK"
    assert "LAYER1_RULE_SQLI_UNION_SELECT" in decision.reason
    assert mock_ml.predict.call_count == 0
