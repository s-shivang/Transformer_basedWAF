"""
Comprehensive PyTest Suite for WAF ML Inference Service.

Covers:
1. Health & Readiness endpoints (including simulated unready state).
2. Benign traffic fast-pass triage (Microsecond TF-IDF).
3. Attack detection (SQLi and XSS block decisions).
4. Score parity with offline pipeline (<= 1e-5 numerical match).
5. Error handling (malformed HTTP, empty payload, oversized payload > 64 KB).
6. Truncation flag verification (> 192 tokens vs <= 192 tokens).
7. Concurrency test (20 parallel requests via httpx.AsyncClient).
8. Live 100-request latency benchmark (p50 / p95 for fast-pass and transformer).
"""
import pytest
import asyncio
import time
import math
import numpy as np
import torch
from fastapi.testclient import TestClient
import httpx

from src.ml_service.app import app
from src.ml_service.model_loader import container
from src.pipeline.schema import ParsedRequest
from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features


@pytest.fixture(scope="module")
def client():
    """Initializes model container and yields a TestClient."""
    if not container.is_ready:
        container.initialize()
    with TestClient(app) as c:
        yield c


# ============================================================================
# 1. Health & Readiness Tests
# ============================================================================

def test_health_endpoint(client):
    """GET /health returns 200 healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "waf-ml-inference"


def test_ready_endpoint_success(client):
    """GET /ready returns 200 with verified SHA-256 and model version."""
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is True
    assert data["sha256_verified"] is True
    assert data["model_version"] == "v1.0.0"
    assert "device" in data


def test_ready_endpoint_unready(client):
    """GET /ready returns 503 when models are not ready."""
    original_ready = container.is_ready
    try:
        container.is_ready = False
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["ready"] is False
    finally:
        container.is_ready = original_ready


def test_model_info_endpoint(client):
    """GET /v1/model-info returns active model metadata and calibrated thresholds."""
    response = client.get("/v1/model-info")
    assert response.status_code == 200
    data = response.json()
    assert data["model_version"] == "v1.0.0"
    assert data["representation_mode"] == "structured"
    assert data["max_length"] == 192
    assert data["sha256_verified"] is True
    assert "thresholds" in data
    assert data["thresholds"]["fast_pass_allow"] == 0.04
    assert data["thresholds"]["block"] == 0.50
    assert "calibration_policy" in data


# ============================================================================
# 2. Benign Traffic Fast-Pass Tests
# ============================================================================

def test_benign_traffic_fast_pass(client):
    """Benign request must trigger Layer 2 Fast-Pass TF-IDF triage with <=0.04 risk."""
    req_payload = {
        "raw_http": "GET /tienda1/index.jsp HTTP/1.1\r\nHost: example.com\r\n\r\n"
    }
    response = client.post("/v1/predict", json=req_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "benign"
    assert data["recommended_tier"] == "fast_pass_allow"
    assert data["stage_used"] == "fast_pass_tfidf"
    assert data["malicious_probability"] <= 0.04
    assert data["status"] == "ok"


# ============================================================================
# 3. Attack Detection Tests
# ============================================================================

def test_sqli_attack_detection(client):
    """SQL Injection attack must be escalated to Transformer and blocked."""
    sqli_raw = (
        "GET /search?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: sqlmap/1.5\r\n\r\n"
    )
    response = client.post("/v1/predict", json={"raw_http": sqli_raw})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "malicious"
    assert data["recommended_tier"] == "block"
    assert data["malicious_probability"] >= 0.50
    assert data["stage_used"] == "transformer"


def test_xss_attack_detection(client):
    """Cross-Site Scripting attack must be escalated to Transformer and blocked."""
    xss_raw = (
        "POST /comment HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "body=<script>alert('xss')</script>"
    )
    response = client.post("/v1/predict", json={"raw_http": xss_raw})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "malicious"
    assert data["recommended_tier"] == "block"
    assert data["malicious_probability"] >= 0.50
    assert data["stage_used"] == "transformer"


# ============================================================================
# 4. Score Parity Test (Service vs. Offline Direct Pipeline)
# ============================================================================

def test_score_parity_with_offline_pipeline(client):
    """
    Verifies that the FastAPI service produces probability scores mathematically
    identical (<= 1e-5) to the direct offline pipeline on the exact same request.
    """
    test_raw = (
        "POST /api/login HTTP/1.1\r\n"
        "Host: bank.local\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "username=admin' OR '1'='1&password=password123"
    )

    # 1. Query FastAPI service
    service_resp = client.post("/v1/predict", json={"raw_http": test_raw})
    assert service_resp.status_code == 200
    service_data = service_resp.json()

    # 2. Compute directly using offline pipeline
    parsed = parse_raw_http(test_raw, request_id="offline_parity_test")
    feat_text = build_features(parsed, representation="structured")

    enc = container.transformer_tokenizer(
        feat_text,
        max_length=container.max_length,
        truncation=True,
        return_tensors="pt"
    ).to(container.device)

    with torch.inference_mode():
        logits = container.transformer_model(**enc).logits
        if container.device.startswith("cuda") and logits.dtype != torch.float32:
            logits = logits.float()
        probs = torch.softmax(logits, dim=-1).squeeze().tolist()
        direct_raw = float(probs[1]) if isinstance(probs, list) else float(probs)

    # Platt calibration formula
    w = float(container.platt_params.get("w", 0.7724))
    b = float(container.platt_params.get("b", 0.4965))
    eps = 1e-7
    p_clipped = min(max(direct_raw, eps), 1.0 - eps)
    logit = math.log(p_clipped / (1.0 - p_clipped))
    direct_calibrated = 1.0 / (1.0 + math.exp(-(w * logit + b)))

    # Assert exact numerical parity
    assert abs(service_data["raw_probability"] - round(direct_raw, 5)) <= 1e-5, (
        f"Raw probability mismatch: service={service_data['raw_probability']}, direct={direct_raw}"
    )
    assert abs(service_data["malicious_probability"] - round(direct_calibrated, 5)) <= 1e-5, (
        f"Calibrated probability mismatch: service={service_data['malicious_probability']}, direct={direct_calibrated}"
    )


# ============================================================================
# 5. Error Handling Tests
# ============================================================================

def test_malformed_raw_http(client):
    """Malformed raw HTTP without valid request line must return HTTP 400."""
    response = client.post("/v1/predict", json={"raw_http": "INVALID_CORRUPTED_LINE"})
    assert response.status_code == 400
    data = response.json()
    assert "Malformed HTTP request" in data["detail"]


def test_empty_input(client):
    """Empty JSON or whitespace string must return HTTP 400."""
    res1 = client.post("/v1/predict", json={})
    assert res1.status_code == 400
    assert "Empty payload" in res1.json()["detail"]

    res2 = client.post("/v1/predict", json={"raw_http": "   \n\t  "})
    assert res2.status_code == 400
    assert "Empty payload" in res2.json()["detail"]


def test_oversized_payload(client):
    """Payloads exceeding 64 KB must return HTTP 422 with a descriptive error."""
    oversized_body = "x=" + ("A" * 70000)
    oversized_http = f"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n{oversized_body}"
    response = client.post("/v1/predict", json={"raw_http": oversized_http})
    assert response.status_code == 422
    data = response.json()
    assert "exceeds maximum allowed limit of 64 KB" in data["detail"]


# ============================================================================
# 6. Truncation Flag Tests
# ============================================================================

def test_truncation_detection(client):
    """Requests exceeding 192 tokens must have truncated=True; shorter requests truncated=False."""
    # Long query parameters exceeding 192 tokens
    long_query = "param=" + ("abcde12345_" * 40)
    long_req = f"GET /api/test?{long_query} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    res_long = client.post("/v1/predict", json={"raw_http": long_req})
    assert res_long.status_code == 200
    assert res_long.json()["truncated"] is True

    # Short request within 192 tokens
    short_req = "GET /status HTTP/1.1\r\nHost: example.com\r\n\r\n"
    res_short = client.post("/v1/predict", json={"raw_http": short_req})
    assert res_short.status_code == 200
    assert res_short.json()["truncated"] is False


# ============================================================================
# 7. Concurrency Test (20 Parallel Requests)
# ============================================================================

def test_concurrent_requests():
    """
    Fires 20 concurrent requests across both fast-pass and transformer branches
    verifying thread safety, 200 responses, and zero CUDA OOM errors.
    """
    async def _run_concurrent():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            tasks = []
            for i in range(20):
                if i % 2 == 0:
                    payload = {
                        "raw_http": f"GET /item/{i} HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    }
                else:
                    payload = {
                        "raw_http": f"GET /search?q=test%20UNION%20SELECT%20{i}%20FROM%20dual-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    }
                tasks.append(ac.post("/v1/predict", json=payload))

            responses = await asyncio.gather(*tasks)

            for res in responses:
                assert res.status_code == 200
                data = res.json()
                assert data["status"] == "ok"
                assert data["prediction"] in ("benign", "malicious")
                assert data["recommended_tier"] in ("fast_pass_allow", "allow", "monitor_alert", "block")

    asyncio.run(_run_concurrent())


# ============================================================================
# 8. Live 100-Request Latency Benchmark
# ============================================================================

def test_latency_benchmark(client):
    """
    Executes 100 sequential requests (50 fast-pass benign + 50 transformer)
    and reports p50 / p95 latencies.
    Verifies that Fast-Pass p50 is < 5.0 ms.
    """
    fast_pass_payload = {
        "raw_http": "GET /tienda1/index.jsp HTTP/1.1\r\nHost: example.com\r\n\r\n"
    }
    transformer_payload = {
        "raw_http": "POST /api/user HTTP/1.1\r\nHost: example.com\r\n\r\nname=admin' OR 1=1--"
    }

    fast_pass_latencies = []
    transformer_latencies = []

    # 50 fast-pass iterations
    for _ in range(50):
        t0 = time.perf_counter()
        resp = client.post("/v1/predict", json=fast_pass_payload)
        t_elapsed = (time.perf_counter() - t0) * 1000.0
        assert resp.status_code == 200
        assert resp.json()["stage_used"] == "fast_pass_tfidf"
        fast_pass_latencies.append(t_elapsed)

    # 50 transformer iterations
    for _ in range(50):
        t0 = time.perf_counter()
        resp = client.post("/v1/predict", json=transformer_payload)
        t_elapsed = (time.perf_counter() - t0) * 1000.0
        assert resp.status_code == 200
        assert resp.json()["stage_used"] == "transformer"
        transformer_latencies.append(t_elapsed)

    # Compute percentiles
    fp_p50 = float(np.percentile(fast_pass_latencies, 50))
    fp_p95 = float(np.percentile(fast_pass_latencies, 95))
    tr_p50 = float(np.percentile(transformer_latencies, 50))
    tr_p95 = float(np.percentile(transformer_latencies, 95))

    print(f"\n--- Latency Benchmark Results (100 sequential requests) ---")
    print(f"Layer 2 Fast-Pass (50 requests): p50 = {fp_p50:.2f} ms, p95 = {fp_p95:.2f} ms")
    print(f"Layer 3 Transformer (50 requests): p50 = {tr_p50:.2f} ms, p95 = {tr_p95:.2f} ms")

    # Fast-pass tier must be < 5.0 ms p50
    assert fp_p50 < 5.0, f"Fast-pass p50 ({fp_p50:.2f} ms) exceeded 5.0 ms target!"


# ============================================================================
# 9. Step 0 Resilience & Integrity Gap Closure Tests
# ============================================================================

def test_sha256_tamper_detection(client, tmp_path):
    """
    Simulates a tampered model manifest with a corrupted hash.
    Verifies that ModelContainer aborts startup with RuntimeError,
    and /ready returns HTTP 503 when SHA-256 verification fails.
    """
    import json
    import shutil
    from src.ml_service.model_loader import ModelContainer, FROZEN_DIR

    # 1. Create temporary directory with a corrupted manifest
    tampered_dir = tmp_path / "tampered_frozen"
    shutil.copytree(str(FROZEN_DIR), str(tampered_dir))

    manifest_file = tampered_dir / "model_manifest.json"
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    # Corrupt one hash
    manifest_data["artifacts_sha256"]["threshold.json"] = "0000000000000000000000000000000000000000000000000000000000000000"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f)

    tampered_container = ModelContainer(frozen_dir=tampered_dir)
    verified, details = tampered_container.verify_checksums()
    assert verified is False
    assert "SHA-256 mismatch" in details.get("error", "")

    with pytest.raises(RuntimeError, match="Startup verification failed"):
        tampered_container.initialize()

    # 2. Verify /ready returns 503 when container is not verified
    original_verified = container.sha256_verified
    try:
        container.sha256_verified = False
        res = client.get("/ready")
        assert res.status_code == 503
        assert res.json()["sha256_verified"] is False
    finally:
        container.sha256_verified = original_verified


def test_tokenizer_inference_exception_safety(client, monkeypatch):
    """
    Simulates an unexpected tokenizer/inference runtime exception.
    Verifies that the FastAPI service catches it cleanly and returns
    structured JSON error response (HTTP 500) without crashing the process.
    """
    def _mock_failing_encode(*args, **kwargs):
        raise RuntimeError("Simulated tokenizer memory corruption error")

    monkeypatch.setattr(container.transformer_tokenizer, "encode", _mock_failing_encode)

    response = client.post(
        "/v1/predict",
        json={"raw_http": "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n"}
    )
    assert response.status_code == 500
    data = response.json()
    assert data["status"] == "error"
    assert data["status_code"] == 500
    assert "Inference error" in data["detail"]
    assert "Simulated tokenizer memory corruption error" in data["detail"]


def test_cpu_fallback_execution():
    """
    Forces device='cpu' simulating a host environment without CUDA support.
    Verifies that ModelContainer initializes on CPU and InferenceEngine
    successfully evaluates a request and returns a valid PredictResponse.
    """
    from src.ml_service.model_loader import ModelContainer
    from src.ml_service.inference_engine import InferenceEngine
    from src.ml_service.schemas import PredictRequest

    cpu_container = ModelContainer()
    cpu_container.initialize(preferred_device="cpu")

    assert cpu_container.device == "cpu"
    assert cpu_container.is_ready is True
    assert cpu_container.sha256_verified is True

    cpu_engine = InferenceEngine(cpu_container)
    req = PredictRequest(
        raw_http="GET /search?id=1%20UNION%20SELECT%201-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    resp = cpu_engine.predict(req)

    assert resp.status == "ok"
    assert resp.prediction == "malicious"
    assert resp.stage_used == "transformer"
    assert resp.malicious_probability >= 0.50

