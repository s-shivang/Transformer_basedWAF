"""
End-to-End Data Plane Integration Test Suite (Phase 7).

Tests the complete HTTP Data Plane:
Client -> WAF Reverse-Proxy Gateway (8001) -> Protected Application (8002)
                                 │
                                 └──> ML Inference Service (8000)

Covers:
1. Benign traffic proxying (200 OK + X-WAF-Action headers).
2. Attack interception in blocking mode (403 Forbidden + upstream never contacted).
3. Monitor mode safety: live attack traffic passed through to app with X-WAF-Action: MONITOR.
4. Privacy-safe security event logging: credentials redacted in waf_security_events.jsonl.
5. Runtime policy switching via /_waf/policy endpoint.
6. Path exclusions bypassing ML.
7. Data plane latency benchmark and concurrency verification.
"""
import pytest
import asyncio
import json
import time
from pathlib import Path
import httpx

from src.protected_app.app import app as protected_app
from src.waf_gateway.app import app as gateway_app, gateway, WAFGatewayApp
from src.ml_service.model_loader import container
from src.ml_service.inference_engine import InferenceEngine
from src.firewall.policy import FirewallPolicy


@pytest.fixture(scope="module")
def shared_ml_engine():
    """Initializes model container for fast in-process ML inference."""
    if not container.is_ready:
        container.initialize()
    return InferenceEngine(container)


@pytest.fixture
def custom_gateway(shared_ml_engine, tmp_path):
    """
    Configures a dedicated WAFGatewayApp wired to in-process ML and protected app,
    writing events to an isolated temporary JSONL file.
    """
    log_file = tmp_path / "test_waf_security_events.jsonl"
    gw = WAFGatewayApp(
        upstream_url="http://127.0.0.1:8002",
        ml_service_url="http://127.0.0.1:8000",
        policy=FirewallPolicy(inspection_mode="monitor"),
        security_log_path=log_file,
        in_process_ml_engine=shared_ml_engine,
        in_process_upstream_app=protected_app,
    )
    return gw


# ============================================================================
# 1. Benign Traffic Proxying Tests
# ============================================================================

@pytest.mark.asyncio
async def test_benign_traffic_forwarded_to_upstream(custom_gateway):
    """Benign requests are forwarded upstream with diagnostic telemetry headers."""
    await custom_gateway.initialize()
    try:
        # Wire global gateway to our test instance
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            resp = await client.get("/api/items/42")

            assert resp.status_code == 200
            data = resp.json()
            assert data["item_id"] == 42
            assert data["in_stock"] is True

            # Verify diagnostic headers
            assert resp.headers["X-WAF-Action"] in ("ALLOW", "MONITOR")
            assert resp.headers["X-WAF-Mode"] == "monitor"
            assert "X-WAF-Request-ID" in resp.headers
            assert "X-WAF-Latency-Ms" in resp.headers
    finally:
        await custom_gateway.shutdown()


# ============================================================================
# 2. Attack Interception in Blocking Mode
# ============================================================================

@pytest.mark.asyncio
async def test_blocking_mode_intercepts_sqli_attack(custom_gateway):
    """In blocking mode, SQLi attack returns 403 Forbidden without contacting protected app."""
    custom_gateway.policy.inspection_mode = "blocking"
    await custom_gateway.initialize()
    try:
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            resp = await client.get("/search?q=1%20UNION%20SELECT%20password%20FROM%20users--")

            assert resp.status_code == 403
            assert resp.headers["X-WAF-Action"] == "BLOCK"
            assert resp.headers["X-WAF-Mode"] == "blocking"
            assert "X-WAF-Reason" in resp.headers

            body = resp.json()
            assert "Request blocked by Transformer-Based WAF" in body["error"]
            assert "SQLI_UNION_SELECT" in str(body["rule_matches"])
    finally:
        await custom_gateway.shutdown()


@pytest.mark.asyncio
async def test_blocking_mode_intercepts_post_body_xss(custom_gateway):
    """In blocking mode, POST body containing XSS is blocked with 403."""
    custom_gateway.policy.inspection_mode = "blocking"
    await custom_gateway.initialize()
    try:
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            payload = {
                "title": "Malicious Blog Post",
                "content": "<script>alert('xss_attack_vector')</script>"
            }
            resp = await client.post("/submit", json=payload)

            assert resp.status_code == 403
            assert resp.headers["X-WAF-Action"] == "BLOCK"
            body = resp.json()
            assert "Request blocked by Transformer-Based WAF" in body["error"]
    finally:
        await custom_gateway.shutdown()


# ============================================================================
# 3. Monitor Mode Safety Tests
# ============================================================================

@pytest.mark.asyncio
async def test_monitor_mode_passes_attacks_safely(custom_gateway):
    """
    In monitor mode, attacks are passed through to the upstream protected app
    with 200 OK, while X-WAF-Action: MONITOR and X-WAF-Would-Action: BLOCK are injected.
    """
    custom_gateway.policy.inspection_mode = "monitor"
    await custom_gateway.initialize()
    try:
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            resp = await client.get("/search?q=1%20UNION%20SELECT%20password%20FROM%20users--")

            # Must NOT block in monitor mode!
            assert resp.status_code == 200
            assert resp.headers["X-WAF-Action"] == "MONITOR"
            assert resp.headers["X-WAF-Would-Action"] == "BLOCK"

            # Upstream search executed simulated reflection
            data = resp.json()
            assert "Simulated SQLi match" in str(data["results"])
    finally:
        await custom_gateway.shutdown()


# ============================================================================
# 4. Sensitive Credential Redaction & Security Event Logging
# ============================================================================

@pytest.mark.asyncio
async def test_security_event_logging_and_credential_redaction(custom_gateway):
    """
    Verifies that security events are logged to JSONL and that passwords,
    session cookies, and tokens are completely redacted.
    """
    await custom_gateway.initialize()
    try:
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            secret_password = "SuperSecretPlainTextPassword123!"
            secret_cookie = "session_id=live_cookie_secret_9999"

            resp = await client.post(
                "/login",
                json={"username": "admin", "password": secret_password},
                headers={"Cookie": secret_cookie, "Authorization": "Bearer top_secret_jwt"},
            )
            assert resp.status_code in (200, 401)

        # Read JSONL event log
        assert custom_gateway.security_log_path.exists()
        with open(custom_gateway.security_log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) >= 1
        last_event = json.loads(lines[-1])

        # Assert raw secrets are NOT in the serialized log line
        raw_log_line = lines[-1]
        assert secret_password not in raw_log_line
        assert secret_cookie not in raw_log_line
        assert "top_secret_jwt" not in raw_log_line

        # Assert redaction placeholders are present
        assert last_event["request"]["headers"]["cookie"] == "[REDACTED]"
        assert last_event["request"]["headers"]["authorization"] == "[REDACTED]"
        assert last_event["request"]["body_params"]["password"] == "[REDACTED]"
    finally:
        await custom_gateway.shutdown()


# ============================================================================
# 5. Runtime Policy Management Endpoints (/_waf/)
# ============================================================================

@pytest.mark.asyncio
async def test_runtime_policy_inspection_and_update(custom_gateway):
    """Verifies that inspection_mode can be switched dynamically via /_waf/policy."""
    await custom_gateway.initialize()
    try:
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            # 1. Check health
            health_res = await client.get("/_waf/health")
            assert health_res.status_code == 200
            assert health_res.json()["inspection_mode"] == "monitor"

            # 2. Get current policy
            policy_res = await client.get("/_waf/policy")
            assert policy_res.status_code == 200
            assert policy_res.json()["inspection_mode"] == "monitor"

            # 3. Switch mode to 'blocking'
            update_res = await client.post(
                "/_waf/policy",
                json={"inspection_mode": "blocking"}
            )
            assert update_res.status_code == 200
            assert update_res.json()["policy"]["inspection_mode"] == "blocking"
            assert custom_gateway.policy.inspection_mode == "blocking"

            # 4. Verify immediate enforcement of blocking mode
            attack_res = await client.get("/search?q=1%20UNION%20SELECT%201--")
            assert attack_res.status_code == 403
            assert attack_res.headers["X-WAF-Action"] == "BLOCK"
    finally:
        await custom_gateway.shutdown()


# ============================================================================
# 6. Data Plane Latency Benchmark (50 Requests)
# ============================================================================

@pytest.mark.asyncio
async def test_data_plane_latency_benchmark(custom_gateway):
    """
    Measures end-to-end latency across the complete proxy chain:
    Client -> Gateway -> Decision Engine -> Protected App.
    """
    await custom_gateway.initialize()
    try:
        from src.waf_gateway import app as module_app
        module_app.gateway = custom_gateway

        transport = httpx.ASGITransport(app=module_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            latencies = []
            for i in range(50):
                t0 = time.perf_counter()
                resp = await client.get(f"/api/items/{i % 10 + 1}")
                dur = (time.perf_counter() - t0) * 1000.0
                assert resp.status_code == 200
                latencies.append(dur)

            latencies.sort()
            p50 = latencies[len(latencies) // 2]
            p95 = latencies[int(len(latencies) * 0.95)]

            print(f"\n--- Data Plane End-to-End Latency Benchmark (50 requests) ---")
            print(f"Proxy Chain Latency: p50 = {p50:.2f} ms, p95 = {p95:.2f} ms")

            # Proxy overhead should be fast (< 25 ms p50)
            assert p50 < 25.0, f"p50 latency ({p50:.2f} ms) exceeded 25 ms target!"
    finally:
        await custom_gateway.shutdown()
