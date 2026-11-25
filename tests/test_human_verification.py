"""
Phase 7.5 Human Verification & Interactive Challenge Test Suite.

Verifies:
1. Browser request in gray zone (0.50 <= risk_score < 0.85) receives interactive HTML verification page
   with one of 3 randomized tasks and valid PoW challenge.
2. JSON API request (Accept: application/json) in gray zone receives HTTP 429 JSON (never HTML).
3. Solving a challenge via POST /_waf/challenge/verify sets HttpOnly; SameSite=Lax waf_clearance cookie.
4. Follow-up gray zone request with valid waf_clearance cookie passes through (200 OK) with X-WAF-Action: ALLOW.
5. Security tests:
   - Nonce replay rejected (403).
   - Instant bot speed (< 250ms) rejected (403).
   - Invalid Proof-of-Work rejected (403).
   - Stolen cookie with different User-Agent or IP rejected.
   - Malicious open redirect ("https://evil.com" or "//evil.com") sanitized to "/".
6. Critical invariant:
   - Valid clearance cookie NEVER bypasses hard block (risk_score >= 0.85 or Layer 1 attack like SQLi/traversal).
"""
import pytest
import asyncio
import hashlib
import time
import httpx
from pathlib import Path

from src.protected_app.app import app as protected_app
from src.waf_gateway.app import app as gateway_app, WAFGatewayApp
from src.waf_gateway.challenge import challenge_manager, sanitize_redirect_url
from src.ml_service.model_loader import container
from src.ml_service.inference_engine import InferenceEngine
from src.firewall.policy import FirewallPolicy
from src.pipeline.schema import ParsedRequest


@pytest.fixture(scope="module")
def shared_ml_engine():
    if not container.is_ready:
        container.initialize()
    return InferenceEngine(container)


@pytest.fixture
def challenge_gateway(shared_ml_engine, tmp_path):
    log_file = tmp_path / "test_challenge_security_events.jsonl"
    gw = WAFGatewayApp(
        upstream_url="http://127.0.0.1:8002",
        ml_service_url="http://127.0.0.1:8000",
        policy=FirewallPolicy(
            inspection_mode="blocking",
            rules_enabled=True,
            ml_enabled=True,
            anomaly_enabled=True,
        ),
        security_log_path=log_file,
        in_process_ml_engine=shared_ml_engine,
        in_process_upstream_app=protected_app,
    )
    return gw


def solve_pow(prefix: str, difficulty: int = 3) -> str:
    """Helper to solve browser Proof-of-Work in Python."""
    target_prefix = "0" * difficulty
    nonce = 0
    while True:
        h = hashlib.sha256(f"{prefix}{nonce}".encode("utf-8")).hexdigest()
        if h.startswith(target_prefix):
            return str(nonce)
        nonce += 1


# ============================================================================
# 1. Challenge Rendering Tests (Browser vs. API)
# ============================================================================

def test_browser_in_gray_zone_receives_html_challenge(challenge_gateway):
    """
    Simulate a request that falls in the gray challenge zone (0.50 <= score < 0.85).
    A browser request (Accept: text/html) must receive a 403 HTML challenge page.
    """
    async def _run():
        await challenge_gateway.initialize()
        try:
            import src.waf_gateway.app as gw_mod
            gw_mod.set_gateway(challenge_gateway)

            # Trigger an anomaly score into the challenge band via sensitive probe scanning
            client_ip = "192.168.1.100"
            for probe in ["/admin", "/.env", "/config.php", "/phpmyadmin"]:
                challenge_gateway.decision_engine.anomaly_detector.record_event(
                    client_id=client_ip,
                    path=probe,
                    status_code=404,
                )

            transport = httpx.ASGITransport(app=gw_mod.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "X-Forwarded-For": client_ip,
                }
                resp = await client.get("/api/items/1", headers=headers)

                assert resp.status_code == 403
                assert "text/html" in resp.headers["content-type"]
                assert resp.headers["X-WAF-Action"] == "CHALLENGE"
                html_body = resp.text
                assert "Quick Security Check" in html_body
                assert "task-container" in html_body
                assert "crypto.subtle.digest" in html_body
                assert "submitChallenge" in html_body
        finally:
            await challenge_gateway.shutdown()

    asyncio.run(_run())


def test_api_in_gray_zone_receives_json_429(challenge_gateway):
    """
    An API / curl client (Accept: application/json) in the gray zone must receive
    HTTP 429 JSON, never HTML.
    """
    async def _run():
        await challenge_gateway.initialize()
        try:
            import src.waf_gateway.app as gw_mod
            gw_mod.set_gateway(challenge_gateway)

            client_ip = "192.168.1.101"
            for probe in ["/admin", "/.env", "/config.php", "/phpmyadmin"]:
                challenge_gateway.decision_engine.anomaly_detector.record_event(
                    client_id=client_ip,
                    path=probe,
                    status_code=404,
                )

            transport = httpx.ASGITransport(app=gw_mod.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
                headers = {
                    "User-Agent": "curl/7.88.1",
                    "Accept": "application/json",
                    "X-Forwarded-For": client_ip,
                }
                resp = await client.get("/api/items/1", headers=headers)

                assert resp.status_code == 429
                assert "application/json" in resp.headers["content-type"]
                assert resp.headers["X-WAF-Action"] == "CHALLENGE"
                data = resp.json()
                assert data["action"] == "CHALLENGE"
                assert data["challenge_required"] is True
                assert "error" in data
        finally:
            await challenge_gateway.shutdown()

    asyncio.run(_run())


# ============================================================================
# 2. Challenge Solving & Clearance Cookie Flow
# ============================================================================

def test_challenge_solve_sets_cookie_and_permits_traffic(challenge_gateway):
    """
    Solving a valid challenge sets an HttpOnly waf_clearance cookie, and subsequent
    gray-zone requests carrying that cookie are downgraded to ALLOW (200 OK).
    """
    async def _run():
        await challenge_gateway.initialize()
        try:
            import src.waf_gateway.app as gw_mod
            gw_mod.set_gateway(challenge_gateway)

            client_ip = "127.0.0.1"
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser"

            # 1. Generate challenge
            pkg = challenge_manager.generate_challenge(
                client_ip=client_ip,
                user_agent=user_agent,
                redirect_url="/api/items/5",
            )
            pow_nonce = solve_pow(pkg["pow_prefix"], pkg["pow_difficulty"])

            task = pkg["task"]
            if task["type"] == "slider":
                ans = str(task["target_x"])
            elif task["type"] == "rotate":
                ans = "0"
            else:
                ans = "1,2"

            transport = httpx.ASGITransport(app=gw_mod.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
                # 2. Verify solution via POST /_waf/challenge/verify
                verify_payload = {
                    "token": pkg["token"],
                    "answer": ans,
                    "pow_nonce": pow_nonce,
                    "duration_ms": 500,  # Human duration > 250ms
                    "redirect_url": "/api/items/5",
                }
                verify_headers = {"User-Agent": user_agent}
                v_resp = await client.post("/_waf/challenge/verify", json=verify_payload, headers=verify_headers)

                assert v_resp.status_code == 200
                v_data = v_resp.json()
                assert v_data["verified"] is True
                assert v_data["redirect_url"] == "/api/items/5"
                assert "waf_clearance" in v_resp.cookies
                clearance_val = v_resp.cookies["waf_clearance"]

                # 3. Trigger anomaly challenge condition on client IP
                for probe in ["/admin", "/.env", "/config.php", "/phpmyadmin"]:
                    challenge_gateway.decision_engine.anomaly_detector.record_event(
                        client_id=client_ip,
                        path=probe,
                        status_code=404,
                    )

                # 4. Make request with clearance cookie -> should pass through (200 OK)
                req_headers = {
                    "User-Agent": user_agent,
                    "Accept": "text/html",
                }
                cookies = {"waf_clearance": clearance_val}
                cleared_resp = await client.get("/api/items/5", headers=req_headers, cookies=cookies)

                assert cleared_resp.status_code == 200
                assert cleared_resp.headers["X-WAF-Action"] == "ALLOW"
                assert cleared_resp.json()["item_id"] == 5
        finally:
            await challenge_gateway.shutdown()

    asyncio.run(_run())


# ============================================================================
# 3. Security Tests: Nonce Replay, Bot Speed, PoW, Stolen Cookie, Open Redirect
# ============================================================================

def test_nonce_replay_is_rejected():
    """Consuming the same challenge token twice must fail with NONCE_REPLAY_DETECTED."""
    client_ip = "127.0.0.1"
    ua = "SecurityTester/1.0"
    pkg = challenge_manager.generate_challenge(client_ip, ua)
    pow_nonce = solve_pow(pkg["pow_prefix"], pkg["pow_difficulty"])
    ans = str(pkg["task"].get("target_x", "0")) if pkg["task"]["type"] == "slider" else ("0" if pkg["task"]["type"] == "rotate" else "1,2")

    # Solve 1: Success
    ok, reason, _ = challenge_manager.verify_solution(
        token=pkg["token"],
        answer=ans,
        pow_nonce=pow_nonce,
        duration_ms=400,
        client_ip=client_ip,
        user_agent=ua,
    )
    assert ok is True
    assert reason == "VERIFICATION_SUCCESS"

    # Solve 2: Replay must be rejected
    ok2, reason2, _ = challenge_manager.verify_solution(
        token=pkg["token"],
        answer=ans,
        pow_nonce=pow_nonce,
        duration_ms=400,
        client_ip=client_ip,
        user_agent=ua,
    )
    assert ok2 is False
    assert reason2 == "NONCE_REPLAY_DETECTED"


def test_bot_speed_instant_solve_rejected():
    """Duration under 250ms must be rejected as automated bot speed."""
    client_ip = "127.0.0.1"
    ua = "SpeedBot/1.0"
    pkg = challenge_manager.generate_challenge(client_ip, ua)
    pow_nonce = solve_pow(pkg["pow_prefix"], pkg["pow_difficulty"])
    ans = "0" if pkg["task"]["type"] == "rotate" else (str(pkg["task"].get("target_x", "0")) if pkg["task"]["type"] == "slider" else "1,2")

    ok, reason, _ = challenge_manager.verify_solution(
        token=pkg["token"],
        answer=ans,
        pow_nonce=pow_nonce,
        duration_ms=10,  # 10ms is superhuman / bot speed
        client_ip=client_ip,
        user_agent=ua,
    )
    assert ok is False
    assert reason == "BOT_SPEED_REJECTED"


def test_invalid_pow_rejected():
    """An incorrect Proof-of-Work nonce must fail."""
    client_ip = "127.0.0.1"
    ua = "FakePoW/1.0"
    pkg = challenge_manager.generate_challenge(client_ip, ua)

    ok, reason, _ = challenge_manager.verify_solution(
        token=pkg["token"],
        answer="0",
        pow_nonce="wrong_invalid_nonce_99999",
        duration_ms=500,
        client_ip=client_ip,
        user_agent=ua,
    )
    assert ok is False
    assert reason == "INVALID_PROOF_OF_WORK"


def test_stolen_clearance_cookie_rejected():
    """A clearance cookie issued to IP A and UA A cannot be used by IP B or UA B."""
    ip_a = "192.168.1.10"
    ua_a = "LegitBrowser/1.0"
    cookie = challenge_manager.issue_clearance_cookie(ip_a, ua_a)

    # Valid for same IP + UA
    assert challenge_manager.validate_clearance_cookie(cookie, ip_a, ua_a) is True

    # Stolen by different IP -> rejected
    assert challenge_manager.validate_clearance_cookie(cookie, "10.0.0.99", ua_a) is False

    # Stolen by different User-Agent -> rejected
    assert challenge_manager.validate_clearance_cookie(cookie, ip_a, "AttackerBot/2.0") is False


def test_open_redirect_sanitization():
    """Redirect URLs must not allow open redirect attacks to external hosts."""
    assert sanitize_redirect_url("https://evil.com") == "/"
    assert sanitize_redirect_url("//evil.com") == "/"
    assert sanitize_redirect_url("/\\evil.com") == "/"
    assert sanitize_redirect_url("javascript:alert(1)") == "/"
    assert sanitize_redirect_url("/account/profile") == "/account/profile"
    assert sanitize_redirect_url("/search?q=apples&category=1") == "/search?q=apples&category=1"


# ============================================================================
# 4. Critical Invariant: Clearance Cookie NEVER Bypasses Hard Block
# ============================================================================

def test_clearance_cookie_never_bypasses_hard_block_or_sqli(challenge_gateway):
    """
    INVARIANT: Even if an attacker possesses a 100% valid waf_clearance cookie,
    high-confidence attacks (risk_score >= 0.85 or Layer 1 SQLi / path traversal)
    MUST STILL RETURN 403 FORBIDDEN.
    """
    async def _run():
        await challenge_gateway.initialize()
        try:
            import src.waf_gateway.app as gw_mod
            gw_mod.set_gateway(challenge_gateway)

            client_ip = "127.0.0.1"
            ua = "Mozilla/5.0 InvariantTester"
            cookie = challenge_manager.issue_clearance_cookie(client_ip, ua)

            transport = httpx.ASGITransport(app=gw_mod.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
                headers = {"User-Agent": ua}
                cookies = {"waf_clearance": cookie}

                # 1. Deterministic SQLi -> Must return 403 BLOCK
                resp_sqli = await client.get("/search?q=1%20UNION%20SELECT%201--", headers=headers, cookies=cookies)
                assert resp_sqli.status_code == 403
                assert resp_sqli.headers["X-WAF-Action"] == "BLOCK"
                assert "LAYER1_RULE" in resp_sqli.headers.get("X-WAF-Reason", "")

                # 2. Path Traversal -> Must return 403 BLOCK
                resp_trav = await client.get("/files?name=../../etc/passwd", headers=headers, cookies=cookies)
                assert resp_trav.status_code == 403
                assert resp_trav.headers["X-WAF-Action"] == "BLOCK"
                assert "LAYER1_RULE" in resp_trav.headers.get("X-WAF-Reason", "")
        finally:
            await challenge_gateway.shutdown()

    asyncio.run(_run())
