"""
Phase 17C Tests: Dynamic Host-Based Routing, Per-Site Policy Execution & DNS-Rebinding SSRF Guard.

Verifies:
1. Multi-tenant dynamic host routing via HostRegistry without gateway restart.
2. Per-site policy isolation: Site A (blocking) blocks SQLi, Site B (monitor) passes SQLi.
3. Unknown host rejection (404 UNKNOWN_HOST, never hits default upstream).
4. Dynamic domain eviction via DELETE /_waf/sites/{domain}.
5. SSRF & DNS-rebinding guard: blocks metadata, link-local, private IPs based on policy.
"""
import pytest
import asyncio
import httpx
from unittest.mock import patch
from fastapi import FastAPI, Response
from starlette.testclient import TestClient

from src.ml_service.model_loader import container
from src.ml_service.inference_engine import InferenceEngine
from src.waf_gateway.origin_guard import (
    validate_origin_before_connect,
    OriginSSRFBlockedError,
    clear_dns_cache,
)
from src.waf_gateway.host_registry import host_registry
from src.waf_gateway.app import (
    app,
    DEFAULT_ADMIN_KEY,
    WAFGatewayApp,
    set_gateway,
)
from src.firewall.policy import FirewallPolicy


@pytest.fixture(scope="module")
def shared_ml_engine():
    """Initializes in-process InferenceEngine once for integration tests."""
    if not container.is_ready:
        container.initialize()
    return InferenceEngine(container)


# ============================================================================
# Mock Upstream Apps
# ============================================================================

mock_app_a = FastAPI(title="Mock Upstream A")
mock_app_b = FastAPI(title="Mock Upstream B")

app_a_hits = []
app_b_hits = []


@mock_app_a.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def upstream_a_handler(path: str):
    app_a_hits.append(path)
    return {"app": "site-a", "path": path}


@mock_app_b.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def upstream_b_handler(path: str):
    app_b_hits.append(path)
    return {"app": "site-b", "path": path}


# ============================================================================
# 1. DNS-Rebinding & SSRF Guard Unit Tests
# ============================================================================

def test_origin_guard_always_blocks_link_local_metadata():
    clear_dns_cache()
    # 169.254.169.254 must be blocked even when allow_private_origins=True
    with pytest.raises(OriginSSRFBlockedError, match="forbidden link-local or metadata"):
        validate_origin_before_connect("http://169.254.169.254/latest/meta-data", allow_private_origins=True)

    with pytest.raises(OriginSSRFBlockedError, match="forbidden link-local or metadata"):
        validate_origin_before_connect("https://169.254.1.1:8443", allow_private_origins=True)


def test_origin_guard_blocks_unspecified_and_metadata_hostname():
    clear_dns_cache()
    with pytest.raises(OriginSSRFBlockedError, match="unspecified IP"):
        validate_origin_before_connect("http://0.0.0.0:8000", allow_private_origins=True)

    with pytest.raises(OriginSSRFBlockedError, match="cloud metadata hostname"):
        validate_origin_before_connect("http://metadata.google.internal/computeMetadata/v1", allow_private_origins=True)


def test_origin_guard_private_origins_toggle():
    clear_dns_cache()
    # When allow_private_origins=False (production default): blocks 127.0.0.1, 10.x, 192.168.x
    with pytest.raises(OriginSSRFBlockedError, match="loopback IP"):
        validate_origin_before_connect("http://127.0.0.1:8002", allow_private_origins=False)

    with pytest.raises(OriginSSRFBlockedError, match="private RFC1918/ULA"):
        validate_origin_before_connect("http://10.0.0.5:8080", allow_private_origins=False)

    with pytest.raises(OriginSSRFBlockedError, match="private RFC1918/ULA"):
        validate_origin_before_connect("http://192.168.1.10:3000", allow_private_origins=False)

    # When allow_private_origins=True (local dev / Docker opt-in): allows private IP
    ips_loopback = validate_origin_before_connect("http://127.0.0.1:8002", allow_private_origins=True)
    assert "127.0.0.1" in ips_loopback

    ips_priv = validate_origin_before_connect("http://10.0.0.5:8080", allow_private_origins=True)
    assert "10.0.0.5" in ips_priv


def test_origin_guard_dns_rebinding_simulation():
    clear_dns_cache()
    # Simulate a domain that resolves to AWS metadata IP
    with patch("src.waf_gateway.origin_guard.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (2, 1, 6, "", ("169.254.169.254", 80))
        ]
        with pytest.raises(OriginSSRFBlockedError, match="forbidden link-local or metadata"):
            validate_origin_before_connect("http://rebind.attacker.com", allow_private_origins=True)


# ============================================================================
# 2. Dynamic Host-Based Routing & Per-Site Policy Execution Tests
# ============================================================================

@pytest.fixture
def dynamic_routing_gateway(shared_ml_engine, tmp_path):
    """
    Configures a dedicated gateway with dynamic routing, in-process ML and in-process upstream routing.
    """
    host_registry.clear()
    clear_dns_cache()
    app_a_hits.clear()
    app_b_hits.clear()

    log_file = tmp_path / "test_dynamic_security_events.jsonl"
    gw = WAFGatewayApp(
        upstream_url="http://default-upstream.internal",
        policy=FirewallPolicy(inspection_mode="monitor"),
        security_log_path=log_file,
        in_process_ml_engine=shared_ml_engine,
        in_process_upstream_apps={
            "http://app-a-backend.internal": mock_app_a,
            "http://app-b-backend.internal": mock_app_b,
        },
        dynamic_routing_enabled=True,
        allow_private_origins=True,
    )
    set_gateway(gw)

    yield gw

    host_registry.clear()
    clear_dns_cache()


def test_dynamic_host_routing_and_policy_isolation(dynamic_routing_gateway):
    gw = dynamic_routing_gateway

    async def _run():
        await gw.initialize()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            # 1. Sync Site A -> mode="blocking", points to Upstream A
            res_a = await client.post(
                "/_waf/sites/sync",
                json={
                    "site_id": "site-a-id",
                    "tenant_id": "tenant-alpha",
                    "domain": "app-a.local.test",
                    "origin_url": "http://127.0.0.1:8002",
                    "config_version": 1,
                    "policy": {
                        "mode": "blocking",
                        "block_threshold": 0.85,
                        "challenge_threshold": 0.50,
                        "monitor_threshold": 0.05,
                        "ml_enabled": True,
                        "rules_enabled": True,
                    },
                },
                headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
            )
            assert res_a.status_code == 200
            assert res_a.json()["acknowledged"] is True

            # 2. Sync Site B -> mode="monitor", points to Upstream B
            res_b = await client.post(
                "/_waf/sites/sync",
                json={
                    "site_id": "site-b-id",
                    "tenant_id": "tenant-beta",
                    "domain": "app-b.local.test",
                    "origin_url": "http://127.0.0.1:8002",
                    "config_version": 1,
                    "policy": {
                        "mode": "monitor",
                        "block_threshold": 0.85,
                        "challenge_threshold": 0.50,
                        "monitor_threshold": 0.05,
                        "ml_enabled": True,
                        "rules_enabled": True,
                    },
                },
                headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
            )
            assert res_b.status_code == 200
            assert res_b.json()["acknowledged"] is True

            # Override origin URLs to in-process mock apps for exact response verification
            host_registry.upsert_site({
                "site_id": "site-a-id",
                "tenant_id": "tenant-alpha",
                "domain": "app-a.local.test",
                "origin_url": "http://app-a-backend.internal",
                "config_version": 2,
                "policy": {
                    "mode": "blocking",
                    "block_threshold": 0.85,
                    "rules_enabled": True,
                },
            })
            host_registry.upsert_site({
                "site_id": "site-b-id",
                "tenant_id": "tenant-beta",
                "domain": "app-b.local.test",
                "origin_url": "http://app-b-backend.internal",
                "config_version": 2,
                "policy": {
                    "mode": "monitor",
                    "block_threshold": 0.85,
                    "rules_enabled": True,
                },
            })

            # Bypass DNS for internal mock hostnames during test
            with patch("src.waf_gateway.app.validate_origin_before_connect") as mock_val:
                mock_val.return_value = ["127.0.0.1"]

                # A. Benign request to Site A -> hits Upstream A
                resp_a = await client.get("/api/items/42", headers={"Host": "app-a.local.test"})
                assert resp_a.status_code == 200, f"Error: {resp_a.headers} {resp_a.text}"
                assert resp_a.json()["app"] == "site-a"
                assert resp_a.headers["X-WAF-Action"] in ("ALLOW", "MONITOR")

                # B. Benign request to Site B -> hits Upstream B
                resp_b = await client.get("/api/items/42", headers={"Host": "app-b.local.test"})
                assert resp_b.status_code == 200
                assert resp_b.json()["app"] == "site-b"
                assert resp_b.headers["X-WAF-Action"] in ("ALLOW", "MONITOR")

                # C. SQL Injection on Site A (mode="blocking") -> Hard 403 BLOCK, NEVER hits Upstream A
                app_a_hits_before = len(app_a_hits)
                resp_sqli_a = await client.get(
                    "/search?q=1%20UNION%20SELECT%201,2,3--",
                    headers={"Host": "app-a.local.test"},
                )
                assert resp_sqli_a.status_code == 403
                assert resp_sqli_a.headers["X-WAF-Action"] == "BLOCK"
                assert len(app_a_hits) == app_a_hits_before

                # D. Exact same SQL Injection on Site B (mode="monitor") -> 200 MONITOR, REACHES Upstream B
                app_b_hits_before = len(app_b_hits)
                resp_sqli_b = await client.get(
                    "/search?q=1%20UNION%20SELECT%201,2,3--",
                    headers={"Host": "app-b.local.test"},
                )
                assert resp_sqli_b.status_code == 200
                assert resp_sqli_b.headers["X-WAF-Action"] == "MONITOR"
                assert len(app_b_hits) == app_b_hits_before + 1
                assert resp_sqli_b.json()["app"] == "site-b"

                # E. Unregistered domain -> 404 UNKNOWN_HOST, hits NEITHER upstream
                resp_unknown = await client.get("/", headers={"Host": "unregistered.example.com"})
                assert resp_unknown.status_code == 404
                assert resp_unknown.headers["X-WAF-Action"] == "REJECT_UNKNOWN_HOST"
                assert resp_unknown.json()["error"] == "UNKNOWN_HOST"

                # F. Evict Site A dynamically without restart
                res_del = await client.delete(
                    "/_waf/sites/app-a.local.test",
                    headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
                )
                assert res_del.status_code == 200
                assert res_del.json()["removed"] is True

                # Subsequent requests to app-a.local.test now return 404 UNKNOWN_HOST
                resp_a_post_del = await client.get("/", headers={"Host": "app-a.local.test"})
                assert resp_a_post_del.status_code == 404
                assert resp_a_post_del.headers["X-WAF-Action"] == "REJECT_UNKNOWN_HOST"

                # Site B is completely unaffected
                resp_b_still_alive = await client.get("/", headers={"Host": "app-b.local.test"})
                assert resp_b_still_alive.status_code == 200
                assert resp_b_still_alive.json()["app"] == "site-b"

        await gw.shutdown()

    asyncio.run(_run())


def test_dynamic_routing_blocks_ssrf_origin_at_runtime(dynamic_routing_gateway):
    gw = dynamic_routing_gateway
    clear_dns_cache()

    # Register site with valid hostname
    host_registry.upsert_site({
        "site_id": "site-ssrf",
        "tenant_id": "tenant-bad",
        "domain": "rebind.attacker.test",
        "origin_url": "http://rebind.attacker.test",
        "config_version": 1,
    })

    async def _run():
        await gw.initialize()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
            with patch("src.waf_gateway.origin_guard.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [
                    (2, 1, 6, "", ("169.254.169.254", 80))
                ]

                # Incoming request must be rejected with 502 ORIGIN_BLOCKED_SSRF
                resp = await client.get("/", headers={"Host": "rebind.attacker.test"})
                assert resp.status_code == 502
                assert resp.headers["X-WAF-Action"] == "BLOCKED_SSRF"
                assert resp.json()["error"] == "ORIGIN_BLOCKED_SSRF"

        await gw.shutdown()

    asyncio.run(_run())
