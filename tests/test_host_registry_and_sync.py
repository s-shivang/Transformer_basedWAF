"""
Unit & API Tests for WAF Gateway Atomic HostRegistry and Config Sync.

Verifies:
1. Pydantic validation: domain normalization, SSRF origin blocking, threshold ordering.
2. In-memory atomic operations: upsert, stale downgrade rejection, rollback override, snapshot atomicity.
3. FastAPI endpoints: POST /_waf/sites/sync, DELETE /_waf/sites/{domain}, GET /_waf/sites.
4. Security: X-WAF-Admin-Key header enforcement (401/403).
5. Last-Known-Good preservation on invalid updates.
"""
import pytest
import httpx
from src.waf_gateway.host_registry import (
    HostRegistry,
    SiteRouteConfig,
    SitePolicyConfig,
    host_registry,
)
from src.waf_gateway.app import app, DEFAULT_ADMIN_KEY


@pytest.fixture(autouse=True)
def clean_registry():
    host_registry.clear()
    yield
    host_registry.clear()


@pytest.fixture
def async_client():
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


# ============================================================================
# 1. HostRegistry Unit Tests
# ============================================================================

def test_site_route_config_normalization():
    cfg = SiteRouteConfig(
        site_id="site-1",
        tenant_id="tenant-1",
        domain="  APP.Example.COM  ",
        origin_url="https://upstream.internal:8443/",
        config_version=1,
    )
    assert cfg.domain == "app.example.com"
    assert cfg.origin_url == "https://upstream.internal:8443"


def test_site_route_config_rejects_ssrf():
    with pytest.raises(ValueError, match="Forbidden SSRF origin"):
        SiteRouteConfig(
            site_id="site-1",
            tenant_id="tenant-1",
            domain="app.example.com",
            origin_url="http://169.254.169.254/latest/meta-data/",
            config_version=1,
        )

    with pytest.raises(ValueError, match="Forbidden SSRF origin"):
        SiteRouteConfig(
            site_id="site-1",
            tenant_id="tenant-1",
            domain="app.example.com",
            origin_url="http://metadata.google.internal/",
            config_version=1,
        )


def test_site_route_config_rejects_malformed_domain():
    with pytest.raises(ValueError, match="URL scheme"):
        SiteRouteConfig(
            site_id="site-1",
            tenant_id="tenant-1",
            domain="https://app.example.com",
            origin_url="https://upstream.internal",
            config_version=1,
        )

    with pytest.raises(ValueError, match="Wildcard"):
        SiteRouteConfig(
            site_id="site-1",
            tenant_id="tenant-1",
            domain="*.example.com",
            origin_url="https://upstream.internal",
            config_version=1,
        )


def test_site_policy_threshold_ordering():
    # Valid ordering: monitor <= challenge <= block
    policy = SitePolicyConfig(
        monitor_threshold=0.10,
        challenge_threshold=0.50,
        block_threshold=0.85,
    )
    assert policy.monitor_threshold == 0.10

    # Invalid ordering: challenge > block
    with pytest.raises(ValueError, match="Thresholds must satisfy"):
        SitePolicyConfig(
            monitor_threshold=0.10,
            challenge_threshold=0.90,
            block_threshold=0.80,
        )


def test_host_registry_lookup_normalization():
    reg = HostRegistry()
    reg.upsert_site({
        "site_id": "site-shop",
        "tenant_id": "tenant-corp",
        "domain": "shop.acme.com",
        "origin_url": "https://storefront.internal:443",
        "config_version": 2,
    })

    # Exact match
    assert reg.lookup("shop.acme.com") is not None
    # Port stripped + case normalized
    match = reg.lookup("Shop.ACME.com:8443")
    assert match is not None
    assert match.site_id == "site-shop"
    assert match.origin_url == "https://storefront.internal:443"

    # Unknown host
    assert reg.lookup("unknown.acme.com") is None


def test_host_registry_stale_downgrade_and_rollback():
    reg = HostRegistry()
    reg.upsert_site({
        "site_id": "site-1",
        "tenant_id": "tenant-1",
        "domain": "api.example.com",
        "origin_url": "https://v2.internal",
        "config_version": 5,
    })

    # Stale version downgrade without force_rollback rejected
    with pytest.raises(ValueError, match="Stale config version"):
        reg.upsert_site({
            "site_id": "site-1",
            "tenant_id": "tenant-1",
            "domain": "api.example.com",
            "origin_url": "https://v1.internal",
            "config_version": 3,
        })

    # Existing config remains intact (last-known-good)
    assert reg.lookup("api.example.com").origin_url == "https://v2.internal"
    assert reg.lookup("api.example.com").config_version == 5

    # Force rollback succeeds
    reg.upsert_site({
        "site_id": "site-1",
        "tenant_id": "tenant-1",
        "domain": "api.example.com",
        "origin_url": "https://v1.internal",
        "config_version": 3,
    }, force_rollback=True)

    assert reg.lookup("api.example.com").origin_url == "https://v1.internal"
    assert reg.lookup("api.example.com").config_version == 3


def test_host_registry_snapshot_atomicity():
    reg = HostRegistry()
    reg.upsert_site({
        "site_id": "site-initial",
        "tenant_id": "tenant-1",
        "domain": "initial.example.com",
        "origin_url": "https://initial.internal",
        "config_version": 1,
    })

    # Batch with 1 valid and 1 invalid (SSRF)
    invalid_batch = [
        {
            "site_id": "site-good",
            "tenant_id": "tenant-1",
            "domain": "good.example.com",
            "origin_url": "https://good.internal",
            "config_version": 1,
        },
        {
            "site_id": "site-bad",
            "tenant_id": "tenant-1",
            "domain": "bad.example.com",
            "origin_url": "http://169.254.169.254/",
            "config_version": 1,
        },
    ]

    with pytest.raises(ValueError):
        reg.sync_snapshot(invalid_batch)

    # Initial route preserved; partial batch rejected
    assert reg.lookup("initial.example.com") is not None
    assert reg.lookup("good.example.com") is None


# ============================================================================
# 2. FastAPI Gateway Sync Endpoints Tests (Async)
# ============================================================================

@pytest.mark.anyio
async def test_sync_site_auth_protection(async_client):
    payload = {
        "site_id": "site-test",
        "tenant_id": "tenant-test",
        "domain": "auth-check.example.com",
        "origin_url": "https://upstream.internal",
        "config_version": 1,
    }

    async with async_client as client:
        # Missing X-WAF-Admin-Key -> 401
        res = await client.post("/_waf/sites/sync", json=payload)
        assert res.status_code == 401

        # Wrong key -> 403
        res = await client.post(
            "/_waf/sites/sync",
            json=payload,
            headers={"X-WAF-Admin-Key": "wrong-secret-key"},
        )
        assert res.status_code == 403


@pytest.mark.anyio
async def test_sync_site_success_and_ack(async_client):
    payload = {
        "site_id": "site-prod",
        "tenant_id": "tenant-acme",
        "domain": "prod.acme.com",
        "origin_url": "https://prod-backend.internal:8443",
        "config_version": 4,
        "policy": {
            "mode": "blocking",
            "block_threshold": 0.80,
            "challenge_threshold": 0.45,
            "monitor_threshold": 0.15,
            "ml_enabled": True,
        },
    }

    async with async_client as client:
        res = await client.post(
            "/_waf/sites/sync",
            json=payload,
            headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["acknowledged"] is True
        assert data["domain"] == "prod.acme.com"
        assert data["config_version"] == 4
        assert data["active_sites_count"] == 1

    # Verify lookup via HostRegistry
    route = host_registry.lookup("prod.acme.com")
    assert route is not None
    assert route.origin_url == "https://prod-backend.internal:8443"
    assert route.policy.mode == "blocking"


@pytest.mark.anyio
async def test_sync_site_invalid_payload_preserves_lkg(async_client):
    async with async_client as client:
        # First establish valid config
        valid_payload = {
            "site_id": "site-lkg",
            "tenant_id": "tenant-1",
            "domain": "lkg.example.com",
            "origin_url": "https://healthy-origin.internal",
            "config_version": 2,
        }
        res = await client.post(
            "/_waf/sites/sync",
            json=valid_payload,
            headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
        )
        assert res.status_code == 200

        # Attempt to sync invalid update with SSRF origin
        invalid_payload = {
            "site_id": "site-lkg",
            "tenant_id": "tenant-1",
            "domain": "lkg.example.com",
            "origin_url": "http://169.254.169.254/secret",
            "config_version": 3,
        }
        res_bad = await client.post(
            "/_waf/sites/sync",
            json=invalid_payload,
            headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
        )
        assert res_bad.status_code in (400, 422)

    # Last-known-good config is preserved intact
    route = host_registry.lookup("lkg.example.com")
    assert route is not None
    assert route.config_version == 2
    assert route.origin_url == "https://healthy-origin.internal"


@pytest.mark.anyio
async def test_delete_and_list_sites(async_client):
    async with async_client as client:
        # Sync two domains
        for domain in ("site1.example.com", "site2.example.com"):
            await client.post(
                "/_waf/sites/sync",
                json={
                    "site_id": f"id-{domain}",
                    "tenant_id": "tenant-1",
                    "domain": domain,
                    "origin_url": "https://upstream.internal",
                    "config_version": 1,
                },
                headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
            )

        # List sites
        res_list = await client.get("/_waf/sites", headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY})
        assert res_list.status_code == 200
        assert res_list.json()["active_sites_count"] == 2

        # Delete site1
        res_del = await client.delete(
            "/_waf/sites/site1.example.com",
            headers={"X-WAF-Admin-Key": DEFAULT_ADMIN_KEY},
        )
        assert res_del.status_code == 200
        assert res_del.json()["removed"] is True
        assert res_del.json()["active_sites_count"] == 1

    # site1 should be gone, site2 remains
    assert host_registry.lookup("site1.example.com") is None
    assert host_registry.lookup("site2.example.com") is not None
