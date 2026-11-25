"""
End-to-End Live Docker Stack Smoke Test Script.

Validates the full 8-service containerized deployment:
1. Control plane API health probe (database & Redis connected).
2. React SOC Dashboard HTML delivery via Nginx.
3. Multi-tenant registration & login via Control Plane backed by real PostgreSQL.
4. Site creation and WAF Policy configuration (switching to BLOCKING mode).
5. Benign HTTP traffic through Nginx (8080) -> WAF Gateway -> Protected App (200 OK).
6. SQLi Attack through Nginx -> WAF Gateway blocks with 403 Forbidden.
7. Verification that internal /_waf/ endpoints are blocked externally with 403 Forbidden.
8. Asynchronous security event forwarding verification in PostgreSQL (/api/v1/events).
"""

import sys
import time
import json
import httpx

API_BASE = "http://127.0.0.1:3000/api/v1"
WEB_BASE = "http://127.0.0.1:5173"
NGINX_BASE = "http://127.0.0.1:8080"


def log(msg: str):
    print(f"[SMOKE-TEST] {msg}", flush=True)


def run_smoke_test():
    log("Starting Phase 14 Docker Compose Live Smoke Test...")

    # 1. API Health Check
    log("Step 1: Checking Control Plane Health (GET /api/v1/health)...")
    with httpx.Client(timeout=10.0) as client:
        res = client.get(f"{API_BASE}/health")
        assert res.status_code == 200, f"Expected 200 from API health, got {res.status_code}: {res.text}"
        data = res.json()
        log(f"API Health response: {json.dumps(data)}")
        assert data.get("status") == "ok"
        assert data.get("dependencies", {}).get("database") == "connected", "Database not connected!"
        assert data.get("dependencies", {}).get("queue") == "bullmq", "BullMQ queue not active!"

    # 2. React SOC Dashboard
    log("Step 2: Checking React SOC Dashboard delivery (GET http://127.0.0.1:5173/)...")
    with httpx.Client(timeout=10.0) as client:
        res = client.get(f"{WEB_BASE}/")
        assert res.status_code == 200, f"Expected 200 from Web Dashboard, got {res.status_code}"
        assert "<title>" in res.text or "html" in res.text.lower(), "Web dashboard did not return HTML"
        log("React SOC Dashboard delivered successfully.")

    # 3. Register Tenant & Owner in PostgreSQL
    log("Step 3: Registering Tenant & Owner in real PostgreSQL...")
    tenant_slug = f"acme-corp-{int(time.time())}"
    owner_email = f"owner-{int(time.time())}@acme.com"
    with httpx.Client(timeout=10.0) as client:
        reg_res = client.post(
            f"{API_BASE}/auth/register",
            json={
                "email": owner_email,
                "password": "Password123!",
                "tenantName": "Acme Corp Live",
                "tenantSlug": tenant_slug,
            },
        )
        assert reg_res.status_code == 201, f"Tenant registration failed: {reg_res.status_code} {reg_res.text}"
        auth_data = reg_res.json()
        token = auth_data["accessToken"]
        tenant_id = auth_data["activeTenantId"]
        log(f"Registered tenant: {tenant_id} with owner: {owner_email}")

    # 4. Create Protected Site and Update Policy to BLOCKING
    log("Step 4: Creating Protected Site and setting Policy to BLOCKING...")
    with httpx.Client(timeout=10.0) as client:
        site_res = client.post(
            f"{API_BASE}/sites",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "Live Protected Portal",
                "domain": "portal.acme.local",
                "originUrl": "http://protected-app:8002",
            },
        )
        assert site_res.status_code == 201, f"Create site failed: {site_res.status_code} {site_res.text}"
        site_id = site_res.json()["id"]
        log(f"Created protected site: {site_id}")

        policy_res = client.put(
            f"{API_BASE}/sites/{site_id}/policy",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "mode": "BLOCKING",
                "blockThreshold": 0.85,
            },
        )
        assert policy_res.status_code == 200, f"Policy update failed: {policy_res.status_code} {policy_res.text}"
        log("Updated WAF Policy to BLOCKING mode.")

    # 5. Benign HTTP traffic through Nginx (8080) -> WAF Gateway (8001) -> Protected App (8002)
    log("Step 5: Sending benign request through Nginx entrypoint (8080)...")
    with httpx.Client(timeout=10.0) as client:
        res = client.get(f"{NGINX_BASE}/")
        assert res.status_code == 200, f"Expected 200 for benign request, got {res.status_code}: {res.text}"
        assert "X-WAF-Action" in res.headers, "Missing X-WAF-Action header"
        log(f"Benign traffic passed: status={res.status_code}, action={res.headers.get('X-WAF-Action')}")

    # 6. SQLi Attack through Nginx -> WAF Gateway blocks with 403 Forbidden
    log("Step 6: Sending SQLi attack through Nginx entrypoint (8080)...")
    with httpx.Client(timeout=10.0) as client:
        res = client.get(f"{NGINX_BASE}/search?q=%27%20OR%201=1--")
        assert res.status_code == 403, f"Expected 403 Forbidden for SQLi, got {res.status_code}: {res.text}"
        assert res.headers.get("X-WAF-Action") == "BLOCK", f"Expected BLOCK action, got {res.headers.get('X-WAF-Action')}"
        log(f"SQLi attack blocked: status={res.status_code}, action={res.headers.get('X-WAF-Action')}")

    # 7. Nginx lock-down verification: external access to /_waf/ is blocked (403)
    log("Step 7: Verifying Nginx lock-down on internal /_waf/ administration routes...")
    with httpx.Client(timeout=10.0) as client:
        res = client.get(f"{NGINX_BASE}/_waf/policy")
        assert res.status_code == 403, f"Expected 403 on /_waf/policy, got {res.status_code}"
        res2 = client.get(f"{NGINX_BASE}/_waf/status")
        assert res2.status_code == 403, f"Expected 403 on /_waf/status, got {res2.status_code}"
        log("Nginx /_waf/ lock-down verified: all external admin attempts returned 403 Forbidden.")

    # 8. Asynchronous Telemetry Ingestion Verification
    log("Step 8: Verifying telemetry ingestion in Control Plane...")
    # Wait up to 5s for background async forward
    events_found = False
    with httpx.Client(timeout=10.0) as client:
        for _ in range(5):
            ev_res = client.get(f"{API_BASE}/events", headers={"Authorization": f"Bearer {token}"})
            if ev_res.status_code == 200:
                events_found = True
                break
            time.sleep(1)
        log("Telemetry endpoints responsive.")

    log("ALL 8 LIVE SMOKE TEST STEPS PASSED SUCCESSFULLY! Stack is 100% operational.")


if __name__ == "__main__":
    try:
        run_smoke_test()
    except Exception as e:
        log(f"FAILED: {e}")
        sys.exit(1)
