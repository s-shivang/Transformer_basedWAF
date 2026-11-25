"""
MASTER PLAN PHASE 15 — LIVE SECURITY, PENETRATION & CROSS-TENANT ISOLATION SUITE

Executes live adversarial checks against the running Docker stack:
- Category A: Real-PostgreSQL Multi-Tenant Isolation (IDOR / BOLA)
- Category B: Auth, Cookie, JWT & RBAC Privilege Escalation
- Category C: Control-Plane SSRF, Input Validation & API Abuse
- Category D: Live Data Plane & Nginx Reverse Proxy Hardening
- Category E: Live Container Outage & Fail-Safe Resilience
"""

import sys
import time
import json
import subprocess
import httpx

API_BASE = "http://127.0.0.1:3000/api/v1"
WEB_BASE = "http://127.0.0.1:5173"
NGINX_BASE = "http://127.0.0.1:8080"

test_results = []


def record(cat: str, name: str, passed: bool, detail: str = ""):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] [{cat}] {name}" + (f" -> {detail}" if detail else ""), flush=True)
    test_results.append({
        "category": cat,
        "name": name,
        "passed": passed,
        "detail": detail,
    })


def run_security_audit():
    print("=" * 80)
    print("Starting Master Plan Phase 15 Live Security & Penetration Suite")
    print("=" * 80)

    # =========================================================================
    # CATEGORY A: Real-PostgreSQL Cross-Tenant Isolation (IDOR / BOLA)
    # =========================================================================
    print("\n--- CATEGORY A: Real-PostgreSQL Cross-Tenant Isolation ---")
    ts = int(time.time())
    
    # Register Tenant A
    with httpx.Client(timeout=10.0) as clientA:
        resA = clientA.post(f"{API_BASE}/auth/register", json={
            "email": f"owner-a-{ts}@acme-a.com",
            "password": "Password123!",
            "tenantName": f"Tenant Alpha {ts}",
            "tenantSlug": f"alpha-{ts}",
        })
        assert resA.status_code == 201, f"Failed to register Tenant A: {resA.text}"
        dataA = resA.json()
        tokenA = dataA["accessToken"]
        tenantAId = dataA["activeTenantId"]

    # Register Tenant B (separate client so cookies don't overlap)
    with httpx.Client(timeout=10.0) as clientB:
        resB = clientB.post(f"{API_BASE}/auth/register", json={
            "email": f"owner-b-{ts}@acme-b.com",
            "password": "Password123!",
            "tenantName": f"Tenant Beta {ts}",
            "tenantSlug": f"beta-{ts}",
        })
        assert resB.status_code == 201, f"Failed to register Tenant B: {resB.text}"
        dataB = resB.json()
        tokenB = dataB["accessToken"]
        tenantBId = dataB["activeTenantId"]

    with httpx.Client(timeout=10.0) as client:

        # Provision Tenant A Resources
        siteResA = client.post(f"{API_BASE}/sites", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "name": "Alpha Production Site",
            "domain": f"alpha-{ts}.local",
            "originUrl": "http://protected-app:8002",
        })
        assert siteResA.status_code == 201, f"Failed to create site for Tenant A: {siteResA.text}"
        siteAId = siteResA.json()["id"]

        # Policy update for Site A
        client.put(f"{API_BASE}/sites/{siteAId}/policy", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "mode": "BLOCKING",
            "blockThreshold": 0.88,
        })

        # Ingest a security event for Tenant A
        evRes = client.post(f"{API_BASE}/internal/events", headers={"X-WAF-Ingest-Key": "waf-internal-ingest-secret-dev"}, json={
            "tenantId": tenantAId,
            "siteId": siteAId,
            "requestId": f"req-pen-{ts}-1",
            "method": "POST",
            "path": "/api/v1/checkout",
            "action": "BLOCK",
            "riskScore": 0.95,
        })
        assert evRes.status_code == 201, f"Failed to ingest event: {evRes.text}"
        eventAId = evRes.json()["ids"][0]

        # Submit feedback on eventAId
        fbRes = client.post(f"{API_BASE}/events/{eventAId}/feedback", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "label": "FALSE_POSITIVE",
            "notes": "Testing isolation queue",
        })
        assert fbRes.status_code == 201, f"Failed to submit feedback: {fbRes.text}"
        feedbackAId = fbRes.json()["id"]

        # Create Webhook for Tenant A
        whRes = client.post(f"{API_BASE}/webhooks", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "name": "Alpha Webhook",
            "url": "https://alpha.example.com/alerts",
        })
        assert whRes.status_code == 201, f"Failed to create webhook: {whRes.text}"
        webhookAId = whRes.json()["id"]

        # 1. Tenant B querying Tenant A tenant info
        r = client.get(f"{API_BASE}/tenants/{tenantAId}", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot query Tenant A by ID (403)", r.status_code == 403, f"status={r.status_code}")

        r = client.get(f"{API_BASE}/tenants/slug/alpha-{ts}", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot query Tenant A by slug (403)", r.status_code == 403, f"status={r.status_code}")

        # 2. Tenant B attacking Tenant A Protected Site
        r = client.get(f"{API_BASE}/sites/{siteAId}", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot read Tenant A site (404)", r.status_code == 404, f"status={r.status_code}")

        r = client.patch(f"{API_BASE}/sites/{siteAId}", headers={"Authorization": f"Bearer {tokenB}"}, json={"name": "Hacked"})
        record("Cat A", "Tenant B cannot patch Tenant A site (404)", r.status_code == 404, f"status={r.status_code}")

        r = client.delete(f"{API_BASE}/sites/{siteAId}", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot delete Tenant A site (404)", r.status_code == 404, f"status={r.status_code}")

        # 3. Tenant B attacking Tenant A Policies
        r = client.get(f"{API_BASE}/sites/{siteAId}/policy", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot read Tenant A policy (404)", r.status_code == 404, f"status={r.status_code}")

        r = client.put(f"{API_BASE}/sites/{siteAId}/policy", headers={"Authorization": f"Bearer {tokenB}"}, json={"mode": "DISABLED"})
        record("Cat A", "Tenant B cannot mutate Tenant A policy (404)", r.status_code == 404, f"status={r.status_code}")

        r = client.post(f"{API_BASE}/sites/{siteAId}/policy/rollback/1", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot rollback Tenant A policy (404)", r.status_code == 404, f"status={r.status_code}")

        # 4. Tenant B attacking Tenant A Events & Feedback
        r = client.get(f"{API_BASE}/events/{eventAId}", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot read Tenant A security event (404)", r.status_code == 404, f"status={r.status_code}")

        r = client.post(f"{API_BASE}/events/{eventAId}/feedback", headers={"Authorization": f"Bearer {tokenB}"}, json={"label": "CONFIRMED_ATTACK"})
        record("Cat A", "Tenant B cannot submit feedback on Tenant A event (404)", r.status_code == 404, f"status={r.status_code}")

        r = client.patch(f"{API_BASE}/feedback/{feedbackAId}/review", headers={"Authorization": f"Bearer {tokenB}"}, json={"status": "APPROVED"})
        record("Cat A", "Tenant B cannot review Tenant A feedback item (404)", r.status_code == 404, f"status={r.status_code}")

        # 5. Tenant B Events & Analytics query isolation
        r = client.get(f"{API_BASE}/events", headers={"Authorization": f"Bearer {tokenB}"})
        eventsB = r.json().get("items", [])
        hasAlphaEvent = any(e.get("requestId") == f"req-pen-{ts}-1" for e in eventsB)
        record("Cat A", "Tenant B event queries return zero Tenant A records", not hasAlphaEvent and r.status_code == 200)

        # 6. Tenant B attacking Tenant A Webhook
        r = client.delete(f"{API_BASE}/webhooks/{webhookAId}", headers={"Authorization": f"Bearer {tokenB}"})
        record("Cat A", "Tenant B cannot delete Tenant A webhook endpoint (404)", r.status_code == 404, f"status={r.status_code}")

        # 7. Tenant B adding members to Tenant A
        r = client.post(f"{API_BASE}/tenants/{tenantAId}/members", headers={"Authorization": f"Bearer {tokenB}"}, json={
            "email": "hacker@evil.com", "role": "OWNER"
        })
        record("Cat A", "Tenant B cannot add members to Tenant A (403)", r.status_code == 403, f"status={r.status_code}")

    # =========================================================================
    # CATEGORY B: Auth, Cookie, JWT & RBAC Privilege Escalation
    # =========================================================================
    print("\n--- CATEGORY B: Auth, Cookie, JWT & RBAC Privilege Escalation ---")
    with httpx.Client(timeout=10.0) as client:
        # 1. Cookie Security Attributes
        loginRes = client.post(f"{API_BASE}/auth/login", json={
            "email": f"owner-a-{ts}@acme-a.com",
            "password": "Password123!",
        })
        assert loginRes.status_code == 200
        setCookieHeaders = loginRes.headers.get_list("set-cookie") if hasattr(loginRes.headers, "get_list") else [loginRes.headers.get("set-cookie", "")]
        cookieStr = " ".join(setCookieHeaders).lower()
        hasHttpOnly = "httponly" in cookieStr
        hasSameSite = "samesite=lax" in cookieStr or "samesite=strict" in cookieStr
        record("Cat B", "Auth cookies enforce HttpOnly and SameSite", hasHttpOnly and hasSameSite, f"headers={setCookieHeaders}")

        # 2. Tampered JWT with alg: none or forged role
        # Request with forged Authorization header and empty cookie jar so cookie doesn't supersede
        forgedJwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTYiLCJ0ZW5hbnRJZCI6IjEyMzQiLCJyb2xlIjoiT1dORVIifQ."
        with httpx.Client(timeout=10.0) as unauthClient:
            r = unauthClient.get(f"{API_BASE}/sites", headers={"Authorization": f"Bearer {forgedJwt}"})
            record("Cat B", "Tampered alg:none JWT is rejected (401)", r.status_code == 401, f"status={r.status_code}")

        # 3. Refresh Token Rotation & Reuse Detection
        refreshCookies = loginRes.cookies
        rotateRes1 = client.post(f"{API_BASE}/auth/refresh", cookies=refreshCookies)
        record("Cat B", "Valid refresh token rotation succeeds (200)", rotateRes1.status_code == 200, f"status={rotateRes1.status_code}")

        # Replay the OLD refresh token -> must fail 401
        replayRes = client.post(f"{API_BASE}/auth/refresh", cookies=refreshCookies)
        record("Cat B", "Replaying used refresh token is detected and rejected (401)", replayRes.status_code == 401, f"status={replayRes.status_code}")

        # 4. RBAC Privilege Escalation: Add VIEWER & ANALYST to Tenant A
        # Register a viewer user first so they have known credentials
        with httpx.Client(timeout=10.0) as vRegClient:
            vRegRes = vRegClient.post(f"{API_BASE}/auth/register", json={
                "email": f"viewer-{ts}@acme-a.com",
                "password": "Password123!",
                "tenantName": f"Temp Tenant {ts}",
                "tenantSlug": f"temp-{ts}",
            })
            assert vRegRes.status_code == 201

        # Now add them to Tenant A as a VIEWER
        addViewerRes = client.post(f"{API_BASE}/tenants/{tenantAId}/members", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "email": f"viewer-{ts}@acme-a.com", "role": "VIEWER"
        })
        assert addViewerRes.status_code == 201
        viewerMemberId = addViewerRes.json()["userId"]

        # Mint a viewer JWT token scoped specifically to Tenant A
        # (Since /auth/login returns activeTenantId for the user's primary/registered tenant)
        # We can authenticate as viewer with Tenant A's tenantId via signed JWT
        # Or test using their scoped JWT:
        import jwt as pyjwt
        viewerTokenA = pyjwt.encode(
            {"sub": viewerMemberId, "tenantId": tenantAId, "role": "VIEWER", "email": f"viewer-{ts}@acme-a.com"},
            "dev_jwt_access_secret_super_secure_32chars!",
            algorithm="HS256"
        )

        with httpx.Client(timeout=10.0) as viewerClient:
            # Viewer attempts privileged mutations
            r1 = viewerClient.post(f"{API_BASE}/sites", headers={"Authorization": f"Bearer {viewerTokenA}"}, json={
                "name": "Illegal", "domain": "illegal.com", "originUrl": "http://backend"
            })
            record("Cat B", "VIEWER cannot create protected site (403)", r1.status_code == 403, f"status={r1.status_code}")

            r2 = viewerClient.put(f"{API_BASE}/sites/{siteAId}/policy", headers={"Authorization": f"Bearer {viewerTokenA}"}, json={"mode": "DISABLED"})
            record("Cat B", "VIEWER cannot mutate policy (403)", r2.status_code == 403, f"status={r2.status_code}")

            r3 = viewerClient.post(f"{API_BASE}/webhooks", headers={"Authorization": f"Bearer {viewerTokenA}"}, json={
                "name": "Bad", "url": "https://bad.com"
            })
            record("Cat B", "VIEWER cannot create webhook (403)", r3.status_code == 403, f"status={r3.status_code}")

        # 5. Sensitive Data Redaction
        meRes = client.get(f"{API_BASE}/auth/me", headers={"Authorization": f"Bearer {tokenA}"})
        meStr = json.dumps(meRes.json()).lower()
        record("Cat B", "User payload never leaks passwordHash", "passwordhash" not in meStr and "password" not in meStr)

    # =========================================================================
    # CATEGORY C: Control-Plane SSRF, Input Validation & API Abuse
    # =========================================================================
    print("\n--- CATEGORY C: Control-Plane SSRF, Input Validation & API Abuse ---")
    with httpx.Client(timeout=10.0) as client:
        # 1. Site creation SSRF cloud metadata
        r = client.post(f"{API_BASE}/sites", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "name": "Evil Meta Site",
            "domain": f"evil-meta-{ts}.com",
            "originUrl": "http://169.254.169.254/latest/meta-data/",
        })
        record("Cat C", "Protected site rejects cloud metadata originUrl (400)", r.status_code == 400, f"status={r.status_code}")

        # 2. Webhook creation SSRF
        r1 = client.post(f"{API_BASE}/webhooks", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "name": "Evil Webhook Meta", "url": "http://169.254.169.254/"
        })
        record("Cat C", "Webhook rejects 169.254.169.254 SSRF target (400)", r1.status_code == 400, f"status={r1.status_code}")

        r2 = client.post(f"{API_BASE}/webhooks", headers={"Authorization": f"Bearer {tokenA}"}, json={
            "name": "Evil Webhook Loopback", "url": "http://0.0.0.0:3000/internal"
        })
        record("Cat C", "Webhook rejects 0.0.0.0 internal SSRF target (400)", r2.status_code == 400, f"status={r2.status_code}")

        # 3. Missing or wrong internal ingest key
        r = client.post(f"{API_BASE}/internal/events", json={"tenantId": tenantAId, "requestId": "r1", "method": "GET", "path": "/", "action": "ALLOW"})
        record("Cat C", "Internal event ingestion rejects missing ingest key (401)", r.status_code == 401, f"status={r.status_code}")

        r = client.post(f"{API_BASE}/internal/events", headers={"X-WAF-Ingest-Key": "wrong-key"}, json={
            "tenantId": tenantAId, "requestId": "r1", "method": "GET", "path": "/", "action": "ALLOW"
        })
        record("Cat C", "Internal event ingestion rejects wrong ingest key (401)", r.status_code == 401, f"status={r.status_code}")

        # 4. Malformed UUID SQLi injection in path parameters
        r = client.get(f"{API_BASE}/sites/'%20OR%201=1--", headers={"Authorization": f"Bearer {tokenA}"})
        record("Cat C", "Malformed UUID in route param returns clean 400/404 (not 500)", r.status_code in (400, 404), f"status={r.status_code}")

    # =========================================================================
    # CATEGORY D: Live Data Plane & Nginx Reverse Proxy Hardening
    # =========================================================================
    print("\n--- CATEGORY D: Live Data Plane & Nginx Reverse Proxy Hardening ---")
    with httpx.Client(timeout=10.0) as client:
        # 1. Nginx external lock-down on /_waf/ routes
        r1 = client.get(f"{NGINX_BASE}/_waf/policy")
        record("Cat D", "External access to /_waf/policy is blocked by Nginx (403)", r1.status_code == 403, f"status={r1.status_code}")

        r2 = client.get(f"{NGINX_BASE}/_waf/health")
        record("Cat D", "External access to /_waf/health is blocked by Nginx (403)", r2.status_code == 403, f"status={r2.status_code}")

        # Path-normalized bypass attempt
        r3 = client.get(f"{NGINX_BASE}/_waf//policy")
        record("Cat D", "Path traversal bypass /_waf//policy is blocked (403/404)", r3.status_code in (403, 404), f"status={r3.status_code}")

        # 2. Challenge endpoint reachability & validation
        r = client.post(f"{NGINX_BASE}/_waf/challenge/verify", json={
            "token": "invalid", "answer": "wrong", "pow_nonce": "0", "duration_ms": 100
        })
        record("Cat D", "Challenge endpoint /_waf/challenge/verify is reachable and rejects bad solution (403)", r.status_code == 403, f"status={r.status_code}")

        # 3. Live Attack Evasion Suite through Nginx (port 8080)
        attacks = [
            ("SQLi Tautology", "/search?q=%27%20OR%201=1--"),
            ("SQLi UNION SELECT", "/search?q=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"),
            ("XSS Injection", "/search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E"),
            ("Path Traversal", "/files?name=../../../../etc/passwd"),
            ("Double-Encoded Traversal", "/files?name=..%252f..%252fetc%252fpasswd"),
            ("Command Injection", "/search?q=%3Bcat%20/etc/passwd"),
        ]

        for name, path in attacks:
            r = client.get(f"{NGINX_BASE}{path}")
            is_blocked = (r.status_code == 403 and r.headers.get("X-WAF-Action") == "BLOCK")
            record("Cat D", f"Attack blocked: {name} (403 BLOCK)", is_blocked, f"status={r.status_code}, action={r.headers.get('X-WAF-Action')}")

        # 4. Clearance Cookie Bypass Resistance
        forgedCookie = {"waf_clearance": "forged_hmac_clearance_token"}
        r = client.get(f"{NGINX_BASE}/search?q=%27%20OR%201=1--", cookies=forgedCookie)
        is_blocked = (r.status_code == 403 and r.headers.get("X-WAF-Action") == "BLOCK")
        record("Cat D", "Forged clearance cookie NEVER bypasses hard SQLi block (403 BLOCK)", is_blocked, f"status={r.status_code}")

    # =========================================================================
    # CATEGORY E: Live Container Outage & Fail-Safe Resilience
    # =========================================================================
    print("\n--- CATEGORY E: Live Container Outage & Fail-Safe Resilience ---")
    try:
        # Temporarily stop ml-service container
        print("Stopping waf-ml-service container to test resilience...")
        subprocess.run(["docker", "compose", "stop", "ml-service"], check=True)
        time.sleep(2)

        with httpx.Client(timeout=10.0) as client:
            # 1. Gateway does not crash (not 502)
            # 2. Layer 1 deterministic rules STILL block path traversal attacks!
            r_atk = client.get(f"{NGINX_BASE}/files?name=../../etc/passwd")
            l1_blocks = (r_atk.status_code == 403 and r_atk.headers.get("X-WAF-Action") == "BLOCK")
            record("Cat E", "Layer 1 rules STILL block attacks while ML service is DOWN (403 BLOCK)", l1_blocks, f"status={r_atk.status_code}")

            # 3. Clean benign traffic fails open cleanly with X-WAF-Degraded: true
            r_clean = client.get(f"{NGINX_BASE}/")
            fails_open = (r_clean.status_code == 200 and r_clean.headers.get("X-WAF-Degraded") == "true")
            record("Cat E", "Benign traffic safely fails open (200 OK + X-WAF-Degraded: true)", fails_open, f"status={r_clean.status_code}, degraded={r_clean.headers.get('X-WAF-Degraded')}")
    finally:
        # Restore ml-service container
        print("Restoring waf-ml-service container...")
        subprocess.run(["docker", "compose", "start", "ml-service"], check=True)
        time.sleep(4)

        # Verify normal ML scoring recovers
        with httpx.Client(timeout=10.0) as client:
            r_recov = client.get(f"{NGINX_BASE}/")
            recovered = (r_recov.status_code == 200 and r_recov.headers.get("X-WAF-Degraded") in (None, "false"))
            record("Cat E", "ML Service recovered and scoring normally (X-WAF-Degraded: false/none)", recovered, f"status={r_recov.status_code}, degraded={r_recov.headers.get('X-WAF-Degraded')}")

    # Summary
    print("\n" + "=" * 80)
    passed_cnt = sum(1 for t in test_results if t["passed"])
    failed_cnt = sum(1 for t in test_results if not t["passed"])
    total_cnt = len(test_results)
    print(f"Phase 15 Security Audit Complete: {passed_cnt}/{total_cnt} PASSED ({failed_cnt} FAILED)")
    print("=" * 80)

    if failed_cnt > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_security_audit()
