"""
Phase 17D Live Multi-Domain Onboarding & Dynamic Routing Smoke Test.

Validates the full onboarding lifecycle against the running Docker stack:
1. Health checks on Control Plane API (3000) and WAF Gateway (8001).
2. Multi-tenant registration (Owner user + Tenant).
3. Site onboarding initiation (DNS TXT challenge generation -> PENDING_VERIFICATION).
4. DNS ownership verification (PENDING_VERIFICATION -> VERIFIED).
5. Gateway route & policy push (VERIFIED -> CONFIGURING -> DNS_PENDING).
6. DNS traffic routing verification (DNS_PENDING -> TLS_PENDING).
7. TLS certificate provisioning (TLS_PENDING -> HEALTH_CHECK, 90-day validity).
8. Origin pre-activation health probe & site activation (HEALTH_CHECK -> ACTIVE).
9. Live dynamic HTTP routing verification via Gateway (8001):
   - Benign request with matching Host header -> HTTP 200 via dynamic upstream.
   - Attack request (SQLi) with matching Host header -> HTTP 403 Forbidden.
   - Unknown/unregistered Host header -> HTTP 404 (UNKNOWN_HOST rejection).
10. Site pause & resume:
   - Pause site -> route evicted from Gateway -> HTTP 404.
   - Resume site -> route re-synced to Gateway -> HTTP 200 restored.
"""

import sys
import time
import json
import httpx

API_BASE = "http://127.0.0.1:3000/api/v1"
GATEWAY_BASE = "http://127.0.0.1:8001"
PROTECTED_APP_ORIGIN = "http://protected-app:8002"


def log(msg: str):
    print(f"[PHASE-17D-SMOKE] {msg}", flush=True)


def run_smoke_test():
    log("=================================================================")
    log("Starting Phase 17D End-to-End Live Onboarding Smoke Test")
    log("=================================================================")

    # Step 1: Health Probes
    log("Step 1: Checking Control Plane API & WAF Gateway health...")
    with httpx.Client(timeout=10.0) as client:
        res = client.get(f"{API_BASE}/health")
        assert res.status_code == 200, f"API health check failed: {res.status_code} {res.text}"
        data = res.json()
        log(f"  API Health: status={data.get('status')}, db={data.get('dependencies', {}).get('database')}")

        gw_res = client.get(f"{GATEWAY_BASE}/_waf/health")
        assert gw_res.status_code == 200, f"Gateway health check failed: {gw_res.status_code} {gw_res.text}"
        gw_data = gw_res.json()
        log(f"  Gateway Health: status={gw_data.get('status')}, ml_service={gw_data.get('ml_service')}")

    # Step 2: Register Tenant & Owner
    ts = int(time.time())
    tenant_slug = f"phase17d-corp-{ts}"
    owner_email = f"owner-{ts}@phase17d.example.test"
    domain = f"site-{ts}.test"

    log(f"Step 2: Registering Tenant '{tenant_slug}' with owner '{owner_email}'...")
    with httpx.Client(timeout=10.0) as client:
        reg_res = client.post(
            f"{API_BASE}/auth/register",
            json={
                "email": owner_email,
                "password": "Password123!",
                "tenantName": "Phase 17D Test Corp",
                "tenantSlug": tenant_slug,
            },
        )
        assert reg_res.status_code == 201, f"Registration failed: {reg_res.status_code} {reg_res.text}"
        auth_data = reg_res.json()
        token = auth_data["accessToken"]
        tenant_id = auth_data["activeTenantId"]
        log(f"  Registered tenant ID: {tenant_id}")

    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Initiate Site Onboarding (PENDING_VERIFICATION)
    log(f"Step 3: Initiating site onboarding for domain '{domain}' -> '{PROTECTED_APP_ORIGIN}'...")
    with httpx.Client(timeout=10.0) as client:
        ob_res = client.post(
            f"{API_BASE}/sites/onboarding",
            headers=headers,
            json={
                "name": f"Production App ({domain})",
                "domain": domain,
                "originUrl": PROTECTED_APP_ORIGIN,
            },
        )
        assert ob_res.status_code == 201, f"Initiate onboarding failed: {ob_res.status_code} {ob_res.text}"
        ob_data = ob_res.json()
        site_id = ob_data["siteId"]
        verification_token = ob_data["verificationToken"]
        assert ob_data["onboardingStatus"] == "PENDING_VERIFICATION"
        assert verification_token is not None
        log(f"  Site ID: {site_id}, verificationToken: {verification_token}")

    # Step 4: Verify Domain Ownership (PENDING_VERIFICATION -> VERIFIED)
    log("Step 4: Verifying DNS domain ownership challenge...")
    with httpx.Client(timeout=10.0) as client:
        vd_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/verify-domain",
            headers=headers,
        )
        assert vd_res.status_code == 200, f"Verify domain failed: {vd_res.status_code} {vd_res.text}"
        vd_data = vd_res.json()
        assert vd_data["verified"] is True
        log(f"  Domain ownership verified! Status: {vd_data['site']['onboardingStatus']}")

    # Step 5: Configure Policy & Push to Gateway (VERIFIED -> CONFIGURING -> DNS_PENDING)
    log("Step 5: Updating site policy to BLOCKING and syncing route to Gateway...")
    with httpx.Client(timeout=10.0) as client:
        # Update policy to BLOCKING
        pol_res = client.put(
            f"{API_BASE}/sites/{site_id}/policy",
            headers=headers,
            json={"mode": "BLOCKING", "blockThreshold": 0.85},
        )
        assert pol_res.status_code == 200, f"Policy update failed: {pol_res.status_code} {pol_res.text}"

        cfg_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/configure",
            headers=headers,
            json={"forceRollback": False},
        )
        assert cfg_res.status_code == 200, f"Gateway sync failed: {cfg_res.status_code} {cfg_res.text}"
        cfg_data = cfg_res.json()
        assert cfg_data["gatewayAckVersion"] is not None
        assert cfg_data["onboardingStatus"] == "DNS_PENDING"
        log(f"  Gateway route synced and acknowledged! Ack version: {cfg_data['gatewayAckVersion']}, status: {cfg_data['onboardingStatus']}")

    # Step 6: Verify Traffic Routing DNS (DNS_PENDING -> TLS_PENDING)
    log("Step 6: Verifying DNS traffic routing points to WAF edge...")
    with httpx.Client(timeout=10.0) as client:
        tr_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/verify-dns-routing",
            headers=headers,
        )
        assert tr_res.status_code == 200, f"DNS traffic routing check failed: {tr_res.status_code} {tr_res.text}"
        tr_data = tr_res.json()
        assert tr_data["onboardingStatus"] == "TLS_PENDING"
        log(f"  DNS traffic routing verified! Status: {tr_data['onboardingStatus']}")

    # Step 7: Provision TLS Certificate (TLS_PENDING -> HEALTH_CHECK)
    log("Step 7: Provisioning TLS certificate for domain...")
    with httpx.Client(timeout=10.0) as client:
        tls_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/provision-tls",
            headers=headers,
        )
        assert tls_res.status_code == 200, f"TLS provisioning failed: {tls_res.status_code} {tls_res.text}"
        tls_data = tls_res.json()
        assert tls_data["tlsStatus"] == "PROVISIONED"
        assert tls_data["tlsIssuer"] == "local-dev-acme"
        assert tls_data["onboardingStatus"] == "HEALTH_CHECK"
        log(f"  TLS provisioned! Issuer: {tls_data['tlsIssuer']}, expiresAt: {tls_data['tlsExpiresAt']}, status: {tls_data['onboardingStatus']}")

    # Step 8: Pre-activation Origin Health Probe & Activation (HEALTH_CHECK -> ACTIVE)
    log("Step 8: Executing pre-activation health probe and activating site...")
    with httpx.Client(timeout=10.0) as client:
        act_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/activate",
            headers=headers,
        )
        assert act_res.status_code == 200, f"Activation failed: {act_res.status_code} {act_res.text}"
        act_data = act_res.json()
        assert act_data["onboardingStatus"] == "ACTIVE"
        assert act_data["originHealthStatus"] == "HEALTHY"
        assert act_data["activatedAt"] is not None
        log(f"  Site ACTIVE! ActivatedAt: {act_data['activatedAt']}, originHealth: {act_data['originHealthStatus']}")

    # Step 9: Live Dynamic HTTP Routing Verification via Gateway
    log("Step 9: Testing live dynamic host-based routing via WAF Gateway...")
    with httpx.Client(timeout=10.0) as client:
        # A. Benign request with matching Host
        log(f"  A. Probing benign GET / with Host: {domain}...")
        benign_res = client.get(
            f"{GATEWAY_BASE}/",
            headers={"Host": domain},
        )
        assert benign_res.status_code == 200, f"Expected 200 for benign request, got {benign_res.status_code}: {benign_res.text}"
        assert benign_res.headers.get("X-WAF-Action") in ("ALLOW", "MONITOR"), f"Unexpected WAF action: {benign_res.headers.get('X-WAF-Action')}"
        log(f"    Pass: 200 OK, X-WAF-Action={benign_res.headers.get('X-WAF-Action')}")

        # B. SQLi attack with matching Host (Site policy is BLOCKING)
        log(f"  B. Probing SQLi attack GET /search?q=' OR 1=1-- with Host: {domain}...")
        attack_res = client.get(
            f"{GATEWAY_BASE}/search?q=%27%20OR%201=1--",
            headers={"Host": domain},
        )
        assert attack_res.status_code == 403, f"Expected 403 Forbidden for SQLi, got {attack_res.status_code}: {attack_res.text}"
        assert attack_res.headers.get("X-WAF-Action") == "BLOCK", f"Expected BLOCK action, got {attack_res.headers.get('X-WAF-Action')}"
        log(f"    Pass: 403 Forbidden, X-WAF-Action={attack_res.headers.get('X-WAF-Action')}")

        # C. Unknown Host rejection
        unregistered = "unregistered-intruder.example.com"
        log(f"  C. Probing unregistered Host: {unregistered}...")
        unknown_res = client.get(
            f"{GATEWAY_BASE}/",
            headers={"Host": unregistered},
        )
        assert unknown_res.status_code in (404, 421), f"Expected 404/421 for unknown host, got {unknown_res.status_code}: {unknown_res.text}"
        assert unknown_res.headers.get("X-WAF-Action") == "REJECT_UNKNOWN_HOST", f"Expected REJECT_UNKNOWN_HOST, got {unknown_res.headers.get('X-WAF-Action')}"
        log(f"    Pass: {unknown_res.status_code} Unknown Host Rejected cleanly!")

    # Step 10: Pause & Resume Site
    log("Step 10: Testing site pause and resume...")
    with httpx.Client(timeout=10.0) as client:
        # Pause
        pause_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/pause",
            headers=headers,
        )
        assert pause_res.status_code == 200, f"Pause site failed: {pause_res.status_code} {pause_res.text}"
        log(f"  Site paused successfully.")

        # Gateway probe should now reject with 404 (evicted)
        evicted_res = client.get(
            f"{GATEWAY_BASE}/",
            headers={"Host": domain},
        )
        assert evicted_res.status_code in (404, 421), f"Expected 404 for paused host, got {evicted_res.status_code}"
        log(f"    Pass: Paused domain rejected with {evicted_res.status_code} (evicted from gateway).")

        # Resume
        resume_res = client.post(
            f"{API_BASE}/sites/{site_id}/onboarding/resume",
            headers=headers,
        )
        assert resume_res.status_code == 200, f"Resume site failed: {resume_res.status_code} {resume_res.text}"
        log(f"  Site resumed successfully.")

        # Gateway probe should now succeed again (200 OK)
        resumed_res = client.get(
            f"{GATEWAY_BASE}/",
            headers={"Host": domain},
        )
        assert resumed_res.status_code == 200, f"Expected 200 for resumed host, got {resumed_res.status_code}"
        log(f"    Pass: Resumed domain returns 200 OK via dynamic routing.")

    # Step 11: On-demand Origin Health Check
    log("Step 11: Testing on-demand origin health check endpoint...")
    with httpx.Client(timeout=10.0) as client:
        hc_res = client.post(
            f"{API_BASE}/sites/{site_id}/health-check",
            headers=headers,
        )
        assert hc_res.status_code == 200, f"Health check endpoint failed: {hc_res.status_code} {hc_res.text}"
        hc_data = hc_res.json()
        assert hc_data["healthy"] is True
        log(f"  Health check endpoint response: healthy={hc_data['healthy']}, latencyMs={hc_data['latencyMs']}ms")

    log("=================================================================")
    log("SUCCESS: ALL 11 PHASE 17D SMOKE TEST STAGES PASSED!")
    log("Multi-domain atomic onboarding, TLS readiness, and zero-restart dynamic routing verified.")
    log("=================================================================")


if __name__ == "__main__":
    try:
        run_smoke_test()
    except Exception as exc:
        log(f"FAILED with exception: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
