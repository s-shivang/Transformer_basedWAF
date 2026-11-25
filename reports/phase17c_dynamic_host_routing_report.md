# Phase 17C — Dynamic Host-Based Routing, Per-Site Policy Execution & DNS-Rebinding Guard Report

**Status:** COMPLETED  
**Date:** 2026-11-25  
**Scope:** `src/waf_gateway/` (Python Fast-Path Data Plane) + `src/firewall/` (Decision Engine) + `nginx/` (Reverse Proxy)  
**Verification Status:** 100% Green across Python PyTest, NestJS Unit & E2E (7 suites, 101 tests), Architecture Invariants, and Web Vitest (22 tests).

---

## 1. Executive Summary

Phase 17C achieves true zero-restart, multi-tenant dynamic reverse-proxy routing in the WAF Gateway data plane. Incoming HTTP requests are matched by their `Host` / `X-Forwarded-Host` headers against the thread-safe `HostRegistry`. Legitimate requests are inspected using that site's specific WAF inspection policy and forwarded to that site's verified `origin_url`, while unknown hosts are rejected instantly and SSRF/DNS-rebinding attacks are blocked at connection time.

### Key Milestones Delivered:
1. **Runtime DNS-Rebinding & Origin SSRF Guard (`src/waf_gateway/origin_guard.py`):**
   - Resolves origin hostnames via `socket.getaddrinfo` with a 20-second TTL cache to prevent connection latency while mitigating time-of-check to time-of-use (TOCTOU) DNS rebinding attacks.
   - **Always Blocks:** `169.254.0.0/16` (AWS/GCP/Azure link-local metadata), `fe80::/10`, `0.0.0.0/8`, `100.100.100.200` (Tailscale/Alibaba metadata), multicast ranges, and `metadata.google.internal`—even if private origins are permitted.
   - **Configurable Private Range Enforcement:** When `WAF_ALLOW_PRIVATE_ORIGINS=false` (production default), loopback (`127.0.0.0/8`, `::1`) and RFC 1918 / ULA private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) are blocked. When `WAF_ALLOW_PRIVATE_ORIGINS=true`, local development and Docker Compose origins are permitted while maintaining strict cloud metadata blocks.
   - Raises `OriginSSRFBlockedError` before establishing outbound TCP connections.
2. **Dynamic Host Routing & Per-Site Policy Isolation (`src/waf_gateway/app.py`):**
   - Controlled by `WAF_DYNAMIC_ROUTING_ENABLED` (default `"false"` for backward compatibility with single-upstream configurations, `"true"` for multi-tenant deployments).
   - **Unknown Host Rejection:** If `HostRegistry.lookup(clean_host)` returns no enabled route, the gateway immediately responds with `404 Not Found`, header `X-WAF-Action: REJECT_UNKNOWN_HOST`, and payload `{"error": "UNKNOWN_HOST"}`. Unknown hosts never touch default upstream.
   - **Per-Site Policy Execution:** Converts active `SiteRouteConfig.policy` into a runtime `FirewallPolicy`, overriding thresholds (`block`, `challenge`, `monitor`), rules/ML flags, and scoped exclusions per request. Site A running in `blocking` mode hard-blocks SQLi attacks (403 BLOCK), while Site B running in `monitor` mode simultaneously allows and logs the identical attack (200 MONITOR) on the exact same gateway process.
   - **SSRF Origin Trap:** If `validate_origin_before_connect` fails, returns `502 Bad Gateway` with `X-WAF-Action: BLOCKED_SSRF` and `{"error": "ORIGIN_BLOCKED_SSRF"}` without leaking internal addresses.
   - **Dynamic Connection Pools:** Manages dedicated `httpx.AsyncClient` instances per distinct origin URL, supporting both live networks and in-process mock ASGI applications.
   - **Accurate Telemetry Tagging:** Asynchronous Control Plane event logging tags events with the matched site's exact `tenant_id` and `site_id`.
3. **Nginx Host Header & Health Preservation (`nginx/waf_reverse_proxy.conf` & `nginx/waf_reverse_proxy.docker.conf`):**
   - Configured `proxy_set_header Host $http_host;` and `proxy_set_header X-Forwarded-Host $http_host;` to guarantee client domain integrity through the outer reverse proxy.
   - Maintained `/nginx-health` liveness checks and external `/_waf/*` block rules (preserving public access to `/_waf/challenge/`).

---

## 2. Test Verification Matrix

| Component | Test Suite | Results | Notes |
| :--- | :--- | :--- | :--- |
| **Dynamic Host Routing** | `tests/test_dynamic_host_routing.py` | **6/6 PASSED** | Multi-app routing, per-site policy isolation, SSRF/DNS rebinding, domain eviction |
| **Host Registry & Sync** | `tests/test_host_registry_and_sync.py` | **11/11 PASSED** | Atomic updates, LKG preservation, stale downgrade prevention, admin auth |
| **Python Regression Suite** | `tests/` (PyTest) | **102 PASSED** | All data plane, ML, LoRA, and WAF core suites green |
| **Control Plane Unit** | `apps/api/` (`npm test`) | **87/87 PASSED (9/9 suites)** | Domain entity, quota, and use-case unit tests green |
| **Control Plane E2E** | `apps/api/` (`npm run test:e2e`) | **101/101 PASSED (7/7 suites)** | Onboarding, RBAC, policies, events, tenants, and architecture invariants |
| **Architecture Boundaries** | `test/architecture.e2e-spec.ts` | **2/2 PASSED** | Zero ORM/framework imports in `domain/`; strict clean boundary enforcement |
| **Web Frontend** | `apps/web/` (`vitest`) | **22/22 PASSED (5/5 suites)** | Threat Center, RBAC, theme, and threshold tests green |
| **Production Builds** | `nest build` & `vite build` | **PASSED (0 errors)** | Full production build verification clean |

---

## 3. Strict Boundary Compliance

- **Zero API/Web Modifications:** Strictly zero changes to `apps/api/`, `apps/web/`, or `models/frozen/v1_0/`.
- **Backward Compatibility:** All existing single-upstream tests continue running unmodified because `WAF_DYNAMIC_ROUTING_ENABLED` defaults to `false`.
- **Zero Secrets Leaked:** Origin SSRF and DNS rebinding blocks return generic error payloads without exposing internal topology.
