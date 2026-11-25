# Phase 17B — Atomic Config Distribution & Python Gateway Host Registry Report

**Status:** COMPLETED  
**Date:** 2026-11-25  
**Scope:** `apps/api/` (NestJS Control Plane) + `src/waf_gateway/` (Python Fast-Path Data Plane)  
**Verification Status:** 100% Green across Python PyTest, NestJS Unit, E2E, Architecture Invariants, and Web Vitest.

---

## 1. Executive Summary

Phase 17B establishes the secure, versioned Control-Plane-to-Data-Plane site configuration bridge. Verified sites and their tailored WAF inspection policies are pushed atomically to `waf-gateway` with version acknowledgements (ACKs) and zero gateway restarts.

Key technical milestones achieved:
1. **Thread-Safe `HostRegistry` (`src/waf_gateway/host_registry.py`):**
   - High-performance in-memory routing table mapping normalized lowercase domains to `SiteRouteConfig` and `SitePolicyConfig`.
   - Domain normalization (lowercased, port-stripped, hostname-validated).
   - Strict SSRF origin blocking: link-local IPs (`169.254.169.254`), cloud metadata services (`metadata.google.internal`), and wildcard loopback IPs (`0.0.0.0`) are rejected at schema validation.
   - Threshold ordering validation: `monitor_threshold <= challenge_threshold <= block_threshold`.
   - Stale version downgrades are rejected unless explicitly overridden by `force_rollback=True`.
   - Atomic replacement guarantee: snapshots and updates preserve Last-Known-Good (LKG) configurations on validation error.
2. **FastAPI Management Endpoints (`src/waf_gateway/app.py`):**
   - `POST /_waf/sites/sync`: Atomically registers or updates site routes and policies, returning version acknowledgements.
   - `DELETE /_waf/sites/{domain}`: Evicts domains on site pause or removal.
   - `GET /_waf/sites`: Diagnostic telemetry endpoint listing active routing tables (never exposing secrets).
   - Protected strictly by `X-WAF-Admin-Key` (locked down externally by Nginx reverse proxy).
3. **Control Plane Config Sync Orchestration (`apps/api/`):**
   - Prisma schema extended with `gatewayAckVersion` (`Int?`) and `lastSyncedAt` (`DateTime?`).
   - Domain port `ISiteConfigSyncClient` cleanly decoupled from concrete infrastructure.
   - Production `HttpSiteConfigSyncClient` (with HTTP timeout and error handling) and test `InMemorySiteConfigSyncClient`.
   - `ConfigureSiteOnGatewayUseCase`: Validates site status (`VERIFIED`, `ACTIVE`), queries active `WafPolicy`, dispatches versioned configuration to gateway, records ACK, transitions `VERIFIED -> DNS_PENDING`, and writes `SITE_CONFIG_SYNCED` audit log.
   - `POST /api/v1/sites/:siteId/onboarding/configure` protected by RBAC (`OWNER`, `ADMIN`).
   - `PauseResumeSiteUseCase` and `DeleteProtectedSiteUseCase` integrated to evict routes from data plane on pause/delete and re-sync on resume.

---

## 2. Test Verification Matrix

| Component | Test Suite | Results | Notes |
| :--- | :--- | :--- | :--- |
| **Data Plane** | `tests/test_host_registry_and_sync.py` | **11/11 PASSED** | Unit & API tests for registry, auth, LKG, and downgrades |
| **Data Plane Suite** | `tests/` (PyTest) | **96 PASSED** | Full Python WAF Core, ML, LoRA, and Data Plane suites green |
| **Control Plane Unit** | `apps/api/` (`npm test`) | **87/87 PASSED** | All domain entity and use-case unit tests green |
| **Onboarding E2E** | `test/site-onboarding.e2e-spec.ts` | **18/18 PASSED** | Section 6 tests gateway configure, ACKs, 404 cross-tenant isolation, error handling |
| **Architecture Invariants** | `test/architecture.e2e-spec.ts` | **2/2 PASSED** | Zero ORM/framework imports in `domain/`; clean boundary enforcement |
| **Web Frontend** | `apps/web/` (`vitest`) | **22/22 PASSED** | All 5 test files green |
| **Build Integrity** | `nest build` & `vite build` | **PASSED** | Zero compile or packaging errors |

---

## 3. Strict Boundary Compliance

- **No Upstream Proxy Disruption:** Existing single-upstream proxy behavior in `src/waf_gateway/app.py` remains 100% backward-compatible (multi-host dynamic proxying is isolated to Phase 17C).
- **DDD Domain Invariance:** `apps/api/src/modules/protected-sites/domain/` contains zero framework, ORM, or HTTP imports.
- **SSRF Safety:** Link-local and metadata IPs cannot be injected into the data plane routing registry.
- **Audit Traceability:** Every configuration synchronization is persisted with user ID, IP, domain, and version in `AuditLog`.
