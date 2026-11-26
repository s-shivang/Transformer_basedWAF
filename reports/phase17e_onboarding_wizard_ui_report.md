# Phase 17E — React 6-Step Site Onboarding Setup Wizard & Owner Site Quota UI Verification Report

**Date:** 2026-11-26  
**Environment:** Local Windows Laptop ($0 Cloud Spend)  
**Execution Context:** `apps/web/` (React + TypeScript + Vite + Tailwind CSS + TanStack Query + Lucide Icons)  
**Status:** PASS — Zero Failures, Zero Regressions  

---

## 1. Executive Summary

Phase 17E implements the user-facing self-service onboarding and management layer for the Transformer WAF platform. It delivers the **6-Step Interactive Site Onboarding Setup Wizard (`SiteOnboardingWizard.tsx`)**, the **Tenant Site Quota Management UI** for `OWNER` users, granular **Role-Based Access Control (RBAC)** enforcement, live on-demand origin health probing directly from the site listing table, and zero-restart status badge feedback (`ACTIVE`, `PENDING_VERIFICATION`, `DNS_PENDING`, `TLS_PENDING`, `HEALTH_CHECK`, `PAUSED`, `FAILED`).

All strict constraints and invariants were respected:
- Target strictly restricted to `apps/web/`. Zero backend or proxy runtime modifications (`apps/api/`, `src/`, `models/`, or `nginx/`).
- Design system strictly preserved: Pitch-black (`#000000`, `#0A0A0A`, `#111111`, `#222222`) background with glowing orange accents (`#FF6600`, `#EA580C`) in Dark Mode; crisp neutral white in Light Mode.
- All 328 test suites/cases across the entire system pass with 100% pass rate:
  - React Vitest unit/component tests: **28 / 28 passed** (6 test suites)
  - NestJS API unit tests: **87 / 87 passed** (9 test suites)
  - NestJS API E2E tests: **111 / 111 passed** (7 test suites, including both DDD architectural boundary tests)
  - Python WAF Gateway tests: **102 / 102 passed**
  - Production Vite bundle build: **Succeeded in 5.54s** with route-based manual chunk splitting intact.

---

## 2. Component Implementation Details

### A. API Client Extensions (`apps/web/src/lib/api.ts`)
- **Tenant Quota Management:**
  - `api.tenants.get(tenantId)`: Retrieves tenant details including current `maxSites` quota.
  - `api.tenants.updateQuota(tenantId, maxSites)`: Calls `PATCH /api/v1/tenants/:tenantId/quota` (restricted to `OWNER`).
- **Complete Onboarding Lifecycle Operations:**
  - `api.sites.startOnboarding({ name, domain, originUrl })`: Calls `POST /api/v1/sites/onboarding`.
  - `api.sites.getOnboarding(siteId)`: Calls `GET /api/v1/sites/:siteId/onboarding` returning complete state, challenge tokens, and routing targets.
  - `api.sites.verifyDomain(siteId)`: Calls `POST /api/v1/sites/:siteId/onboarding/verify-domain`.
  - `api.sites.configureGateway(siteId)`: Calls `POST /api/v1/sites/:siteId/onboarding/configure` for atomic zero-downtime policy distribution.
  - `api.sites.verifyDnsRouting(siteId)`: Calls `POST /api/v1/sites/:siteId/onboarding/verify-dns-routing`.
  - `api.sites.provisionTls(siteId)`: Calls `POST /api/v1/sites/:siteId/onboarding/provision-tls`.
  - `api.sites.activate(siteId)`: Calls `POST /api/v1/sites/:siteId/onboarding/activate`.
  - `api.sites.retryOnboarding(siteId)`: Calls `POST /api/v1/sites/:siteId/onboarding/retry`.
  - `api.sites.pause(siteId)` & `api.sites.resume(siteId)`: Calls `/pause` and `/resume`.
  - `api.sites.checkHealth(siteId)`: Calls `POST /api/v1/sites/:siteId/health-check` for on-demand origin reachability testing.

### B. 6-Step Interactive Wizard (`apps/web/src/components/SiteOnboardingWizard.tsx`)
- **Visual Progress Stepper:**
  - 6 clearly demarcated steps with status indicators: `1. Details`, `2. Ownership`, `3. Gateway`, `4. DNS Traffic`, `5. TLS Ready`, `6. Activation`.
  - Dynamically jumps to the correct step based on `onboardingStatus` when resuming setup for an in-flight site.
- **Step 1 — Website & Origin Details:**
  - Displays tenant quota utilization card (`X / maxSites Sites Used`).
  - Automatically disables submission and renders warning if tenant quota is exhausted.
  - Collects friendly name, normalized FQDN domain, and upstream origin URL.
- **Step 2 — Verify Domain Ownership:**
  - Formatted DNS TXT record challenge card displaying `Host` (`_waf-challenge.<domain>`) and `Value` (`verificationToken`).
  - One-click copy buttons with clipboard feedback (`Copied!`).
  - "Verify Domain Ownership" trigger with inline spinner.
- **Step 3 — Atomic Gateway Policy Distribution:**
  - Explains zero-downtime runtime policy distribution and initial safe `MONITOR` mode.
  - "Sync Configuration to Gateway" action showing `gatewayAckVersion` feedback.
- **Step 4 — DNS Traffic Routing:**
  - Displays DNS CNAME routing target (`edge.transformer-waf.internal`) with copy button.
  - "Verify DNS Routing" trigger.
- **Step 5 — Edge TLS Certificate Readiness:**
  - Displays TLS status (`PENDING`, `PROVISIONED`), issuer (`local-dev-acme`), and expiration timestamp.
  - Security invariant strictly adhered to: **Zero private keys are exposed or rendered**.
- **Step 6 — Origin Health Probing & Activation:**
  - Live origin connectivity probe verifying HTTP status and SSRF/DNS-rebinding protection.
  - Once active, presents a glowing success banner with direct action shortcuts:
    * `WAF Policy Studio` (`/policies?siteId=<id>`)
    * `Live Security Events` (`/events`)
- **Error Handling & Resumability:**
  - Displays `lastOnboardingError` inside a high-visibility alert banner.
  - Provides a single-click `Retry Setup` button triggering `POST /onboarding/retry`.

### C. Sites Listing & Management Page (`apps/web/src/pages/Sites.tsx`)
- **Tenant Quota Display & OWNER In-line Quota Editing:**
  - Prominent quota counter badge (`{used} / {maxSites} Sites Used`) with warning tag when full.
  - `OWNER` users can toggle an inline quota editor (`1–100`) directly updating `PATCH /tenants/:id/quota`.
  - Non-OWNER users see quota usage without edit permissions.
- **Granular Status Badges:**
  - Onboarding lifecycle badges: `ACTIVE`, `PAUSED`, `FAILED`, `VERIFY TXT`, `DNS PENDING`, `TLS PENDING`, `HEALTH CHECK`.
  - TLS status indicators (`TLS Active`, `Provisioning`, `None`).
  - Origin health indicators (`Healthy`, `Unhealthy`, `Unknown`).
  - Gateway acknowledgment badge (`v{gatewayAckVersion}`).
- **Row Action Controls:**
  - Incomplete sites display a direct `Resume Setup` button opening the wizard at the current stage.
  - Active sites display `Pause` / `Resume` protection toggles.
  - Live on-demand `Check Health` button running origin probe with inline latency & status feedback.
  - Delete site confirmation dialog.
- **RBAC Enforcement:**
  - `OWNER`: Full access including quota modification.
  - `ADMIN`: Protection and site mutation allowed; quota editing hidden.
  - `ANALYST` & `VIEWER`: Read-only observation mode; mutating actions disabled/hidden.

---

## 3. Test & Verification Results

| Suite / Test Target | Command | Result | Pass Count |
|---|---|---|---|
| **Web Vitest Tests** | `npm test -- --run` (in `apps/web/`) | **PASS** | 28 / 28 passed |
| **Web Production Build** | `npm run build` (in `apps/web/`) | **PASS** | Succeeded in 5.54s |
| **API Unit Tests** | `npm test` (in `apps/api/`) | **PASS** | 87 / 87 passed |
| **API E2E Tests** | `npx jest --config ./test/jest-e2e.json` | **PASS** | 111 / 111 passed |
| **DDD Invariant Tests** | `architecture.e2e-spec.ts` | **PASS** | 2 / 2 passed |
| **Python WAF Gateway** | `pytest tests/ -q` | **PASS** | 102 / 102 passed |
| **TOTAL** | | **100% PASS** | **328 / 328 passed** |

---

## 4. Architectural Boundary Verification

1. **Zero Backend Modifications:**
   - No files inside `apps/api/`, `src/waf_gateway/`, `models/frozen/v1_0/`, or `nginx/` were touched.
2. **Domain Architecture Invariants:**
   - Both DDD invariants in `apps/api/test/architecture.e2e-spec.ts` pass cleanly (0 framework imports in `domain/`, 0 cross-module concrete imports).
3. **Frontend Code Splitting:**
   - Route-level lazy loading (`React.lazy`) and manual chunk splitting in `vite.config.ts` retained across all routes (`Sites`, `Policies`, `Events`, `Feedback`, `Team`, `Overview`).
