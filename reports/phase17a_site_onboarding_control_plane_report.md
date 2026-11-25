# Phase 17A — Site Onboarding State Machine, Owner Site Quotas & Domain Ownership Verification

**Execution Date**: 2026-11-25  
**Scope**: Control Plane (`apps/api/`) Modular Monolith DDD Architecture  
**Status**: Completed & Verified  

---

## 1. Executive Summary

Phase 17A delivers the enterprise onboarding control plane for Transformer WAF. It establishes a multi-state onboarding state machine, enforces tenant-level site quotas controlled exclusively by tenant `OWNER`s, implements global domain uniqueness to prevent cross-tenant domain hijacking, and introduces automated cryptographic DNS TXT ownership verification.

---

## 2. Architecture & Domain Invariants

### 2.1 State Machine Lifecycle
The `ProtectedSite` entity implements an 11-status finite state machine:
- `DRAFT` $\rightarrow$ `PENDING_VERIFICATION` | `REMOVED`
- `PENDING_VERIFICATION` $\rightarrow$ `VERIFIED` | `FAILED` | `REMOVED`
- `VERIFIED` $\rightarrow$ `CONFIGURING` | `FAILED` | `REMOVED`
- `CONFIGURING` $\rightarrow$ `DNS_PENDING` | `FAILED`
- `DNS_PENDING` $\rightarrow$ `TLS_PENDING` | `HEALTH_CHECK` | `FAILED`
- `TLS_PENDING` $\rightarrow$ `HEALTH_CHECK` | `FAILED`
- `HEALTH_CHECK` $\rightarrow$ `ACTIVE` | `FAILED`
- `ACTIVE` $\rightarrow$ `PAUSED` | `CONFIGURING` | `REMOVED`
- `PAUSED` $\rightarrow$ `ACTIVE` | `REMOVED`
- `FAILED` $\rightarrow$ `PENDING_VERIFICATION` | `CONFIGURING` | `REMOVED` (retry path)

Illegal state transitions (such as attempting to jump directly from `PENDING_VERIFICATION` to `ACTIVE` without verification) are rejected at the domain model level.

### 2.2 Quota & Ownership Invariants
1. **Tenant Quota Invariant**: `Tenant.maxSites` defaults to 5 and is restricted to $1 \le \text{maxSites} \le 100$. Quota modifications are guarded by `RolesGuard` and restricted strictly to `UserRole.OWNER`.
2. **Global Domain Uniqueness**: Enforced via Prisma `@unique` on `ProtectedSite.domain` and domain validation (`findGlobalByDomain`), preventing Tenant B from hijacking or registering a domain already owned or verified by Tenant A.
3. **Cryptographic Token Challenge**: Every onboarded site receives a unique cryptographic challenge token (`waf-verify-<32-hex-bytes>`). Ownership requires publishing this token as a DNS TXT record at `_waf-challenge.<domain>`.

### 2.3 Strict DDD Layering
- **Zero Framework Imports in Domain**: All files in `domain/` maintain zero imports from `@prisma/client`, `@nestjs/*`, `express`, `bullmq`, or `ioredis`.
- **Infrastructure Decoupling**: DNS verification is abstracted through the `IDnsVerifier` domain port. The production implementation uses `NodeDnsVerifier` (`dns/promises`), while tests and local development use `LocalDevDnsVerifier`.

---

## 3. Endpoints Implemented

| Method | Endpoint | Authorized Roles | Description |
| :--- | :--- | :--- | :--- |
| `PATCH` | `/api/v1/tenants/:id/quota` | `OWNER` | Sets protected site quota ($1 \le \text{maxSites} \le 100$) |
| `POST` | `/api/v1/sites/onboarding` | `OWNER`, `ADMIN` | Starts onboarding in `PENDING_VERIFICATION` |
| `GET` | `/api/v1/sites/:siteId/onboarding` | `VIEWER+` | Retrieves status, challenge token, and DNS instructions |
| `POST` | `/api/v1/sites/:siteId/onboarding/verify-domain` | `OWNER`, `ADMIN` | Checks DNS TXT record; advances to `VERIFIED` on match |
| `POST` | `/api/v1/sites/:siteId/onboarding/retry` | `OWNER`, `ADMIN` | Resets a `FAILED` site back to `PENDING_VERIFICATION` |
| `POST` | `/api/v1/sites/:siteId/onboarding/pause` | `OWNER`, `ADMIN` | Pauses an active site |
| `POST` | `/api/v1/sites/:siteId/onboarding/resume` | `OWNER`, `ADMIN` | Resumes a paused site |
| `POST` | `/api/v1/sites` | `OWNER`, `ADMIN` | Legacy site creation (remains 100% backward compatible) |

---

## 4. Test Verification & Results

1. **API Unit Tests (`apps/api`)**:
   - `9 passed, 9 total suites`
   - `87 passed, 87 total tests` (including state machine transitions, quota bounds, and SSRF origin checks)
2. **API E2E Tests (`apps/api/test/site-onboarding.e2e-spec.ts`)**:
   - `14 passed, 14 total tests` covering RBAC quota authorization, quota limits, cross-tenant domain hijacking rejection, DNS TXT challenge resolution, failed retries, and pause/resume.
3. **Architectural Boundary Invariants (`apps/api/test/architecture.e2e-spec.ts`)**:
   - Zero framework imports in domain: **PASS**
   - Zero concrete cross-module infrastructure imports: **PASS**
4. **Build Compilation**:
   - NestJS build (`nest build`) passes cleanly with zero TypeScript errors.

---

## 5. Next Steps (Phase 17B)
With the control plane state machine and verification primitives established in 17A, the system is primed for **Phase 17B (Dynamic Gateway Routing & Zero-Downtime Reload)**.
