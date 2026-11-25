# PHASE 10 — PROTECTED SITES & TENANT WAF POLICY MANAGEMENT REPORT
**Date:** 2026-11-25  
**Author:** Antigravity Autonomous Agent  
**Status:** Completed & Validated  

---

## 1. Executive Summary

Phase 10 delivers the complete multitenant **Protected Sites** and **WAF Policy Management** bounded contexts inside `apps/api/` following the Master Plan Modular Monolith + DDD architecture:
- **`modules/protected-sites/`**: Domain-driven site registration, FQDN validation, SSRF-safe upstream origin enforcement, and full lifecycle management.
- **`modules/waf-policies/`**: Level 1 per-site policy customization, strict threshold ordering invariants, anti-wildcard scoped exclusions, versioned policy snapshots, 1-click non-destructive rollback, and gateway data plane effective policy export.
- **Security & Multitenancy**: Complete cross-tenant isolation (cross-tenant access yields `404 Not Found` without information leakage), strict RBAC hierarchy (`OWNER`, `ADMIN`, `ANALYST`, `VIEWER`), and structured AuditLog persistence.
- **Architectural Boundary**: Verified 0 imports of `@prisma/client`, `@nestjs/*`, or `express` across all domain layers.

---

## 2. Domain & Application Architecture

### 2.1 Protected Sites Bounded Context (`apps/api/src/modules/protected-sites/`)
- **Domain Layer (`domain/`)**:
  - `SiteDomain`: Value object enforcing valid FQDNs (RFC 1035 / RFC 1123), lowercasing, and rejecting URL schemes (`http://`), paths (`/api`), ports (`:8080`), and wildcards (`*.domain.com`).
  - `OriginUrl`: Value object enforcing `http://` or `https://` upstream schemes, explicitly rejecting SSRF targets (link-local AWS/GCP/Azure `169.254.169.254`, Google Cloud internal `metadata.google.internal`, Tailscale `100.100.100.200`, and `0.0.0.0`).
  - `ProtectedSite`: Aggregate root with `status` (`ACTIVE`, `PAUSED`, `ARCHIVED`), domain, origin URL, and tenant ownership.
  - `IProtectedSiteRepository`: Repository interface with tenant-scoped isolation.
- **Application Layer (`application/`)**:
  - `CreateProtectedSiteUseCase`: Creates site, validates unique domain per tenant, auto-provisions default v1 MONITOR policy, and writes `SITE_CREATED` AuditLog.
  - `ListProtectedSitesUseCase`, `GetProtectedSiteUseCase`: Scoped site retrieval.
  - `UpdateProtectedSiteUseCase`: Scoped updates with `SITE_UPDATED` AuditLog.
  - `DeleteProtectedSiteUseCase`: Scoped deletion with `SITE_DELETED` AuditLog.
- **Infrastructure Layer (`infrastructure/`)**:
  - `PrismaProtectedSiteRepository`: Production persistence with Prisma ORM.
  - `InMemoryProtectedSiteRepository`: Zero-dependency test doubles for fast, hermetic test execution.
- **Presentation Layer (`presentation/`)**:
  - `ProtectedSitesController`: Exposes `/api/v1/sites` protected by `JwtAuthGuard`, `RolesGuard`, and `@Roles`.

### 2.2 WAF Policies Bounded Context (`apps/api/src/modules/waf-policies/`)
- **Domain Layer (`domain/`)**:
  - `PolicyThresholds`: Value object enforcing mathematical threshold ordering:
    $$0.0 < \tau_{\text{monitor}} < \tau_{\text{challenge}} < \tau_{\text{block}} \le 1.0$$
  - `ScopedExclusion`: Value object enforcing leading slash (`/`), mandatory justification reason ($\ge 5$ chars), and explicitly rejecting dangerous full-site wildcard bypasses (`*` or `/*`).
  - `WafPolicy`: Versioned policy aggregate supporting modes (`MONITOR`, `BLOCKING`, `STRICT`, `CORROBORATED`, `DISABLED`), ML failure modes (`FAIL_OPEN`, `FAIL_CLOSED`), feature toggles (`mlEnabled`, `rulesEnabled`, `challengeEnabled`), and non-destructive versioning.
  - `IWafPolicyRepository`: Interface supporting `findActiveBySite`, `findBySiteAndVersion`, `findHistoryBySite`, `save`, and `deactivateActivePolicies`.
- **Application Layer (`application/`)**:
  - `GetSitePolicyUseCase`: Fetches currently active version for site.
  - `ListSitePolicyHistoryUseCase`: Returns all versions in reverse chronological order for auditing.
  - `UpdateSitePolicyUseCase`: Deactivates previous active policy, creates incremented active version ($v_{\text{new}} = v_{\text{old}} + 1$), and records `WAF_POLICY_UPDATED` AuditLog.
  - `RollbackSitePolicyUseCase`: Non-destructive 1-click rollback: retrieves historical snapshot and creates a new active version ($v_{\text{new}} = v_{\text{current}} + 1$) matching the target state, recording `WAF_POLICY_ROLLED_BACK` AuditLog.
  - `GetEffectiveGatewayPolicyUseCase`: Generates clean JSON schema directly consumable by the Python WAF Gateway data plane.
- **Infrastructure Layer (`infrastructure/`)**:
  - `PrismaWafPolicyRepository`: Production persistence storing exclusions as structured JSON.
  - `InMemoryWafPolicyRepository`: Hermetic in-memory repository for unit and E2E testing.
- **Presentation Layer (`presentation/`)**:
  - `WafPoliciesController`: Exposes `/api/v1/sites/:siteId/policy` protected by `JwtAuthGuard` and `RolesGuard`.

---

## 3. API Surface & Security Specifications

| Route | Method | Roles Allowed | Description |
|---|---|---|---|
| `/api/v1/sites` | `POST` | `OWNER`, `ADMIN` | Register protected site & auto-provision v1 MONITOR policy |
| `/api/v1/sites` | `GET` | All Roles | List sites belonging to caller's tenant |
| `/api/v1/sites/:siteId` | `GET` | All Roles | Get site details (404 if cross-tenant) |
| `/api/v1/sites/:siteId` | `PATCH` | `OWNER`, `ADMIN` | Update site name, origin URL, or status |
| `/api/v1/sites/:siteId` | `DELETE` | `OWNER`, `ADMIN` | Delete protected site |
| `/api/v1/sites/:siteId/policy` | `GET` | All Roles | Get active policy configuration |
| `/api/v1/sites/:siteId/policy/history` | `GET` | All Roles | Get full version audit history |
| `/api/v1/sites/:siteId/policy` | `PUT` | `OWNER`, `ADMIN` | Update policy (creates incremented version) |
| `/api/v1/sites/:siteId/policy/rollback/:version` | `POST` | `OWNER`, `ADMIN` | 1-click rollback restoring historical version as new version |
| `/api/v1/sites/:siteId/policy/effective` | `GET` | All Roles | Export effective policy JSON for WAF Gateway |

---

## 4. Verification & Test Results

### 4.1 DDD Architecture Invariants
- `test/architecture.e2e-spec.ts`: **PASS** (Zero forbidden imports from `@prisma/client`, `@nestjs/*`, or `express` across all `**/domain/**` files).

### 4.2 NestJS Unit Tests
- `npm test`: **5 test suites, 49 tests passing (100%)**
  - `tenant.entity.spec.ts`
  - `protected-site.spec.ts` (FQDN validation, SSRF IP blocking, entity lifecycle)
  - `waf-policy.spec.ts` (Threshold ordering, anti-wildcard exclusions, versioning, rollback)
  - `identity.spec.ts`
  - `tenant-use-cases.spec.ts`

### 4.3 NestJS E2E Integration Tests
- `npm run test:e2e`: **4 test suites, 45 tests passing (100%)**
  - `architecture.e2e-spec.ts` (1 passed)
  - `sites-policies.e2e-spec.ts` (29 passed: site creation, auto v1 policy, updates, rollback, RBAC 403 enforcement, cross-tenant 404 isolation, deletion)
  - `tenants.e2e-spec.ts` (4 passed)
  - `auth-rbac.e2e-spec.ts` (11 passed)

### 4.4 Build Verification
- `npm run build`: **PASS** (Zero TypeScript compilation errors).

### 4.5 Python ML/WAF Data Plane Integrity
- `pytest tests/ -q`: **77 passed** (All ML models, feature extractors, challenge verification, and firewall pipeline tests remain 100% untouched and passing).
