# Phase 13 Audit & Architecture Report: Background Jobs, Alerting & Async Control-to-Data Bridge

**Date:** 2026-11-25  
**Scope:** Phase 13 — Background Jobs, Real-time Alerting, Webhooks & Asynchronous Control-to-Data Bridge (Redis + BullMQ)  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

Phase 13 establishes the asynchronous orchestration layer for the multi-tenant Transformer WAF platform. It bridges the control-plane NestJS API to background operations, external alerting channels, and the data-plane WAF gateways.

The implementation strictly maintains:
1. **Modular Monolith & DDD Boundaries:** The domain layers (`modules/notifications/domain/`, etc.) have **0 external dependencies** on `@prisma/client`, `@nestjs/*`, `express`, `bullmq`, or `ioredis`. This is verified by architectural assertions in `test/architecture.e2e-spec.ts`.
2. **Dual-Mode Queue Architecture:** An `IJobQueue` port abstraction provides pluggable infrastructure support for BullMQ + Redis (`BullMqJobQueue`) in production and a deterministic in-memory queue (`InMemoryJobQueue`) for hermetic local testing ($0 cloud/infrastructure cost).
3. **Enterprise Webhook Security:** Webhooks feature strict SSRF defense (blocking `169.254.0.0/16`, `0.0.0.0`, `metadata.google.internal`) and cryptographically robust HMAC-SHA256 signature verification (`X-WAF-Signature-256`, `X-WAF-Timestamp`).
4. **Offline ML Safety Rule:** The feedback export worker processes only `APPROVED` false positive / attack feedback into versioned, redacted JSONL datasets with SHA-256 manifest integrity. It **never** triggers auto-retraining or alters live model weights.

---

## 2. Test Verification Matrix

| Component / Test Suite | Type | Tests | Status | Execution Time |
| :--- | :--- | :--- | :--- | :--- |
| **NestJS Unit Tests** (`apps/api`) | Jest Unit | 81 / 81 | **PASSED** | 5.81s |
| **NestJS E2E Test Suite** (`apps/api`) | Supertest E2E | 82 / 82 | **PASSED** | 11.48s |
| - `architecture.e2e-spec.ts` | Architecture (DDD) | 1 / 1 | PASSED | - |
| - `tenants.e2e-spec.ts` | Multi-Tenant Scoping | 16 / 16 | PASSED | - |
| - `auth-rbac.e2e-spec.ts` | RBAC & Identity | 14 / 14 | PASSED | - |
| - `sites-policies.e2e-spec.ts` | Sites & Versioned Policies | 18 / 18 | PASSED | - |
| - `events-analytics.e2e-spec.ts` | Events, Feedback & Analytics | 18 / 18 | PASSED | - |
| - `jobs-notifications.e2e-spec.ts` | Webhooks, Alerts & Queue Workers | 15 / 15 | PASSED | - |
| **NestJS Production Build** (`apps/api`) | TypeScript Compilation | `nest build` | **PASSED** | 0 errors |
| **React SOC Dashboard Tests** (`apps/web`) | Vitest + RTL | 18 / 18 | **PASSED** | 3.20s |
| **React SOC Dashboard Build** (`apps/web`) | Vite Production Build | `tsc -b && vite build`| **PASSED** | 4.37s |
| **Python Core ML/WAF Engine** (`tests/`) | PyTest | 77 / 77 | **PASSED** | 43.62s |
| **Total Test Count** | **Full System Matrix** | **258 / 258** | **ALL GREEN** | - |

---

## 3. Implemented Architecture & Components

### 3.1 Prisma Schema Enhancements
- `Notification`: In-app tenant notification entity supporting `INFO`, `WARNING`, `CRITICAL` severities and types: `ATTACK_SPIKE`, `ML_DEGRADED`, `POLICY_SYNC_FAILED`, `FEEDBACK_EXPORT_READY`. Indexed by `[tenantId, isRead, createdAt]`.
- `WebhookEndpoint`: Outbound webhook configuration supporting HMAC secrets, URL validation, and subscription filters. Indexed by `[tenantId]`.

### 3.2 Queue Abstraction (`apps/api/src/shared/infrastructure/queues/`)
- `IJobQueue`: Enqueueing interface with delayed execution, exponential backoff retries, and job tracking.
- `BullMqJobQueue`: Redis-backed queue (`bullmq` + `ioredis`) for production deployment.
- `InMemoryJobQueue`: Fast, deterministic, zero-dependency in-memory queue for developer laptops and hermetic CI testing.

### 3.3 Domain & Application Services (`apps/api/src/modules/notifications/`)
- `WebhookUrl`: Value object preventing SSRF by strictly rejecting private link-local ranges (`169.254.x.x`), wildcard IPs (`0.0.0.0`), and cloud metadata services.
- `WebhookSignature`: Cryptographic HMAC-SHA256 generator and timing-safe signature validator.
- `AlertEvaluator`: Domain service identifying attack spikes (burst of $\ge 5$ blocked events for a site) and degraded ML fallbacks.
- `AlertsWorker`: Processes `alerts` jobs, creates in-app notifications, and dispatches signed outbound webhooks.
- `PolicySyncWorker`: Pushes site policy updates to data-plane WAF gateways with automatic retries and failure notification escalation.
- `FeedbackExportWorker`: Generates offline ML dataset artifacts from `APPROVED` event feedback without touching live inference models.

---

## 4. Architectural Rules Compliance
- **Rule 1 (Zero Domain Leakage):** Verified by `test/architecture.e2e-spec.ts`. All domain files have 0 imports from Prisma, NestJS, Express, BullMQ, or IORedis.
- **Rule 2 (Tenant Isolation):** Every webhook endpoint, notification query, and background job strictly binds to `tenantId`.
- **Rule 3 (Preservation of ML/WAF Core):** All files under `src/`, `models/`, `tests/`, and `nginx/` remain 100% untouched and passing (`77/77`).
