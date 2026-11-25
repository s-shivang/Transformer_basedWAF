# Phase 16: Operations, Microservice Extraction & Enterprise Scaling Runbook

**Document Version:** 1.0.0  
**Phase:** 16 — Scale & Microservice Extraction Readiness  
**Target Environment:** Local Windows / Hybrid Cloud Microservice Transition ($0 baseline)  
**System Status:** Production Ready, Containerized, and Extraction-Prepared  

---

## 1. System Topology Overview

The Transformer WAF architecture operates with strict physical and logical boundaries separating the **Control Plane**, **Data Plane**, and **Async Message/Job Bridge**:

```
                              [ Internet Ingress ]
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   waf-nginx (Reverse Proxy)   │
                       │   Port: 8080 (Perimeter TLS)  │
                       │   /_waf/* Admin Routes BLOCKED│
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │     waf-gateway (FastAPI)     │
                       │     Data Plane Decision Engine│
                       │     Latency Budget: < 15ms    │
                       └───────┬───────────────┬───────┘
                               │               │
       (Sync HTTP scoring)     │               │  (Async Background Fire-and-Forget)
       Timeout: <= 50ms        │               │  Timeout: <= 1.5s
                               ▼               ▼
      ┌───────────────────────────────┐  ┌─────────────────────────────────┐
      │   waf-ml-service (PyTorch)    │  │       waf-api (NestJS API)      │
      │   Port: 8000                  │  │       Control Plane SaaS        │
      │   Frozen v1_0 Base Encoder    │  │       Port: 3000                │
      │   Level 4 LoRA Multi-Tenant   │  └────────────────┬────────────────┘
      └───────────────────────────────┘                   │
                                                          ▼
                                         ┌─────────────────────────────────┐
                                         │  waf-postgres (PostgreSQL 16)   │
                                         │  waf-redis (Redis 7 + BullMQ)   │
                                         └─────────────────────────────────┘
```

---

## 2. Microservice Extraction Playbook

The NestJS Control Plane (`apps/api/`) is built as a **Modular Monolith** adhering to Domain-Driven Design (DDD). Domain layers have zero imports from frameworks, databases, or message queues. Concrete repositories are encapsulated inside their respective module's `infrastructure/` package, and cross-context interactions are strictly governed by NestJS injection tokens and abstract interfaces.

### Step-by-Step Service Extraction Methodology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MODULAR MONOLITH EXTRACTION PHASES                   │
├──────────────────────┬─────────────────────────────┬────────────────────────┤
│ Phase 1: In-Process  │ Phase 2: Dual-Run / Strangler│ Phase 3: Autonomous    │
│ Modular Monolith     │ Remote RPC / Event Bridge   │ Standalone Service     │
├──────────────────────┼─────────────────────────────┼────────────────────────┤
│ - Direct TS Provider │ - HTTP/gRPC client adapter  │ - Independent DB repo  │
│ - Shared Transaction │ - BullMQ event bus bridge   │ - Independent Git repo │
│ - In-memory pipeline │ - Feature flag route split  │ - Independent CI/CD    │
└──────────────────────┴─────────────────────────────┴────────────────────────┘
```

### Extraction Target 1: `security-events` (High-Volume Ingestion)
- **Current Location:** `apps/api/src/modules/security-events/`
- **Why Extract First:** `security-events` absorbs 100% of telemetry from all data planes. Separating it shields the SaaS management API from traffic spikes.
- **Extraction Steps:**
  1. **Interface Isolation:** The data plane currently sends events via `POST /api/v1/internal/events`. This endpoint is already completely decoupled from user authentication (secured by `X-WAF-Ingest-Key`).
  2. **Database Separation:** Split `SecurityEvent` and `EventFeedback` tables into a dedicated read-optimized PostgreSQL or ClickHouse instance.
  3. **Queue Ingestion:** Transition from synchronous HTTP ingestion to direct Redis stream ingestion (`waf-gateway` $\rightarrow$ Redis stream $\rightarrow$ `security-events` worker).
  4. **Consumer Contract:** Control Plane reads events via a lightweight HTTP client implementing the `ISecurityEventQueryService` interface.

### Extraction Target 2: `notifications` & Webhooks (Async Worker Fleet)
- **Current Location:** `apps/api/src/modules/notifications/`
- **Why Extract Second:** Outbound HTTP webhooks and batch ML feedback export jobs are I/O heavy and must not starve API request threads.
- **Extraction Steps:**
  1. Deploy `apps/api/src/modules/notifications/application/workers/` as a headless Node.js container (`waf-worker`).
  2. The worker container connects to `waf-redis` and processes BullMQ queues (`alerts`, `policy-sync`, `feedback-export`).
  3. API container retains read-only queries for in-app notification bell icons via `GET /api/v1/notifications`.

### Extraction Target 3: `ml-service` (GPU-Accelerated Inference Cluster)
- **Current Location:** `src/ml_service/`
- **Already Extracted:** Operates as an independent FastAPI container communicating over HTTP.
- **Horizontal Scaling Path:**
  1. Place `ml-service` behind an internal load balancer (e.g. Nginx upstream `least_conn` or Envoy).
  2. Autoscale replicas based on CPU/GPU utilization without altering `waf-gateway` configuration.

---

## 3. Level 1–4 Multi-Tenant Customization Ladder

The platform provides a 4-tier customization model allowing enterprise tenants to balance simplicity against specialized threat protection:

```
LEVEL 4: Per-Tenant / Per-Site LoRA Adapters (Dynamic Rank <= 16, Custom Fine-Tuned Threat Vectors)
   ▲
   │
LEVEL 3: Curated Feedback Loop (Tenant Analysts Verify FP/FN -> Versioned JSONL -> Offline Retrain)
   ▲
   │
LEVEL 2: Dynamic Fast-Pass & Calibrated Risk Thresholds (p50 < 5ms Fast Paths, Tenant-Specific Sensitivity)
   ▲
   │
LEVEL 1: WAF Policy Modes & Deterministic Rule Exclusions (OFF | MONITOR | CHALLENGE | BLOCKING)
```

| Customization Level | Mechanism | Scope | Latency Impact | VRAM / Memory Cost |
| :--- | :--- | :--- | :--- | :--- |
| **Level 1** | Policy Mode (`BLOCKING`, `CHALLENGE`, `MONITOR`, `OFF`) + Rule Exclusion List | Tenant / Site | 0 ms | 0 MB |
| **Level 2** | Risk score thresholds (`blockThreshold`, `challengeThreshold`, `anomalyWeight`) | Tenant / Site | 0 ms | 0 MB |
| **Level 3** | False positive feedback export to versioned, redacted JSONL artifacts | Tenant / Global | Offline Job | 0 MB live |
| **Level 4** | LoRA Adapter Hot-Swap (`lora_registry.py`, rank $\le$ 16, memory budget $\le$ 64 MB) | Tenant / Site | $< 1.5$ ms | $\le 64$ MB / adapter |

### Level 4 LoRA Architectural Invariants:
1. **Base Encoder Invariance:** The shared base model (`models/frozen/v1_0/`) is frozen and strictly read-only.
2. **Deterministic Fallback:** Requests from tenants or sites without an active adapter automatically resolve to `base_v1_0` with zero runtime overhead.
3. **Hardware Guardrails:** Adapters enforce strict safety bounds (`rank <= 16`, estimated memory $\le 64$ MB) to guarantee continuous operation on constrained hardware (e.g., 4 GB laptop GPU).
4. **Cryptographic Verification:** Adapters must pass SHA-256 integrity verification before hot-swapping into memory.

---

## 4. Operational Runbook & Incident Response

### Scenario A: ML Service Outage or Degradation
- **Symptom:** `waf-ml-service` container crashes, runs out of memory, or fails health checks (`/health` returns non-200 or times out).
- **Automated Fail-Safe Behavior:**
  1. `waf-gateway` detects connection failure via `httpx.ConnectError` or timeout ($> 50$ ms).
  2. **Layer 1 Deterministic Defense Remains Active:** Deterministic regex rules (SQLi, XSS, Path Traversal, Command Injection) continue executing and blocking attacks (`403 Forbidden`).
  3. **Fail-Open Policy:** For requests where Layer 1 detects no threat, traffic is passed upstream with header `X-WAF-Degraded: true` and status `200 OK`.
  4. An alert of type `ML_DEGRADED` is enqueued for tenant notifications.
- **Remediation Steps:**
  ```powershell
  # 1. Check ML service container status and logs
  docker compose logs --tail=100 ml-service

  # 2. Restart ML service
  docker compose restart ml-service

  # 3. Verify health
  Invoke-RestMethod -Uri http://127.0.0.1:8000/health
  ```

### Scenario B: Accidental False-Positive Outage (1-Click Policy Rollback)
- **Symptom:** A tenant updates their WAF policy threshold to an overly aggressive value (e.g. `blockThreshold: 0.10`), causing legitimate user traffic to be blocked.
- **Automated Rollback Mechanism:**
  1. Tenant navigates to **Policies** in the Threat Center dashboard (`http://127.0.0.1:5173/policies`).
  2. Selects the target site and clicks **Rollback to Version X**.
  3. The API invokes `POST /api/v1/sites/:siteId/policy/rollback/:version`:
     - Creates a new active policy revision with the previous version's configuration.
     - Asynchronously syncs the restored policy to `waf-gateway` (`PUT /_waf/policy`).
  4. Instant recovery time: $< 200$ ms.

### Scenario C: Safe Git & Container Rollback
- **Procedure for Production Rollback:**
  ```powershell
  # 1. Roll back Git repository to previous verified commit
  git checkout <PREVIOUS_COMMIT_SHA>

  # 2. Rebuild and restart the container fleet
  docker compose up -d --build

  # 3. Run automated smoke verification
  .venv\Scripts\python.exe scripts/smoke_test_docker_stack.py
  ```

---

## 5. Architectural Decision Records (ADRs)

### ADR-01: Modular Monolith vs. Early Microservices
- **Decision:** Build the Control Plane as a Modular Monolith in NestJS rather than spinning up 6 separate microservices on Day 1.
- **Context:** A microservice architecture introduces distributed transaction overhead, network latency, serialization costs, and complex local deployment requirements on developer laptops.
- **Consequences:** The modular monolith provides 100% of the domain boundary benefits with zero network hop overhead and simple $0-cloud deployment. Code boundaries are strictly verified via automated architecture tests (`architecture.e2e-spec.ts`).

### ADR-02: Asynchronous Non-Blocking Telemetry Bridge
- **Decision:** Forward WAF decision events from the data plane (`waf-gateway`) to the control plane (`waf-api`) asynchronously in background tasks with short timeouts ($\le 1.5$s).
- **Context:** If telemetry ingestion were synchronous, any Control Plane database lock or downtime would block end-user web traffic.
- **Consequences:** End users experience sub-15ms proxying latency regardless of Control Plane database load or network blips.

### ADR-03: Frozen Base Model with Level 4 LoRA Multi-Tenancy
- **Decision:** Freeze the Transformer v1_0 encoder and implement tenant customization through an out-of-band LoRA adapter registry rather than per-tenant fine-tuned base models.
- **Context:** Full fine-tuning for dozens of tenants would require gigabytes of disk and VRAM, exceeding local laptop constraints and causing severe model thrashing.
- **Consequences:** Base weights remain SHA-256 verified and immutable. LoRA adapters add $< 1.5$ MB overhead per tenant with rank $\le 16$, perfectly conforming to a 4 GB VRAM budget.

### ADR-04: Dual-Engine ML Pipeline (TF-IDF Fast-Pass + DistilBERT)
- **Decision:** Combine a high-speed linear TF-IDF classifier (p50 $< 5$ms) with a deep Transformer sequence classifier (DistilBERT).
- **Context:** Deep neural networks cannot evaluate every single benign request within tight edge WAF budgets ($< 15$ms).
- **Consequences:** Over 85% of traffic is resolved on the sub-5ms fast path, preserving Transformer compute capacity for ambiguous or sophisticated attack vectors.
