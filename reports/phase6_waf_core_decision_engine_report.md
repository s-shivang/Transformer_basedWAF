# Phase 6 — WAF Core & Decision Engine Engineering Report

**Date:** 2026-11-24  
**Project:** Transformer-Based End-to-End Web Application Firewall (WAF)  
**Hardware Environment:** NVIDIA GeForce RTX 2050 (4GB VRAM, sm_86, CUDA 12.4), Intel Core i5 Host, Windows 11  
**Cloud Budget:** \$0.00 (Strictly Local Execution)  
**Architecture Context:** Modular Monolith with Domain-Driven Design (DDD)  

---

## 1. Executive Summary

Phase 6 implements the complete **WAF Core & Central Decision Engine** (`src/firewall/`), seamlessly fusing Layer 1 deterministic protocol rules, Layer 2/3 machine learning inference, and Layer 4 behavioral anomaly tracking into a single unified decision framework.

The WAF Core is built as an independent, tenant-ready Python engine decoupled from future NestJS SaaS business logic. By default, the engine operates in **`monitor` mode**, guaranteeing that production traffic is never automatically dropped or disrupted unless a tenant policy explicitly activates `blocking` or `strict` enforcement.

Additionally, Phase 6 closes all remaining Phase 5 test gaps (real SHA-256 tamper abort, tokenizer exception resilience, and CPU-fallback execution). Across both test suites, **34/34 tests passed** in $11.93\text{ seconds}$ with zero errors.

---

## 2. Phase 5 Test Gap Closure

The PyTest suite in `tests/test_ml_inference_service.py` was extended with 3 critical resilience and integrity tests:

1. **Real SHA-256 Tamper Test (`test_sha256_tamper_detection`):**
   - Corrupted an artifact checksum inside a simulated frozen manifest.
   - Verified that `ModelContainer.initialize()` immediately aborts with `RuntimeError: Startup verification failed`.
   - Verified that the `/ready` probe returns HTTP 503 (`sha256_verified: false`).
2. **Tokenizer / Inference Exception Safety Test (`test_tokenizer_inference_exception_safety`):**
   - Simulated an unexpected tokenizer runtime exception via monkeypatching.
   - Verified that `POST /v1/predict` catches the failure and returns a clean, structured JSON HTTP 500 error without exposing stack traces or crashing the ASGI worker.
3. **CPU-Fallback Verification Test (`test_cpu_fallback_execution`):**
   - Forced `device="cpu"` simulating a host environment without CUDA support.
   - Verified that `ModelContainer` initializes on CPU, executes PyTorch forward pass, and returns a valid `PredictResponse` ($p \ge 0.50$, `prediction="malicious"`).

---

## 3. WAF Core Architectural Components (`src/firewall/`)

```
src/firewall/
├── __init__.py            # Package exports: policy, rules, ml_client, anomaly, decision_engine
├── policy.py              # Tenant-ready FirewallPolicy & ThresholdConfig Pydantic models
├── rules_engine.py        # Layer 1: Sub-millisecond RFC protocol and deterministic signature checks
├── ml_client.py           # Pooled ML API Client (HTTP connection pooling + in-process adapter)
├── anomaly_detector.py    # Layer 4: Sliding time-window client behavioral tracking & burst detection
├── decision_engine.py     # CentralDecisionEngine & WAFDecision multi-signal fusion
├── shadow_validator.py    # Multi-client traffic replay harness
└── validate_firewall.py   # 4-layer validation runner
```

### 3.1 Policy Configuration Model (`src/firewall/policy.py`)
- **Inspection Modes:**
  - `"monitor"` (**default**): Full multi-layer inspection with security telemetry; `action` is always `MONITOR` or `ALLOW`, recording the hypothetical enforcement in `would_action`.
  - `"blocking"`: Enforces `BLOCK` for Layer 1 violations and high-risk ML ($\ge 0.90$), `CHALLENGE` for ambiguous band ($0.50 \le \text{score} < 0.90$).
  - `"strict"`: Lowers the automated block threshold to $0.50$.
  - `"disabled"`: Skips inspection and immediately returns `ALLOW` (`reason="INSPECTION_DISABLED"`).
- **Threshold Tiers:** `monitor=0.05`, `challenge=0.50`, `block=0.90` (low-FPR blocking), `strict_block=0.50`.
- **Request Constraints:** `max_request_size_bytes=65536` (64 KB limit), `allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]`.
- **Path Exclusions:** Excludes `/healthcheck`, `/health`, `/ready` from ML evaluation.
- **Explicit ML Failure Mode:** Configurable per tenant as `"fail_open"` or `"fail_closed"`.

### 3.2 Pooled ML API Client (`src/firewall/ml_client.py`)
- Employs a shared `httpx.Client` with HTTP keep-alive connection pooling (`max_keepalive=20`, `max_connections=50`).
- Granular microsecond timeouts prevent worker blocking:
  - Connect timeout: $100\text{ ms}$
  - Read timeout: $250\text{ ms}$
  - Pool acquisition timeout: $500\text{ ms}$
- Built-in `in_process_engine` adapter allows running hermetic unit and integration tests without network socket dependencies.
- Explicit failure domain categorization: `"timeout"`, `"connection_refused"`, `"service_unready"`, and `"invalid_response"`.

### 3.3 Multi-Layer Decision Engine (`src/firewall/decision_engine.py`)

#### Pipeline Execution Sequence:
```
Incoming Request
       │
       ▼
Request Validation (Size & Method Constraints)
       │
       ▼
Layer 1 Deterministic Rules Engine (Short-circuits if attack matched)
       │
       ▼
Path Exclusions Check (Bypasses ML if exempt endpoint)
       │
       ▼
Layer 4 Behavioral Anomaly Evaluation (Calculates client burst/scan score)
       │
       ▼
Layer 2/3 ML Service Call (Fast-Pass TF-IDF -> Deep Transformer)
       │
       ▼
Central Decision Engine Signal Fusion & Policy Enforcement
       │
       ▼
Structured WAFDecision (ALLOW · BLOCK · MONITOR · CHALLENGE)
```

#### Multi-Signal Fusion Matrix:
| Trigger / Signal Condition | Inspection Mode | `action` | `would_action` | `reason` |
| :--- | :---: | :---: | :---: | :--- |
| `policy.inspection_mode == "disabled"` | Any | `ALLOW` | `ALLOW` | `INSPECTION_DISABLED` |
| Request size $> 64\text{ KB}$ | `blocking` / `strict` | `BLOCK` | `BLOCK` | `REQUEST_SIZE_LIMIT_EXCEEDED` |
| Request size $> 64\text{ KB}$ | `monitor` | `MONITOR` | `BLOCK` | `REQUEST_SIZE_LIMIT_EXCEEDED` |
| Disallowed HTTP Method | `blocking` / `strict` | `BLOCK` | `BLOCK` | `DISALLOWED_HTTP_METHOD_{M}` |
| Layer 1 Critical Rule Violation | `blocking` / `strict` | `BLOCK` | `BLOCK` | `LAYER1_RULE_{RULE_ID}` |
| Layer 1 Critical Rule Violation | `monitor` | `MONITOR` | `BLOCK` | `LAYER1_RULE_{RULE_ID}` |
| Path Excluded (e.g. `/healthcheck`) | Any | `ALLOW` | `ALLOW` | `PATH_EXCLUDED_FROM_ML` |
| ML Fast-Pass ($\text{score} \le 0.04$, clean L4) | Any | `ALLOW` | `ALLOW` | `FAST_PASS_CLEAN` |
| ML Score $\ge 0.90$ | `blocking` | `BLOCK` | `BLOCK` | `ML_THRESHOLD_EXCEEDED` |
| ML Score in $[0.50, 0.90)$, clean L4 | `blocking` | `CHALLENGE` | `CHALLENGE` | `ML_CHALLENGE_BAND` |
| ML Score in $[0.50, 0.90)$ + Active L4 Anomaly | `blocking` | `BLOCK` | `BLOCK` | `ML_AND_ANOMALY_ESCALATION` |
| ML Score in $[0.05, 0.50)$ | `blocking` | `MONITOR` | `MONITOR` | `ML_MONITOR_ALERT` |
| ML Score $\ge 0.50$ | `strict` | `BLOCK` | `BLOCK` | `STRICT_ML_BLOCK` |
| Any Attack ($\ge 0.05$ or Layer 1 rule) | `monitor` | `MONITOR` | `BLOCK`/`CHAL` | (Records true trigger) |
| Clean Traffic ($< 0.05$, clean L4) | Any | `ALLOW` | `ALLOW` | `CLEAN_REQUEST` |
| ML Outage + `fail_open` | `blocking` / `strict` | `ALLOW` | `ALLOW` | `ML_UNAVAILABLE_FAIL_OPEN` (`degraded_mode=True`) |
| ML Outage + `fail_closed` | `blocking` / `strict` | `BLOCK` | `BLOCK` | `ML_UNAVAILABLE_FAIL_CLOSED` (`degraded_mode=True`) |
| ML Outage + Active L4 Anomaly | `blocking` / `strict` | `CHALLENGE` | `CHALLENGE` | `ML_DEGRADED_ANOMALY_ACTIVE` (`degraded_mode=True`) |

---

## 4. Standardized Output Schema (`WAFDecision`)

All decisions return a structured, privacy-safe JSON schema compliant with the Master Plan:

```json
{
  "request_id": "req_50a5b0c51faf",
  "tenant_id": "default",
  "site_id": "default",
  "action": "MONITOR",
  "would_action": "BLOCK",
  "reason": "ML_THRESHOLD_EXCEEDED",
  "risk_score": 0.9842,
  "stage_used": "transformer",
  "rule_matches": [],
  "anomaly_flags": [],
  "degraded_mode": false,
  "model_version": "v1.0.0",
  "policy_version": "1.0.0",
  "inspection_mode": "monitor",
  "latency_ms": 9.38,
  "details": {}
}
```

---

## 5. Test Suite Verification & Quality Sign-Off

The entire WAF testing harness was validated with 100% pass rates:

1. **`tests/test_ml_inference_service.py`**: **17/17 PASSED** (includes tamper, exception safety, and CPU-fallback tests).
2. **`tests/test_waf_core.py`**: **17/17 PASSED** (includes policy constraints, rules short-circuiting, ML+anomaly fusion, challenge escalation, degraded mode, and failure handling).
3. **`src/evaluation/test_evaluation_pipeline.py`**: **11/11 PASSED** (verifies frozen SHA-256 hashes and 0-group leakage).
4. **`src/firewall/validate_firewall.py`**: **100% PASSED** (all 4 layers and central decision engine verified).

```
Total PyTest Execution: 34 passed in 11.93s
```

Phase 6 is formally complete and ready for integration with upstream proxies in subsequent phases.
