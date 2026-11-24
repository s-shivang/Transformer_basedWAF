# Phase 5 — Python + FastAPI ML Inference Service Engineering Report

**Date:** 2026-11-24  
**Project:** Transformer-Based End-to-End Web Application Firewall (WAF)  
**Hardware Environment:** NVIDIA GeForce RTX 2050 (4GB VRAM, sm_86, CUDA 12.4), Intel Core i5 Host, Windows 11  
**Cloud Budget:** \$0.00 (Strictly Local Execution)  
**Architecture Context:** Modular Monolith with Domain-Driven Design (DDD)  

---

## 1. Executive Summary

Phase 5 delivers a standalone, high-performance **Python + FastAPI ML Inference Service** (`src/ml_service/`) providing non-blocking HTTP endpoints for 2-stage cascaded WAF scoring. The service strictly decouples ML compute from future SaaS business logic (NestJS, PostgreSQL, Redis, billing, multitenancy) in accordance with the DDD Modular Monolith architecture.

All operational thresholds, representation configurations, and Platt scaling parameters are loaded dynamically at runtime from the frozen model directory (`models/frozen/v1_0/`), eliminating hardcoded constants from application code. Startup is protected by cryptographic SHA-256 verification against `model_manifest.json`, ensuring immediate `/ready` probe failure if any model artifact is modified, corrupted, or missing.

A comprehensive PyTest suite (`tests/test_ml_inference_service.py`) verified 100% of service specifications (14/14 tests passing), including exact mathematical score parity ($\le 10^{-5}$) against the offline pipeline, thread-safe concurrency (20 parallel requests without CUDA OOM), and sub-5 ms fast-pass latency ($p50 = 2.94\text{ ms}$).

---

## 2. Configuration Hygiene & Frozen Artifact Verification

In accordance with Phase 4 audit recommendations, the frozen directory `models/frozen/v1_0/` was finalized with machine-readable, schema-compliant JSON configuration files:

1. **`threshold.json`**:
   - `fast_pass_allow`: $0.04$
   - `monitor_alert`: $0.05$
   - `block`: $0.50$
   - `strict_block_low_fpr`: $0.90$
   - `platt_calibration`: $w = 0.7724, b = 0.4965$ ($ECE = 0.0048$, $Brier = 0.01109$)
2. **`preprocessing_config.json`**:
   - `representation_mode`: `"structured"` (Representation D)
   - `max_length`: $192$
   - `special_structural_tokens`: `["[METHOD]", "[PATH]", "[PARAM]", "[PAYLOAD]", "[HEADERS]"]`
   - `canonicalizer_settings`: depth 2, NFKC unicode normalization, obfuscation flag tracking.
3. **`model_manifest.json`**:
   - Updated with live SHA-256 digests of all 7 frozen files.
   - Verified 11/11 tests passing in `src/evaluation/test_evaluation_pipeline.py`.

---

## 3. Architecture & Service Components

```
src/ml_service/
├── __init__.py            # Exports app, container, ModelContainer, InferenceEngine
├── schemas.py             # Pydantic v2 schemas: PredictRequest, PredictResponse, Probes, Metadata
├── model_loader.py        # ModelContainer: SHA-256 startup verification, GPU FP16/CPU loader, warmup
├── inference_engine.py    # InferenceEngine: parsing, Rep D assembly, 2-Stage Cascade, Platt scaling
└── app.py                 # FastAPI application with lifespan handler and custom error handlers
```

### 3.1 Startup Lifecycle & ModelContainer
- **Integrity Validation:** Iterates through every artifact in `model_manifest.json`. If any file digest does not match, startup fails and `/ready` returns HTTP 503.
- **Dynamic Configuration:** Ingests `threshold.json` and `preprocessing_config.json` without hardcoded constants.
- **Hardware Acceleration:** Deploys Layer 3 Transformer on CUDA (`half()` precision) with automatic CPU fallback. Layer 2 TF-IDF runs on CPU.
- **Warmup Execution:** Issues dummy forward passes through both TF-IDF and Transformer during ASGI lifespan initialization, eliminating cold-start latency spikes.

### 3.2 2-Stage Cascade Inference Pipeline
1. **Safety Envelopes & Validation:**
   - Payloads $> 64\text{ KB}$ ($65,536\text{ bytes}$) are rejected with HTTP 422 Unprocessable Entity.
   - Empty requests (whitespace only or missing actionable content) return HTTP 400 Bad Request.
   - Malformed raw HTTP requests return HTTP 400 Bad Request without unhandled 500 crashes.
2. **Representation D Parity:**
   - Both raw HTTP strings and structured decomposed fields (`method`, `path`, `query_params`, `headers`, `body`) are parsed using `src/pipeline/parser.py` and canonicalized via `src/pipeline/canonicalizer.py`.
   - Structural features are generated using `build_features(parsed_req, representation="structured")`.
3. **Truncation Detection:**
   - Token count is inspected against `max_length = 192`. If the token length exceeds 192, `truncated = True` is flagged in the response.
4. **Stage 1 (Microsecond TF-IDF Triage):**
   - If $p_{\text{tfidf}} \le 0.04$, request is classified as `prediction="benign"`, `recommended_tier="fast_pass_allow"`, `stage_used="fast_pass_tfidf"`. Response returns in $\approx 2.9\text{ ms}$.
5. **Stage 2 (Transformer Forward Pass & Platt Calibration):**
   - Requests with $p_{\text{tfidf}} > 0.04$ escalate to the Transformer.
   - Raw softmax output $p_{\text{raw}}$ is mapped through Platt calibration:
     $$\text{logit} = \ln\left(\frac{p_{\text{raw}}}{1 - p_{\text{raw}}}\right), \quad p_{\text{cal}} = \frac{1}{1 + e^{-(0.7724 \cdot \text{logit} + 0.4965)}}$$
   - Decision tier assigned:
     - $p_{\text{cal}} \ge \tau_{\text{block}}$ ($0.50$, or `threshold_override`) $\implies$ `"block"`, `"malicious"`
     - $p_{\text{cal}} \ge \tau_{\text{monitor}}$ ($0.05$) $\implies$ `"monitor_alert"`, `"malicious"`
     - $p_{\text{cal}} < \tau_{\text{monitor}}$ ($0.05$) $\implies$ `"allow"`, `"benign"`

---

## 4. REST API Endpoint Specifications

| Endpoint | Method | Status | Description |
| :--- | :---: | :---: | :--- |
| `/health` | `GET` | 200 | Liveness probe: returns `{"status": "healthy", "service": "waf-ml-inference"}` |
| `/ready` | `GET` | 200 / 503 | Readiness probe: checks model readiness & SHA-256 verification |
| `/v1/model-info` | `GET` | 200 | Returns model version, device, representation mode, thresholds, calibration params |
| `/v1/predict` | `POST` | 200 / 400 / 422 | Main inference endpoint returning structured `PredictResponse` |

---

## 5. Test Suite & Verification Results

The test suite in `tests/test_ml_inference_service.py` was executed using PyTest across all 8 required categories:

| Test Name | Category | Status | Verified Outcome |
| :--- | :--- | :---: | :--- |
| `test_health_endpoint` | Observability | **PASS** | HTTP 200, healthy status |
| `test_ready_endpoint_success` | Observability | **PASS** | HTTP 200, `ready=True`, `sha256_verified=True` |
| `test_ready_endpoint_unready` | Observability | **PASS** | HTTP 503 when model unready |
| `test_model_info_endpoint` | Metadata | **PASS** | Correct metadata, `max_length=192`, thresholds |
| `test_benign_traffic_fast_pass` | Cascade Triage | **PASS** | Benign request triggers `fast_pass_tfidf` ($\le 0.04$) |
| `test_sqli_attack_detection` | Attack Detection | **PASS** | SQLi escalated to Transformer, `tier="block"` ($p \ge 0.50$) |
| `test_xss_attack_detection` | Attack Detection | **PASS** | XSS escalated to Transformer, `tier="block"` ($p \ge 0.50$) |
| `test_score_parity_with_offline` | Numerical Parity | **PASS** | $\Delta \le 10^{-5}$ mathematical match against offline pipeline |
| `test_malformed_raw_http` | Error Handling | **PASS** | HTTP 400 without crashing service |
| `test_empty_input` | Error Handling | **PASS** | HTTP 400 for empty payload |
| `test_oversized_payload` | Error Handling | **PASS** | HTTP 422 for payload $> 64\text{ KB}$ |
| `test_truncation_detection` | Token Limits | **PASS** | Flags `truncated=True` when $> 192$ tokens |
| `test_concurrent_requests` | Concurrency | **PASS** | 20 parallel requests succeed with 200 OK, zero OOM |
| `test_latency_benchmark` | Performance | **PASS** | 100 sequential requests evaluated |

### Latency Benchmark (100 Sequential Requests)
- **Layer 2 Fast-Pass (50 requests):**
  - **p50 Latency:** $2.94\text{ ms}$ (Target: $< 5.0\text{ ms}$ — **MET**)
  - **p95 Latency:** $3.70\text{ ms}$
- **Layer 3 Transformer (50 requests):**
  - **p50 Latency:** $9.16\text{ ms}$ (Sub-10 ms GPU execution)
  - **p95 Latency:** $11.91\text{ ms}$

### Regression Test Suite Status
- `src/evaluation/test_evaluation_pipeline.py`: **11/11 PASSED** (8.51s)
- `src/firewall/validate_firewall.py`: **100% PASSED** (All 4 layers verified)
- `tests/test_ml_inference_service.py`: **14/14 PASSED** (10.19s)

---

## 6. Phase 5 Sign-off

With Phase 5 complete:
1. Frozen artifact configuration hygiene is finalized and cryptographically verified.
2. The independent Python + FastAPI ML Inference Service is implemented, fully tested, and ready to be consumed by upstream reverse proxies or gateway services.
3. The codebase adheres strictly to the DDD Modular Monolith boundary, preserving local RTX 2050 execution with $0 cloud spend.
