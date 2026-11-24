"""
FastAPI Application for WAF ML Inference Service.

Provides high-performance, non-blocking HTTP endpoints for model inference,
liveness/readiness probes, and active model metadata.
"""
from typing import Dict, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from src.ml_service.schemas import (
    PredictRequest,
    PredictResponse,
    HealthResponse,
    ReadyResponse,
    ModelInfoResponse,
)
from src.ml_service.model_loader import container
from src.ml_service.inference_engine import InferenceEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup & shutdown lifespan event handler.
    Initializes models, verifies cryptographic SHA-256 hashes, and runs warmup.
    """
    try:
        container.initialize()
    except Exception as e:
        print(f"[Lifespan] Error during model initialization: {e}")
    yield


app = FastAPI(
    title="Transformer WAF ML Inference Service",
    description="High-performance, 2-Stage Cascade ML inference service for Web Application Firewall",
    version="1.0.0",
    lifespan=lifespan,
)

engine = InferenceEngine(container)


# Custom Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "status_code": exc.status_code,
            "detail": exc.detail,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "validation_error",
            "status_code": 422,
            "detail": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "status_code": 500,
            "detail": "Internal server error occurred.",
            "error": str(exc),
        },
    )


# Endpoints
@app.get("/health", response_model=HealthResponse, tags=["Observability"])
async def health_check():
    """Liveness probe: returns 200 immediately if service process is alive."""
    return HealthResponse(status="healthy", service="waf-ml-inference")


@app.get("/ready", tags=["Observability"])
async def ready_check():
    """
    Readiness probe: returns 200 if models are loaded and verified, 503 if not ready.
    """
    if not container.is_ready or not container.sha256_verified:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=ReadyResponse(
                ready=False,
                model_version=container.model_version,
                device=container.device,
                sha256_verified=container.sha256_verified,
                details={"error": "Models not loaded or SHA-256 verification incomplete."},
            ).model_dump(),
        )

    return ReadyResponse(
        ready=True,
        model_version=container.model_version,
        device=container.device,
        sha256_verified=True,
        details={
            "model_name": container.manifest.get("model_name"),
            "architecture": container.manifest.get("architecture"),
        },
    )


@app.get("/v1/model-info", response_model=ModelInfoResponse, tags=["Metadata"])
async def model_info():
    """Returns active model metadata, thresholds, and calibration configuration."""
    if not container.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model container is not ready.",
        )

    thresholds_dict = {
        "fast_pass_allow": float(container.thresholds.get("fast_pass_allow", 0.04)),
        "monitor_alert": float(container.thresholds.get("monitor_alert", 0.05)),
        "block": float(container.thresholds.get("block", 0.50)),
        "strict_block_low_fpr": float(container.thresholds.get("strict_block_low_fpr", 0.90)),
    }

    return ModelInfoResponse(
        model_version=container.model_version,
        device=container.device,
        representation_mode=container.preprocessing_cfg.get("representation_mode", "structured"),
        max_length=container.max_length,
        thresholds=thresholds_dict,
        calibration_policy=container.thresholds.get("platt_calibration", {}),
        sha256_verified=container.sha256_verified,
        artifacts=container.manifest.get("artifacts_sha256", {}),
    )


@app.post("/v1/predict", response_model=PredictResponse, tags=["Inference"])
async def predict_request(req: PredictRequest):
    """
    Evaluates an incoming HTTP request via 2-Stage Cascade:
    1. Microsecond Tier 1 Fast-Pass TF-IDF triage on CPU.
    2. Deep Tier 2 Contextual Transformer forward pass on GPU/CPU.
    3. Platt scaling calibration and tier assignment.
    """
    return engine.predict(req)
