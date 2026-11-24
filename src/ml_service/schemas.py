"""
Pydantic v2 Schemas for WAF ML Inference Service.
"""
from typing import Optional, Dict, Any, List, Union, Literal
from pydantic import BaseModel, Field, model_validator


class PredictRequest(BaseModel):
    request_id: Optional[str] = Field(
        default=None,
        description="Optional unique tracking identifier for the request. Auto-generated if omitted."
    )
    raw_http: Optional[str] = Field(
        default=None,
        description="Raw full HTTP request string (e.g., 'GET /path?arg=1 HTTP/1.1\\r\\nHost: ...')"
    )
    method: Optional[str] = Field(
        default=None,
        description="HTTP Method (GET, POST, etc.) when submitting decomposed fields."
    )
    path: Optional[str] = Field(
        default=None,
        description="URL Path (e.g., '/api/v1/search')."
    )
    query_params: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Query parameters key-value dictionary."
    )
    headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="HTTP Headers dictionary."
    )
    body: Optional[str] = Field(
        default=None,
        description="Request body content string."
    )
    threshold_override: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional runtime block threshold override in range [0.0, 1.0]."
    )




class PredictResponse(BaseModel):
    request_id: str
    prediction: Literal["benign", "malicious"]
    recommended_tier: Literal["fast_pass_allow", "allow", "monitor_alert", "block"]
    malicious_probability: float = Field(ge=0.0, le=1.0)
    raw_probability: float = Field(ge=0.0, le=1.0)
    stage_used: Literal["fast_pass_tfidf", "transformer"]
    threshold: float
    model_version: str
    truncated: bool
    latency_ms: float
    status: str = "ok"


class HealthResponse(BaseModel):
    status: str = "healthy"
    service: str = "waf-ml-inference"


class ReadyResponse(BaseModel):
    ready: bool
    model_version: str
    device: str
    sha256_verified: bool
    details: Optional[Dict[str, Any]] = None


class ModelInfoResponse(BaseModel):
    model_version: str
    device: str
    representation_mode: str
    max_length: int
    thresholds: Dict[str, float]
    calibration_policy: Dict[str, Any]
    sha256_verified: bool
    artifacts: Dict[str, str]

