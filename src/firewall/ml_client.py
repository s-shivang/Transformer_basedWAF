"""
Pooled ML API Client for WAF Core.

Provides high-throughput connection-pooled communication to the Phase 5
FastAPI ML Inference Service (/v1/predict) with granular timeouts, in-process
testing adapters, and explicit failure domain categorization.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
import time
import socket
from urllib.parse import urlparse
import httpx

from src.ml_service.schemas import PredictRequest, PredictResponse
from src.ml_service.inference_engine import InferenceEngine


@dataclass
class MLClientResult:
    """Standardized response from ML Inference Client."""
    success: bool
    failure_domain: Optional[str] = None  # 'timeout', 'connection_refused', 'service_unready', 'invalid_response'
    error_message: Optional[str] = None
    risk_score: float = 0.0               # Calibrated probability
    raw_probability: float = 0.0          # Pre-calibration probability
    stage_used: str = "unknown"           # 'fast_pass_tfidf', 'transformer', 'in_process'
    recommended_tier: str = "allow"       # 'fast_pass_allow', 'allow', 'monitor_alert', 'block'
    model_version: str = "unknown"
    truncated: bool = False
    latency_ms: float = 0.0


class MLClient:
    """
    Client connecting WAF Core to the FastAPI ML Inference Service.
    Supports connection pooling with granular microsecond timeouts,
    as well as in-process execution for hermetic testing.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        connect_timeout_ms: float = 100.0,
        read_timeout_ms: float = 250.0,
        pool_timeout_ms: float = 500.0,
        in_process_engine: Optional[InferenceEngine] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.in_process_engine = in_process_engine

        # Granular timeouts: connect, read, write, pool
        self.timeout = httpx.Timeout(
            connect=connect_timeout_ms / 1000.0,
            read=read_timeout_ms / 1000.0,
            write=read_timeout_ms / 1000.0,
            pool=pool_timeout_ms / 1000.0,
        )
        self.limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=30.0,
        )

        self._client: Optional[httpx.Client] = None
        self._hostname: Optional[str] = None
        self._cached_ip: Optional[str] = None
        self._port_str: str = ""
        self._scheme: str = "http"

        if self.in_process_engine is None:
            effective_base_url = self.base_url
            headers = {}
            try:
                parsed = urlparse(self.base_url)
                self._scheme = parsed.scheme or "http"
                self._hostname = parsed.hostname
                self._port_str = f":{parsed.port}" if parsed.port else ""
                if self._hostname and not all(c.isdigit() or c == "." for c in self._hostname):
                    self._cached_ip = socket.gethostbyname(self._hostname)
                    effective_base_url = f"{self._scheme}://{self._cached_ip}{self._port_str}"
                    headers["Host"] = parsed.netloc
            except Exception:
                effective_base_url = self.base_url

            self._client = httpx.Client(
                base_url=effective_base_url,
                headers=headers if headers else None,
                timeout=self.timeout,
                limits=self.limits,
            )

    def _try_refresh_ip(self):
        """Attempts to re-resolve hostname if container was restarted with a new IP."""
        if not self._hostname or all(c.isdigit() or c == "." for c in self._hostname):
            return
        try:
            new_ip = socket.gethostbyname(self._hostname)
            if new_ip != self._cached_ip:
                self._cached_ip = new_ip
                effective_base_url = f"{self._scheme}://{new_ip}{self._port_str}"
                old_client = self._client
                self._client = httpx.Client(
                    base_url=effective_base_url,
                    headers={"Host": f"{self._hostname}{self._port_str}"},
                    timeout=self.timeout,
                    limits=self.limits,
                )
                if old_client:
                    try:
                        old_client.close()
                    except Exception:
                        pass
        except Exception:
            pass

    def close(self):
        """Closes the underlying HTTP connection pool."""
        if self._client is not None:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def predict(
        self,
        raw_http: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        query_params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        threshold_override: Optional[float] = None,
        request_id: Optional[str] = None,
    ) -> MLClientResult:
        """
        Sends prediction request to ML Inference Service.
        Categorizes failures into explicit domains (timeout, connection_refused,
        service_unready, invalid_response) without crashing or silent drops.
        """
        t0 = time.perf_counter()

        # In-process adapter bypass
        if self.in_process_engine is not None:
            try:
                req = PredictRequest(
                    request_id=request_id,
                    raw_http=raw_http,
                    method=method,
                    path=path,
                    query_params=query_params,
                    headers=headers,
                    body=body,
                    threshold_override=threshold_override,
                )
                resp: PredictResponse = self.in_process_engine.predict(req)
                latency = (time.perf_counter() - t0) * 1000.0
                return MLClientResult(
                    success=True,
                    risk_score=resp.malicious_probability,
                    raw_probability=resp.raw_probability,
                    stage_used=resp.stage_used,
                    recommended_tier=resp.recommended_tier,
                    model_version=resp.model_version,
                    truncated=resp.truncated,
                    latency_ms=round(latency, 3),
                )
            except Exception as e:
                latency = (time.perf_counter() - t0) * 1000.0
                return MLClientResult(
                    success=False,
                    failure_domain="invalid_response",
                    error_message=f"In-process inference error: {str(e)}",
                    latency_ms=round(latency, 3),
                )

        # Remote / Network HTTP Client path
        payload = {}
        if request_id:
            payload["request_id"] = request_id
        if raw_http is not None:
            payload["raw_http"] = raw_http
        if method:
            payload["method"] = method
        if path:
            payload["path"] = path
        if query_params:
            payload["query_params"] = query_params
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body
        if threshold_override is not None:
            payload["threshold_override"] = threshold_override

        try:
            resp = self._client.post("/v1/predict", json=payload)
            latency = (time.perf_counter() - t0) * 1000.0

            if resp.status_code == 200:
                data = resp.json()
                return MLClientResult(
                    success=True,
                    risk_score=float(data.get("malicious_probability", 0.0)),
                    raw_probability=float(data.get("raw_probability", 0.0)),
                    stage_used=data.get("stage_used", "unknown"),
                    recommended_tier=data.get("recommended_tier", "allow"),
                    model_version=data.get("model_version", "unknown"),
                    truncated=bool(data.get("truncated", False)),
                    latency_ms=round(latency, 3),
                )
            elif resp.status_code == 503:
                return MLClientResult(
                    success=False,
                    failure_domain="service_unready",
                    error_message=f"ML Service returned HTTP 503: {resp.text}",
                    latency_ms=round(latency, 3),
                )
            else:
                return MLClientResult(
                    success=False,
                    failure_domain="invalid_response",
                    error_message=f"ML Service returned HTTP {resp.status_code}: {resp.text}",
                    latency_ms=round(latency, 3),
                )

        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout) as e:
            self._try_refresh_ip()
            latency = (time.perf_counter() - t0) * 1000.0
            return MLClientResult(
                success=False,
                failure_domain="timeout",
                error_message=f"ML request timed out: {type(e).__name__} ({str(e)})",
                latency_ms=round(latency, 3),
            )
        except (httpx.ConnectError, httpx.NetworkError) as e:
            self._try_refresh_ip()
            latency = (time.perf_counter() - t0) * 1000.0
            return MLClientResult(
                success=False,
                failure_domain="connection_refused",
                error_message=f"Failed to connect to ML service: {str(e)}",
                latency_ms=round(latency, 3),
            )
        except Exception as e:
            latency = (time.perf_counter() - t0) * 1000.0
            return MLClientResult(
                success=False,
                failure_domain="invalid_response",
                error_message=f"Unexpected client error: {str(e)}",
                latency_ms=round(latency, 3),
            )
