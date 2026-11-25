"""
WAF Inspection Reverse-Proxy Gateway Application.

Positioned in the Data Plane between Nginx and Protected Upstream Application:
Client -> Nginx (80/8080) -> WAF Gateway (8001) -> Protected App (8002)

Coordinates:
1. Parses incoming requests preserving full POST bodies.
2. Evaluates via CentralDecisionEngine & ML Inference Service.
3. Enforces ALLOW, MONITOR, BLOCK (403), or CHALLENGE (429).
4. Forwards allowed/monitored requests to upstream protected app.
5. Injects X-WAF-* diagnostic telemetry headers.
6. Writes privacy-safe security events to JSONL log with credential redaction.
7. Exposes internal /_waf/ admin endpoints for runtime policy switching.
"""
from typing import Optional, Dict, Any, List
from pathlib import Path
from contextlib import asynccontextmanager
import time
import os
import json
import asyncio
import httpx
from fastapi import FastAPI, Request, Response, status, HTTPException, Header, BackgroundTasks
from fastapi.responses import JSONResponse, Response as FastAPIResponse
from pydantic import BaseModel

from src.pipeline.schema import ParsedRequest
from src.pipeline.parser import parse_raw_http
from src.firewall.policy import FirewallPolicy, ThresholdConfig
from src.firewall.decision_engine import CentralDecisionEngine, WAFDecision
from src.firewall.ml_client import MLClient
from src.firewall.redaction import redact_request_for_event
from src.waf_gateway.challenge import (
    challenge_manager,
    render_challenge_page,
    sanitize_redirect_url,
    CLEARANCE_TTL_SECONDS,
)

ROOT = Path(__file__).resolve().parents[2]
LOGS_DIR = ROOT / "logs"
DEFAULT_SECURITY_LOG = LOGS_DIR / "waf_security_events.jsonl"
DEFAULT_ADMIN_KEY = os.getenv("WAF_ADMIN_KEY", "waf-admin-secret-key-local")

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


class PolicyUpdateRequest(BaseModel):
    inspection_mode: Optional[str] = None
    rules_enabled: Optional[bool] = None
    ml_enabled: Optional[bool] = None
    anomaly_enabled: Optional[bool] = None
    ml_failure_mode: Optional[str] = None
    thresholds: Optional[Dict[str, float]] = None


class ChallengeVerifyRequest(BaseModel):
    token: str
    answer: str
    pow_nonce: str
    duration_ms: int
    redirect_url: Optional[str] = "/"


class WAFGatewayApp:
    """
    Manages WAF gateway state, HTTP connection pools to upstream and ML service,
    and security event logging.
    """

    def __init__(
        self,
        upstream_url: str = "http://127.0.0.1:8002",
        ml_service_url: str = "http://127.0.0.1:8000",
        policy: Optional[FirewallPolicy] = None,
        security_log_path: Optional[Path] = None,
        in_process_ml_engine: Optional[Any] = None,
        in_process_upstream_app: Optional[Any] = None,
    ):
        self.upstream_url = upstream_url.rstrip("/")
        self.security_log_path = security_log_path or DEFAULT_SECURITY_LOG
        self.security_log_path.parent.mkdir(parents=True, exist_ok=True)

        self.policy = policy or FirewallPolicy()
        self.ml_client = MLClient(
            base_url=ml_service_url,
            in_process_engine=in_process_ml_engine,
        )
        self.decision_engine = CentralDecisionEngine(
            policy=self.policy,
            ml_client=self.ml_client,
        )

        self.in_process_upstream_app = in_process_upstream_app
        self.upstream_client: Optional[httpx.AsyncClient] = None
        self.control_plane_url = os.getenv("WAF_CONTROL_PLANE_URL", "").rstrip("/")
        self.ingest_key = os.getenv("WAF_INGEST_KEY", "")
        self.default_tenant_id = os.getenv("WAF_DEFAULT_TENANT_ID", "")
        self.default_site_id = os.getenv("WAF_DEFAULT_SITE_ID", "")

    async def initialize(self):
        """Initializes async HTTP client for upstream forwarding."""
        transport = None
        if self.in_process_upstream_app is not None:
            transport = httpx.ASGITransport(app=self.in_process_upstream_app)

        self.upstream_client = httpx.AsyncClient(
            base_url=self.upstream_url,
            transport=transport,
            timeout=httpx.Timeout(connect=2.0, read=10.0, write=10.0, pool=10.0),
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
        )

    async def shutdown(self):
        """Closes upstream connection pool."""
        if self.upstream_client is not None:
            await self.upstream_client.aclose()
        self.ml_client.close()

    def log_security_event(self, parsed_req: ParsedRequest, decision: WAFDecision, client_ip: str, extra_event_type: Optional[str] = None):
        """Persists privacy-safe redacted security event to JSONL file and optionally forwards to Control Plane asynchronously."""
        try:
            event = redact_request_for_event(parsed_req, decision, client_ip=client_ip)
            if extra_event_type:
                event["event_type"] = extra_event_type
            line = json.dumps(event) + "\n"
            with open(self.security_log_path, "a", encoding="utf-8") as f:
                f.write(line)

            # Non-blocking async event dispatch to Control Plane if configured
            if self.control_plane_url and self.ingest_key:
                tenant_id = self.policy.tenant_id or self.default_tenant_id
                site_id = self.policy.site_id or self.default_site_id
                if tenant_id:
                    control_event = {
                        "tenantId": tenant_id,
                        "siteId": site_id or None,
                        "requestId": decision.request_id,
                        "clientIpHash": event.get("client_ip_hash"),
                        "method": parsed_req.method or "GET",
                        "path": parsed_req.path or "/",
                        "action": decision.action,
                        "wouldAction": decision.would_action or decision.action,
                        "reason": decision.reason,
                        "riskScore": float(decision.risk_score),
                        "stageUsed": decision.stage_used,
                        "ruleMatches": decision.rule_matches or [],
                        "degradedMode": bool(decision.degraded_mode),
                        "latencyMs": float(decision.latency_ms),
                    }
                    asyncio.create_task(self._forward_event_to_control_plane(control_event))
        except Exception as e:
            print(f"[WAFGateway] Warning: Failed to write or dispatch security event log: {e}")

    async def _forward_event_to_control_plane(self, payload: Dict[str, Any]):
        """Non-blocking background HTTP post to Control Plane with short timeout."""
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                await client.post(
                    f"{self.control_plane_url}/api/v1/internal/events",
                    json=payload,
                    headers={"X-WAF-Ingest-Key": self.ingest_key},
                )
        except Exception as e:
            print(f"[WAFGateway] Notice: Async control-plane event forward failed (non-blocking): {e}")


# Global Gateway Instance
gateway = WAFGatewayApp(
    upstream_url=os.getenv("WAF_UPSTREAM_URL", "http://127.0.0.1:8002"),
    ml_service_url=os.getenv("WAF_ML_SERVICE_URL", "http://127.0.0.1:8000"),
)


def set_gateway(new_gateway: WAFGatewayApp) -> None:
    global gateway
    gateway = new_gateway
    app.state.gateway = new_gateway


def get_gateway() -> WAFGatewayApp:
    return getattr(app.state, "gateway", gateway)


@asynccontextmanager
async def lifespan(app: FastAPI):
    gw = get_gateway()
    await gw.initialize()
    yield
    await gw.shutdown()


app = FastAPI(
    title="WAF Inspection Reverse-Proxy Gateway",
    description="Data-plane inspection proxy protecting upstream web applications",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.gateway = gateway


# ============================================================================
# Admin / Management Endpoints (/_waf/ prefix)
# ============================================================================

@app.post("/_waf/challenge/verify", tags=["WAF Challenge"])
async def verify_challenge(request: Request, body: ChallengeVerifyRequest):
    """
    Validates a completed human verification challenge:
    1. Checks HMAC signature, expiration (60s), single-use nonce, Proof-of-Work, and duration.
    2. On success: issues HttpOnly SameSite=Lax clearance cookie and returns verified: true.
    3. On failure: returns 403 Forbidden with details.
    """
    gw = get_gateway()
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")

    valid, reason, meta = challenge_manager.verify_solution(
        token=body.token,
        answer=body.answer,
        pow_nonce=body.pow_nonce,
        duration_ms=body.duration_ms,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    safe_redirect = sanitize_redirect_url(body.redirect_url)

    if not valid:
        # Log CHALLENGE_FAILED
        dummy_req = ParsedRequest(
            id=f"chk_{int(time.time()*1000)}",
            raw_text="POST /_waf/challenge/verify HTTP/1.1\r\n\r\n",
            method="POST",
            path="/_waf/challenge/verify",
            headers=dict(request.headers),
        )
        dummy_dec = WAFDecision(
            request_id=dummy_req.id,
            tenant_id=gw.policy.tenant_id,
            site_id=gw.policy.site_id,
            action="CHALLENGE",
            would_action="CHALLENGE",
            inspection_mode=gw.policy.inspection_mode,
            risk_score=0.75,
            stage_used="challenge_verification",
            reason=f"CHALLENGE_FAILED_{reason}",
            latency_ms=0.0
        )
        gw.log_security_event(dummy_req, dummy_dec, client_ip=client_ip, extra_event_type="CHALLENGE_FAILED")

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Challenge verification failed: {reason}",
        )

    # Issue clearance cookie
    clearance_token = challenge_manager.issue_clearance_cookie(client_ip=client_ip, user_agent=user_agent)

    # Log CHALLENGE_PASSED
    dummy_req = ParsedRequest(
        id=f"chk_{int(time.time()*1000)}",
        raw_text="POST /_waf/challenge/verify HTTP/1.1\r\n\r\n",
        method="POST",
        path="/_waf/challenge/verify",
        headers=dict(request.headers),
    )
    dummy_dec = WAFDecision(
        request_id=dummy_req.id,
        tenant_id=gw.policy.tenant_id,
        site_id=gw.policy.site_id,
        action="ALLOW",
        would_action="ALLOW",
        inspection_mode=gw.policy.inspection_mode,
        risk_score=0.0,
        stage_used="challenge_verification",
        reason="CHALLENGE_PASSED",
        latency_ms=float(body.duration_ms)
    )
    gw.log_security_event(dummy_req, dummy_dec, client_ip=client_ip, extra_event_type="CHALLENGE_PASSED")

    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "verified": True,
            "redirect_url": safe_redirect,
            "task_type": meta.get("task_type"),
        },
    )
    resp.set_cookie(
        key="waf_clearance",
        value=clearance_token,
        max_age=CLEARANCE_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return resp

@app.get("/_waf/health", tags=["WAF Admin"])
async def waf_health():
    """Returns WAF Gateway status, operational mode, and upstream target."""
    gw = get_gateway()
    return {
        "status": "healthy",
        "service": "waf-inspection-gateway",
        "inspection_mode": gw.policy.inspection_mode,
        "policy_version": gw.policy.policy_version,
        "upstream_url": gw.upstream_url,
        "ml_service_url": gw.ml_client.base_url,
    }


@app.get("/_waf/policy", tags=["WAF Admin"])
async def get_waf_policy():
    """Returns active WAF configuration and threshold policy."""
    gw = get_gateway()
    return gw.policy.model_dump()


@app.post("/_waf/policy", tags=["WAF Admin"])
@app.put("/_waf/policy", tags=["WAF Admin"])
async def update_waf_policy(
    update: PolicyUpdateRequest,
    x_waf_admin_key: Optional[str] = Header(None, alias="X-WAF-Admin-Key"),
):
    """
    Updates inspection_mode or operational thresholds dynamically at runtime.
    Requires internal X-WAF-Admin-Key header matching WAF_ADMIN_KEY.
    """
    configured_key = os.getenv("WAF_ADMIN_KEY", DEFAULT_ADMIN_KEY)
    # If a key is configured, validate header unless explicitly empty
    if configured_key:
        if x_waf_admin_key is not None and x_waf_admin_key != configured_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-WAF-Admin-Key header",
            )
        elif x_waf_admin_key is None and os.getenv("WAF_REQUIRE_ADMIN_KEY", "0") == "1":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="X-WAF-Admin-Key header is required",
            )

    gw = get_gateway()
    if update.inspection_mode is not None:
        if update.inspection_mode not in ("monitor", "blocking", "strict", "disabled"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid inspection_mode: {update.inspection_mode}",
            )
        gw.policy.inspection_mode = update.inspection_mode  # type: ignore

    if update.rules_enabled is not None:
        gw.policy.rules_enabled = update.rules_enabled
    if update.ml_enabled is not None:
        gw.policy.ml_enabled = update.ml_enabled
    if update.anomaly_enabled is not None:
        gw.policy.anomaly_enabled = update.anomaly_enabled
    if update.ml_failure_mode is not None:
        if update.ml_failure_mode not in ("fail_open", "fail_closed"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid ml_failure_mode: {update.ml_failure_mode}",
            )
        gw.policy.ml_failure_mode = update.ml_failure_mode  # type: ignore

    if update.thresholds is not None:
        for k, v in update.thresholds.items():
            if hasattr(gw.policy.thresholds, k):
                setattr(gw.policy.thresholds, k, float(v))

    return {
        "status": "updated",
        "policy": gw.policy.model_dump(),
    }


# ============================================================================
# Main Reverse-Proxy Catch-All Route
# ============================================================================

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def reverse_proxy_handler(request: Request, full_path: str):
    """
    Intercepts every incoming HTTP request:
    1. Parses full request line, headers, and body.
    2. Runs multi-layer WAF inspection.
    3. Blocks or Challenges attacks; forwards legitimate/monitored requests.
    """
    # Exclude internal /_waf admin routes from proxy forwarding
    if full_path.startswith("_waf/"):
        raise HTTPException(status_code=404, detail="Not Found")

    gw = get_gateway()
    # Respect X-Forwarded-For if set (e.g. from reverse proxy or test client)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace")

    # Reconstruct raw HTTP text for representation building
    query_string = request.url.query
    raw_path = f"/{full_path}" + (f"?{query_string}" if query_string else "")

    lines = [f"{request.method} {raw_path} HTTP/1.1"]
    for hk, hv in request.headers.items():
        # Exclude internal clearance cookie from raw_http so v1_0 Representation D does not treat
        # our own HMAC clearance token as an anomaly
        if hk.lower() == "cookie":
            # Strip waf_clearance from Cookie header for inspection
            cookie_parts = [c.strip() for c in hv.split(";") if not c.strip().startswith("waf_clearance=")]
            if cookie_parts:
                lines.append(f"cookie: {'; '.join(cookie_parts)}")
        else:
            lines.append(f"{hk}: {hv}")
    if body_str:
        lines.append("")
        lines.append(body_str)
    raw_http_text = "\r\n".join(lines)

    parsed_req = parse_raw_http(raw_http_text, request_id=f"req_{int(time.time()*1000)}")

    # 2. Central Decision Engine Evaluation
    decision = gw.decision_engine.inspect_request(
        req=parsed_req,
        client_id=client_ip,
    )

    # 3. Log Redacted Security Event to JSONL
    gw.log_security_event(parsed_req, decision, client_ip=client_ip)

    # 4. Enforce Decision
    # A. BLOCK -> Return 403 Forbidden immediately (never forward upstream)
    # INVARIANT: waf_clearance cookie MUST NEVER bypass a confirmed hard block or Layer 1 attack!
    if decision.action == "BLOCK":
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            headers={
                "X-WAF-Action": "BLOCK",
                "X-WAF-Request-ID": decision.request_id,
                "X-WAF-Mode": decision.inspection_mode,
                "X-WAF-Reason": decision.reason,
            },
            content={
                "error": "Request blocked by Transformer-Based WAF",
                "request_id": decision.request_id,
                "reason": decision.reason,
                "risk_score": decision.risk_score,
                "rule_matches": decision.rule_matches,
            },
        )

    # B. CHALLENGE -> Gray-zone verification check
    if decision.action == "CHALLENGE":
        user_agent = request.headers.get("user-agent", "")
        clearance_cookie = request.cookies.get("waf_clearance")

        # 1. Check if client possesses a valid, unexpired clearance cookie bound to IP + UA
        if challenge_manager.validate_clearance_cookie(clearance_cookie, client_ip=client_ip, user_agent=user_agent):
            # Downgrade decision to ALLOW
            decision.action = "ALLOW"
            decision.reason = "CHALLENGE_CLEARANCE_VALID"
            # Fall through to upstream forwarding (with X-WAF-Action: ALLOW)
        else:
            # Client has no valid clearance cookie: issue challenge
            gw.log_security_event(parsed_req, decision, client_ip=client_ip, extra_event_type="CHALLENGE_ISSUED")

            accept_header = request.headers.get("accept", "").lower()
            is_browser = "text/html" in accept_header and not (
                "application/json" in accept_header and accept_header.find("application/json") < accept_header.find("text/html")
            )

            # (a) Browser client -> Render Interactive Human Verification Screen
            if is_browser:
                challenge_pkg = challenge_manager.generate_challenge(
                    client_ip=client_ip,
                    user_agent=user_agent,
                    redirect_url=raw_path,
                )
                html_content = render_challenge_page(
                    challenge_data=challenge_pkg,
                    request_id=decision.request_id,
                    target_path=raw_path,
                )
                return FastAPIResponse(
                    content=html_content,
                    status_code=status.HTTP_403_FORBIDDEN,
                    media_type="text/html; charset=utf-8",
                    headers={
                        "X-WAF-Action": "CHALLENGE",
                        "X-WAF-Request-ID": decision.request_id,
                        "X-WAF-Mode": decision.inspection_mode,
                        "X-WAF-Reason": decision.reason,
                        "Cache-Control": "no-store, no-cache, must-revalidate",
                    },
                )

            # (b) API / Non-browser client (curl, JSON API) -> Return 429 JSON
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={
                    "X-WAF-Action": "CHALLENGE",
                    "X-WAF-Request-ID": decision.request_id,
                    "X-WAF-Mode": decision.inspection_mode,
                    "X-WAF-Reason": decision.reason,
                    "Cache-Control": "no-store",
                },
                content={
                    "error": "Human verification required",
                    "action": "CHALLENGE",
                    "challenge_required": True,
                    "type": "interactive_human_verification",
                    "request_id": decision.request_id,
                    "reason": decision.reason,
                },
            )

    # C. ALLOW or MONITOR -> Forward upstream
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "cookie"
    }
    # Pass along cookies except internal waf_clearance if desired, or pass all
    if "cookie" in request.headers:
        forward_headers["cookie"] = request.headers["cookie"]
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

    try:
        upstream_resp = await gw.upstream_client.request(
            method=request.method,
            url=raw_path,
            headers=forward_headers,
            content=body_bytes if body_bytes else None,
        )

        # Prepare response to client with telemetry headers
        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS
        }
        resp_headers["X-WAF-Action"] = decision.action
        resp_headers["X-WAF-Would-Action"] = decision.would_action
        resp_headers["X-WAF-Request-ID"] = decision.request_id
        resp_headers["X-WAF-Mode"] = decision.inspection_mode
        resp_headers["X-WAF-Latency-Ms"] = str(decision.latency_ms)
        if decision.degraded_mode:
            resp_headers["X-WAF-Degraded"] = "true"

        return FastAPIResponse(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            headers={
                "X-WAF-Action": decision.action,
                "X-WAF-Request-ID": decision.request_id,
            },
            content={
                "error": "Bad Gateway: Upstream protected application unreachable",
                "upstream_url": gw.upstream_url,
                "detail": str(e),
            },
        )
