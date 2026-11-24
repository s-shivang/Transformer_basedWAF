"""
Privacy-Safe Sensitive Data Redaction Module for WAF Security Events.

Ensures credentials, session tokens, authorization headers, and personal data
are stripped or replaced with '[REDACTED]' before persisting security logs.
"""
from typing import Dict, Any, List, Set, Union
from datetime import datetime, timezone
import re
import uuid

from src.pipeline.schema import ParsedRequest
from src.firewall.decision_engine import WAFDecision

REDACTED_STR = "[REDACTED]"

# Headers containing credentials or session identifiers
SENSITIVE_HEADERS: Set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
    "x-auth-token",
    "x-csrf-token",
}

# Parameter keys carrying secrets, credentials, or PII
SENSITIVE_PARAM_KEYS: Set[str] = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "auth",
    "api_key",
    "apikey",
    "credit_card",
    "creditcard",
    "cc_num",
    "cvv",
    "ssn",
}

# Regex patterns for sanitizing secrets in raw text strings
RE_SENSITIVE_HEADER = re.compile(
    r"(?i)\b(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-API-Key|API-Key|X-Auth-Token|X-CSRF-Token)\s*:\s*([^\r\n]+)",
)
RE_JSON_SECRET = re.compile(
    r'(?i)("(\w*?(password|passwd|pwd|secret|token|api_key|apikey|auth|credit_card)\w*)"\s*:\s*)"([^"\\]*)"',
)
RE_JSON_NUM_SECRET = re.compile(
    r'(?i)("(\w*?(password|passwd|pwd|secret|token|api_key|apikey|auth|cvv|credit_card)\w*)"\s*:\s*)([0-9]+)',
)
RE_FORM_SECRET = re.compile(
    r'(?i)\b((\w*?(password|passwd|pwd|secret|token|api_key|apikey|auth)\w*)\s*=\s*)([^\s&;]+)',
)
RE_COLON_SECRET = re.compile(
    r'(?i)\b((\w*?(password|passwd|pwd|secret|token|api_key|apikey|auth)\w*)\s*:\s*)([^\s\r\n,]+)',
)


def redact_dictionary(data: Dict[str, Any], sensitive_keys: Set[str]) -> Dict[str, Any]:
    """Recursively redacts values for keys matching sensitive keywords."""
    redacted = {}
    for k, v in data.items():
        k_lower = str(k).lower().strip()
        if k_lower in sensitive_keys or any(s in k_lower for s in ("password", "secret", "token", "apikey")):
            redacted[k] = REDACTED_STR
        elif isinstance(v, dict):
            redacted[k] = redact_dictionary(v, sensitive_keys)
        elif isinstance(v, list):
            redacted[k] = [
                redact_dictionary(item, sensitive_keys) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            redacted[k] = v
    return redacted


def redact_raw_text(raw_text: str) -> str:
    """Sanitizes raw HTTP string replacing authorization headers, cookies, API keys, JSON, and form secrets."""
    if not raw_text:
        return ""
    text = RE_SENSITIVE_HEADER.sub(r"\1: " + REDACTED_STR, raw_text)
    text = RE_JSON_SECRET.sub(r'\1"[REDACTED]"', text)
    text = RE_JSON_NUM_SECRET.sub(r'\1"[REDACTED]"', text)
    text = RE_FORM_SECRET.sub(r'\1[REDACTED]', text)
    text = RE_COLON_SECRET.sub(r'\1[REDACTED]', text)
    return text


def redact_request_for_event(
    req: ParsedRequest,
    decision: WAFDecision,
    client_ip: str = "127.0.0.1",
) -> Dict[str, Any]:
    """
    Constructs a privacy-safe, serialized security event dictionary.
    Replaces all sensitive headers, query parameters, and body values.
    """
    # 1. Redact headers
    redacted_headers = {}
    for hk, hv in req.headers.items():
        if hk.lower() in SENSITIVE_HEADERS:
            redacted_headers[hk] = REDACTED_STR
        else:
            redacted_headers[hk] = hv

    # 2. Redact query params
    redacted_query = redact_dictionary(dict(req.query_params), SENSITIVE_PARAM_KEYS)

    # 3. Redact body params
    redacted_body_params = {}
    if isinstance(req.body_params, dict):
        redacted_body_params = redact_dictionary(req.body_params, SENSITIVE_PARAM_KEYS)

    # 4. Redact raw text
    sanitized_raw = redact_raw_text(req.raw_text)

    # Construct standard Master Plan security event
    return {
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": decision.request_id,
        "tenant_id": decision.tenant_id,
        "site_id": decision.site_id,
        "action": decision.action,
        "would_action": decision.would_action,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "stage_used": decision.stage_used,
        "rule_matches": decision.rule_matches,
        "anomaly_flags": decision.anomaly_flags,
        "degraded_mode": decision.degraded_mode,
        "model_version": decision.model_version,
        "policy_version": decision.policy_version,
        "inspection_mode": decision.inspection_mode,
        "latency_ms": decision.latency_ms,
        "client_ip": client_ip,
        "request": {
            "method": req.method,
            "path": req.path,
            "query_params": redacted_query,
            "headers": redacted_headers,
            "body_params": redacted_body_params,
            "raw_text": sanitized_raw,
        },
    }
