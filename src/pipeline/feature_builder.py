from typing import Dict, List, Any
from src.pipeline.schema import ParsedRequest


def build_representation_a(req: ParsedRequest) -> str:
    """
    Representation A: Full raw request string (Baseline approach).
    """
    return req.raw_text


def build_representation_b(req: ParsedRequest) -> str:
    """
    Representation B: Target + Payload.
    Combines HTTP method, normalized path, query string, and body payload values,
    excluding static headers (Host, User-Agent, Accept, etc.).
    """
    query_parts = []
    for k, v in req.query_params.items():
        if isinstance(v, list):
            for item in v:
                query_parts.append(f"{k}={item}")
        else:
            query_parts.append(f"{k}={v}")
    
    query_str = "?" + "&".join(query_parts) if query_parts else ""
    target = f"{req.method} {req.path}{query_str}"

    body_parts = []
    if isinstance(req.body_params, dict):
        for k, v in req.body_params.items():
            if not k.startswith("_"):
                body_parts.append(f"{k}={v}")
            else:
                body_parts.append(str(v))

    body_str = " ".join(body_parts) if body_parts else ""
    if body_str:
        return f"{target}\n{body_str}".strip()
    return target.strip()


def build_representation_c(req: ParsedRequest) -> str:
    """
    Representation C: Canonical Payloads Only.
    Extracts strictly the canonicalized parameter and body values,
    isolating user input from application endpoints and routing.
    """
    if req.canonical_payloads:
        return " ".join(str(p) for p in req.canonical_payloads if p)
    # If no parameters, fall back to empty or clean path
    return ""


def build_representation_d(req: ParsedRequest) -> str:
    """
    Representation D: Structured Serialization.
    Standardized structural sequence format:
    [METHOD] {method} [PATH] {path} [PARAM] {param_key}={val} [PAYLOAD] {payloads} [HEADERS] {ua_and_cookie}
    """
    parts = [f"[METHOD] {req.method}", f"[PATH] {req.path}"]

    # Add parameters
    all_params = []
    for k, v in req.query_params.items():
        if isinstance(v, list):
            for item in v:
                all_params.append(f"{k}={item}")
        else:
            all_params.append(f"{k}={v}")

    if isinstance(req.body_params, dict):
        for k, v in req.body_params.items():
            if not k.startswith("_"):
                all_params.append(f"{k}={v}")

    if all_params:
        parts.append(f"[PARAM] {' '.join(all_params)}")

    # Add canonical payloads
    if req.canonical_payloads:
        payload_str = " ".join(str(p) for p in req.canonical_payloads if p)
        if payload_str:
            parts.append(f"[PAYLOAD] {payload_str}")

    # Add security-relevant headers only (User-Agent, Cookie) if present
    sec_headers = []
    for hk in ("user-agent", "cookie", "referer"):
        if hk in req.headers:
            sec_headers.append(f"{hk}={req.headers[hk]}")

    if sec_headers:
        parts.append(f"[HEADERS] {' '.join(sec_headers)}")

    return " ".join(parts)


def build_features(req: ParsedRequest, representation: str = "structured") -> str:
    """
    Main dispatch function for building feature text from a ParsedRequest.
    Options: 'raw', 'target_payload', 'payload_only', 'structured'
    """
    rep = representation.lower()
    if rep in ("raw", "full_request", "a"):
        return build_representation_a(req)
    elif rep in ("target_payload", "target", "b"):
        return build_representation_b(req)
    elif rep in ("payload_only", "payload", "c"):
        return build_representation_c(req)
    elif rep in ("structured", "d"):
        return build_representation_d(req)
    else:
        raise ValueError(f"Unknown representation: {representation}. Expected 'a', 'b', 'c', or 'd'.")

