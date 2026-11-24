import json
import re
from typing import Dict, List, Any
from src.pipeline.schema import ParsedRequest


SUSPICIOUS_HEADER_PATTERNS = re.compile(
    r"(?:"
    r"union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|<script|javascript:|onerror=|onload="
    r"|\.\./|\.\.\\|%2e%2e|/etc/passwd|/bin/sh|169\.254\.\d+\.\d+|localhost|127\.0\.0\.1"
    r"|\{\{.*\}\}|\$\{.*\}|system\(|exec\(|eval\(|`|--|\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|\bAND\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?"
    r"|\$ne|\$gt|\$where|<svg|<img"
    r")",
    re.IGNORECASE,
)

NOISY_HEADERS = {
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "accept-charset",
    "connection",
    "keep-alive",
    "cache-control",
    "referer",
    "upgrade-insecure-requests",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
    "host",
    "pragma",
    "dnt",
    "cookie",
}


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


def build_representation_d(req: ParsedRequest, mask_path: bool = False) -> str:
    """
    Representation D: Structured Serialization (v1.0 format).
    Standardized structural sequence format:
    [METHOD] {method} [PATH] {path} [PARAM] {param_key}={val} [PAYLOAD] {payloads} [HEADERS] {ua_and_cookie}

    If mask_path is True, replaces specific endpoint paths with a standardized abstraction
    to prevent the model from memorizing endpoint-specific routing tokens.
    """
    display_path = "/__APP_ENDPOINT__" if mask_path else req.path
    parts = [f"[METHOD] {req.method}", f"[PATH] {display_path}"]

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

    # Add security-relevant headers only (User-Agent, Cookie, Referer) if present
    sec_headers = []
    for hk in ("user-agent", "cookie", "referer"):
        if hk in req.headers:
            sec_headers.append(f"{hk}={req.headers[hk]}")

    if sec_headers:
        parts.append(f"[HEADERS] {' '.join(sec_headers)}")

    return " ".join(parts)


def build_representation_d_v2(req: ParsedRequest, mask_path: bool = False) -> str:
    """
    Representation D-v2: Structured Serialization with Header Stripping & Payload Prioritization (v2.0 format).
    - Strips low-value, noisy headers (User-Agent, Accept, Accept-Language, Connection, Referer, Cookie)
      unless they match an explicit suspicious attack pattern.
    - Prioritizes security-relevant structure: [METHOD], [PATH], [PARAM], [PAYLOAD], and compact Content-Type.
    - Frees token capacity for payload analysis and eliminates cross-domain header overfitting.
    """
    display_path = "/__APP_ENDPOINT__" if mask_path else req.path
    parts = [f"[METHOD] {req.method}", f"[PATH] {display_path}"]

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

    # Add security-relevant headers: compact Content-Type or suspicious headers
    retained_headers = []

    # 1. Compact Content-Type
    if "content-type" in req.headers:
        ct = req.headers["content-type"].split(";")[0].strip().lower()
        if ct:
            retained_headers.append(f"content-type={ct}")

    # 2. Any header with explicit suspicious attack pattern
    for hk, hv in req.headers.items():
        hk_lower = hk.lower()
        if hk_lower == "content-type":
            continue
        hv_str = str(hv)
        if SUSPICIOUS_HEADER_PATTERNS.search(hv_str) or SUSPICIOUS_HEADER_PATTERNS.search(hk_lower):
            retained_headers.append(f"{hk_lower}={hv_str}")
        elif hk_lower not in NOISY_HEADERS and len(hv_str) < 100:
            retained_headers.append(f"{hk_lower}={hv_str}")

    if retained_headers:
        parts.append(f"[HEADERS] {' '.join(retained_headers)}")

    return " ".join(parts)


SAFE_ROUTING_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9]{1,5})?$")
PATH_ATTACK_KEYWORDS = {
    "etc", "passwd", "win.ini", "cmd", "shell", "admin",
    "config", ".env", ".git", "script", "select", "union"
}
BENIGN_EXTENSIONS = {
    "jsp", "php", "html", "htm", "json", "asp", "aspx",
    "xml", "txt", "do", "action", "cgi"
}


def normalize_path_smart(path: str) -> str:
    """
    Smart Path Normalization for Representation D-v2-Norm:
    - Splits path by '/'.
    - If a segment contains ONLY safe routing characters and no attack keywords,
      normalizes to '__SEG__' (or '__FILE__.ext' for benign file extensions).
    - If a segment contains special/encoded/traversal chars (.., %, ', <, >, ;, $, etc.)
      or attack keywords, preserves the raw segment intact.
    - Example: '/tienda1/publico/anadir.jsp' -> '/__SEG__/__SEG__/__FILE__.jsp'
    - Example: '/files/../../etc/passwd'     -> '/__SEG__/../../etc/passwd'
    """
    if not path or path == "/":
        return path or "/"

    segments = path.split("/")
    norm_segs = []
    for seg in segments:
        if not seg:
            norm_segs.append("")
            continue

        seg_lower = seg.lower()
        # If segment contains attack keyword or special/traversal chars, keep raw
        if any(kw in seg_lower for kw in PATH_ATTACK_KEYWORDS) or not SAFE_ROUTING_RE.match(seg):
            norm_segs.append(seg)
        else:
            if "." in seg:
                name, ext = seg.rsplit(".", 1)
                ext_l = ext.lower()
                if ext_l in BENIGN_EXTENSIONS:
                    norm_segs.append(f"__FILE__.{ext_l}")
                else:
                    norm_segs.append("__SEG__")
            else:
                norm_segs.append("__SEG__")

    return "/".join(norm_segs)


def build_representation_d_v2_norm(req: ParsedRequest, mask_path: bool = False) -> str:
    """
    Representation D-v2-Norm: Structured Serialization with Header Stripping,
    Payload Prioritization, and Smart Path Normalization (v2.1 format).
    - Normalizes safe routing segments to '__SEG__' / '__FILE__.ext' to eliminate
      path memorization while 100% preserving traversal attacks and sensitive targets.
    - Strips low-value noisy headers while retaining suspicious attack patterns.
    """
    norm_path = "/__APP_ENDPOINT__" if mask_path else normalize_path_smart(req.path)
    parts = [f"[METHOD] {req.method}", f"[PATH] {norm_path}"]

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

    # Add security-relevant headers: compact Content-Type or suspicious headers
    retained_headers = []

    # 1. Compact Content-Type
    if "content-type" in req.headers:
        ct = req.headers["content-type"].split(";")[0].strip().lower()
        if ct:
            retained_headers.append(f"content-type={ct}")

    # 2. Any header with explicit suspicious attack pattern
    for hk, hv in req.headers.items():
        hk_lower = hk.lower()
        if hk_lower == "content-type":
            continue
        hv_str = str(hv)
        if SUSPICIOUS_HEADER_PATTERNS.search(hv_str) or SUSPICIOUS_HEADER_PATTERNS.search(hk_lower):
            retained_headers.append(f"{hk_lower}={hv_str}")
        elif hk_lower not in NOISY_HEADERS and len(hv_str) < 100:
            retained_headers.append(f"{hk_lower}={hv_str}")

    if retained_headers:
        parts.append(f"[HEADERS] {' '.join(retained_headers)}")

    return " ".join(parts)


SAFE_PARAM_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,40}$")
INJECTION_KEY_CHARS = {"'", '"', '<', '>', ';', '|', '$', '{', '}', '..', '%', '(', ')', ' '}


def is_safe_param_key(key: str) -> bool:
    """
    Returns True if parameter key matches safe identifier regex AND
    does not contain injection/NoSQL operators.
    Safe keys (e.g., ciudad, precio, B1, item[0]) -> True.
    Attack keys (e.g., $ne, $gt, ' OR 1=1, <script>, ../) -> False.
    """
    if not key or not isinstance(key, str):
        return False
    if not SAFE_PARAM_KEY_RE.match(key):
        return False
    if any(ch in key for ch in INJECTION_KEY_CHARS):
        return False
    return True


def normalize_json_keys(obj: Any, counter: List[int]) -> Any:
    """Recursively replaces safe dictionary keys with P1, P2... while keeping injection keys ($ne, $gt, etc.) intact."""
    if isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            if is_safe_param_key(str(k)):
                new_key = f"P{counter[0]}"
                counter[0] += 1
            else:
                new_key = str(k)
            new_dict[new_key] = normalize_json_keys(v, counter)
        return new_dict
    elif isinstance(obj, list):
        return [normalize_json_keys(item, counter) for item in obj]
    else:
        return obj


def build_representation_d_v2_2(req: ParsedRequest, mask_path: bool = False) -> str:
    """
    Representation D-v2.2: Structured Serialization with Smart Path Normalization,
    Smart Parameter-Key Normalization, and Header Stripping.
    - Normalizes safe routing segments to '__SEG__' / '__FILE__.ext'.
    - Normalizes safe query, form, and JSON parameter keys to positional 'P1', 'P2'...
      eliminating parameter-name overfitting across domains and languages, while
      leaving parameter values 100% untouched.
    - Preserves parameter keys containing injection/NoSQL characters ($ne, $gt, quotes, scripts).
    - Preserves path traversal (..) and attack targets.
    """
    norm_path = "/__APP_ENDPOINT__" if mask_path else normalize_path_smart(req.path)
    parts = [f"[METHOD] {req.method}", f"[PATH] {norm_path}"]

    all_params = []
    p_counter = [1]

    # 1. Query Parameters
    for k, v in req.query_params.items():
        if isinstance(v, list):
            for item in v:
                k_norm = f"P{p_counter[0]}" if is_safe_param_key(k) else k
                p_counter[0] += 1
                all_params.append(f"{k_norm}={item}")
        else:
            k_norm = f"P{p_counter[0]}" if is_safe_param_key(k) else k
            p_counter[0] += 1
            all_params.append(f"{k_norm}={v}")

    # 2. Body Parameters
    if isinstance(req.body_params, dict):
        if "_raw" in req.body_params or "_json_raw" in req.body_params:
            raw_body = req.body_params.get("_json_raw") or req.body_params.get("_raw")
            try:
                data = json.loads(raw_body)
                norm_json = normalize_json_keys(data, p_counter)
                all_params.append(json.dumps(norm_json, separators=(",", ":")))
            except Exception:
                pass
        else:
            for k, v in req.body_params.items():
                if not k.startswith("_"):
                    if isinstance(v, (dict, list)):
                        norm_v = normalize_json_keys(v, p_counter)
                        k_norm = f"P{p_counter[0]}" if is_safe_param_key(k) else k
                        p_counter[0] += 1
                        all_params.append(f"{k_norm}={json.dumps(norm_v, separators=(',', ':'))}")
                    else:
                        k_norm = f"P{p_counter[0]}" if is_safe_param_key(k) else k
                        p_counter[0] += 1
                        all_params.append(f"{k_norm}={v}")

    if all_params:
        parts.append(f"[PARAM] {' '.join(all_params)}")

    # 3. Canonical Payloads
    if req.canonical_payloads:
        payload_str = " ".join(str(p) for p in req.canonical_payloads if p)
        if payload_str:
            parts.append(f"[PAYLOAD] {payload_str}")

    # 4. Security-relevant Headers
    retained_headers = []
    if "content-type" in req.headers:
        ct = req.headers["content-type"].split(";")[0].strip().lower()
        if ct:
            retained_headers.append(f"content-type={ct}")

    for hk, hv in req.headers.items():
        hk_lower = hk.lower()
        if hk_lower == "content-type":
            continue
        hv_str = str(hv)
        if SUSPICIOUS_HEADER_PATTERNS.search(hv_str) or SUSPICIOUS_HEADER_PATTERNS.search(hk_lower):
            retained_headers.append(f"{hk_lower}={hv_str}")
        elif hk_lower not in NOISY_HEADERS and len(hv_str) < 100:
            retained_headers.append(f"{hk_lower}={hv_str}")

    if retained_headers:
        parts.append(f"[HEADERS] {' '.join(retained_headers)}")

    return " ".join(parts)


def build_features(req: ParsedRequest, representation: str = "structured") -> str:
    """
    Main dispatch function for building feature text from a ParsedRequest.
    Options: 'raw', 'target_payload', 'payload_only', 'structured', 'structured_masked',
             'structured_v2', 'structured_v2_masked', 'structured_v2_norm', 'structured_v2_2'
    """
    rep = representation.lower()
    if rep in ("raw", "full_request", "a"):
        return build_representation_a(req)
    elif rep in ("target_payload", "target", "b"):
        return build_representation_b(req)
    elif rep in ("payload_only", "payload", "c"):
        return build_representation_c(req)
    elif rep in ("structured", "d"):
        return build_representation_d(req, mask_path=False)
    elif rep in ("structured_masked", "d_masked", "masked"):
        return build_representation_d(req, mask_path=True)
    elif rep in ("structured_v2", "d_v2", "d2", "v2"):
        return build_representation_d_v2(req, mask_path=False)
    elif rep in ("structured_v2_masked", "d_v2_masked", "v2_masked"):
        return build_representation_d_v2(req, mask_path=True)
    elif rep in ("structured_v2_norm", "d_v2_norm", "v2_norm", "v2_1", "v2.1", "structured_v2.1"):
        return build_representation_d_v2_norm(req, mask_path=False)
    elif rep in ("structured_v2_2", "d_v2_2", "v2_2", "v2.2", "structured_v2.2"):
        return build_representation_d_v2_2(req, mask_path=False)
    elif rep in ("structured_v2_2_masked", "d_v2_2_masked", "v2_2_masked"):
        return build_representation_d_v2_2(req, mask_path=True)
    else:
        raise ValueError(
            f"Unknown representation: {representation}. Expected 'a', 'b', 'c', 'd', 'structured_v2', 'structured_v2_norm', 'structured_v2_2', etc."
        )

