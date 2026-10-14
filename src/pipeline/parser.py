import json
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Union

from src.pipeline.schema import ParsedRequest
from src.pipeline.canonicalizer import (
    canonicalize_value,
    canonicalize_path,
    inspect_encoding_flags,
)

REQUEST_LINE_PATTERN = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/\d\.\d)?",
    re.IGNORECASE,
)


def parse_query_string(query_str: str) -> Dict[str, Union[str, List[str]]]:
    """Parse query string into key-value dictionary, preserving values."""
    if not query_str:
        return {}
    parsed = urllib.parse.parse_qs(query_str, keep_blank_values=True)
    # Simplify single-item lists to strings
    result = {}
    for k, v in parsed.items():
        if len(v) == 1:
            result[k] = v[0]
        else:
            result[k] = v
    return result


def parse_body_content(
    body: str, content_type: str = ""
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Parse body content based on Content-Type header.
    Returns (body_params_dict, extracted_payload_values).
    """
    body = body.strip()
    if not body:
        return {}, []

    extracted_values = []
    body_params = {}

    content_type_lower = content_type.lower()
    if "application/json" in content_type_lower:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                body_params = data
                def extract_json_vals(obj):
                    if isinstance(obj, dict):
                        for v in obj.values():
                            extract_json_vals(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            extract_json_vals(item)
                    elif obj is not None:
                        extracted_values.append(str(obj))
                extract_json_vals(data)
            else:
                body_params = {"_json_raw": body}
                extracted_values.append(body)
        except Exception:
            body_params = {"_raw": body}
            extracted_values.append(body)
    elif "application/x-www-form-urlencoded" in content_type_lower or ("=" in body and not body.startswith("<")):
        parsed = parse_query_string(body)
        body_params = parsed
        for v in parsed.values():
            if isinstance(v, list):
                extracted_values.extend([str(item) for item in v])
            else:
                extracted_values.append(str(v))
    else:
        # Raw or XML/text payload
        body_params = {"_raw": body}
        extracted_values.append(body)

    return body_params, extracted_values


def parse_raw_http(
    raw_text: str,
    request_id: str = "",
    label: Optional[int] = None,
    source: str = "",
    split: Optional[str] = None,
) -> ParsedRequest:
    """
    Adapter for raw HTTP text (e.g., CSIC 2010 or AI WAF text).
    Accurately separates boundaries: Method, Path, Headers, Body, and Query Params.
    """
    text = str(raw_text).replace("\r\n", "\n")
    lines = text.split("\n")

    method = "GET"
    raw_path_and_query = "/"
    headers: Dict[str, str] = {}
    body_lines: List[str] = []

    in_headers = True
    first_line_parsed = False

    for line in lines:
        if not first_line_parsed:
            match = REQUEST_LINE_PATTERN.match(line.strip())
            if match:
                method = match.group(1).upper()
                raw_path_and_query = match.group(2)
                first_line_parsed = True
                continue
            elif line.strip() == "":
                continue

        if in_headers:
            if line.strip() == "":
                in_headers = False
                continue
            if ":" in line:
                header_name, header_val = line.split(":", 1)
                headers[header_name.strip().lower()] = header_val.strip()
            else:
                # Malformed header line or transition to body
                in_headers = False
                body_lines.append(line)
        else:
            body_lines.append(line)

    raw_body = "\n".join(body_lines).strip()

    # Split Path and Query String
    if "?" in raw_path_and_query:
        raw_path, query_str = raw_path_and_query.split("?", 1)
    else:
        raw_path, query_str = raw_path_and_query, ""

    # Canonicalize path
    canonical_path, path_flags = canonicalize_path(raw_path)

    # Parse query parameters
    query_params = parse_query_string(query_str)

    # Parse body
    content_type = headers.get("content-type", "")
    body_params, body_payload_values = parse_body_content(raw_body, content_type)

    # Aggregate canonical payloads
    canonical_payloads = []
    combined_flags = dict(path_flags)

    # Add query param values
    for qk, qv in query_params.items():
        vals = qv if isinstance(qv, list) else [qv]
        for val in vals:
            c_val, flags = canonicalize_value(val, decode_html=True)
            canonical_payloads.append(c_val)
            for fk, fv in flags.items():
                if fv:
                    combined_flags[fk] = True

    # Add body values
    for val in body_payload_values:
        c_val, flags = canonicalize_value(val, decode_html=True)
        canonical_payloads.append(c_val)
        for fk, fv in flags.items():
            if fv:
                combined_flags[fk] = True

    return ParsedRequest(
        id=request_id,
        raw_text=raw_text,
        method=method,
        path=canonical_path,
        query_params=query_params,
        body_params=body_params,
        headers=headers,
        canonical_payloads=canonical_payloads,
        encoding_flags=combined_flags,
        label=label,
        source=source,
        split=split,
    )

