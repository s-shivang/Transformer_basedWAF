import html
import re
import unicodedata
import urllib.parse
from typing import Dict, Tuple, List, Any


PERCENT_HEX = re.compile(r"%[0-9a-fA-F]{2}")
HTML_ENTITY = re.compile(r"&(?:[a-zA-Z0-9]+|#[0-9]{1,6}|#[xX][0-9a-fA-F]{1,6});")
NULL_BYTE = re.compile(r"(\x00|%00|\\0)")


def inspect_encoding_flags(text: str) -> Dict[str, bool]:
    """
    Detect suspicious encoding patterns without erasing the forensic signal.
    """
    s = str(text)
    has_pct = bool(PERCENT_HEX.search(s))
    has_null = bool(NULL_BYTE.search(s))
    has_html = bool(HTML_ENTITY.search(s))
    has_non_ascii = any(ord(c) > 127 for c in s)

    # Check for potential double encoding: e.g. %2527 or %25xx
    has_double = bool(re.search(r"%25[0-9a-fA-F]{2}", s, re.IGNORECASE))

    return {
        "has_url_encoding": has_pct,
        "has_double_encoding": has_double,
        "has_null_bytes": has_null,
        "has_html_entities": has_html,
        "has_non_ascii": has_non_ascii,
    }


def bounded_url_decode(val: str, max_depth: int = 2) -> Tuple[str, bool]:
    """
    Carefully decode percent-encoded strings with a bounded depth (default 2 passes).
    Returns (decoded_string, is_double_encoded).
    Does NOT destroy case or whitespace.
    """
    curr = str(val)
    is_double_encoded = False

    for depth in range(max_depth):
        decoded = urllib.parse.unquote(curr)
        if decoded == curr:
            break
        if depth == 1:
            is_double_encoded = True
        curr = decoded

    return curr, is_double_encoded


def normalize_unicode(val: str) -> str:
    """
    Apply Unicode NFKC normalization (turns fullwidth/compatibility characters 
    into standard representations, preventing unicode evasion).
    """
    return unicodedata.normalize("NFKC", str(val))


def canonicalize_value(
    val: str,
    decode_html: bool = False,
    strip_null: bool = True,
    preserve_case: bool = True,
) -> Tuple[str, Dict[str, bool]]:
    """
    Field-aware canonicalization of a single parameter or payload value:
    - Analyzes encoding indicators
    - Performs bounded URL unquoting (up to 2 passes)
    - Optionally decodes HTML entities (e.g. for body or query parameters where relevant)
    - Applies Unicode NFKC normalization
    - Strips or retains null bytes while recording flags
    - Preserves case by default (essential for SQL/JS/Unix payloads)
    """
    raw = str(val)
    flags = inspect_encoding_flags(raw)

    # 1. Bounded URL decoding
    decoded, double_enc = bounded_url_decode(raw, max_depth=2)
    if double_enc:
        flags["has_double_encoding"] = True

    # 2. Selective HTML entity decoding
    if decode_html and flags["has_html_entities"]:
        decoded = html.unescape(decoded)

    # 3. Unicode NFKC normalization
    normalized = normalize_unicode(decoded)

    # 4. Handle null bytes safely
    if strip_null and "\x00" in normalized:
        normalized = normalized.replace("\x00", "")

    if not preserve_case:
        normalized = normalized.lower()

    return normalized, flags


def canonicalize_path(path: str) -> Tuple[str, Dict[str, bool]]:
    """
    Canonicalize an HTTP path:
    - Bounded URL decode
    - Unicode normalization
    - Keep case (paths in Unix systems are case-sensitive)
    """
    flags = inspect_encoding_flags(path)
    decoded, double_enc = bounded_url_decode(path, max_depth=2)
    if double_enc:
        flags["has_double_encoding"] = True

    normalized = normalize_unicode(decoded)

    # If the target is an absolute URI (e.g. http://localhost:8080/path), extract the path component
    if normalized.lower().startswith(("http://", "https://")):
        parsed_url = urllib.parse.urlsplit(normalized)
        normalized = parsed_url.path if parsed_url.path else "/"

    # Collapse multiple consecutive slashes: //api//v1 -> /api/v1
    normalized = re.sub(r"/+", "/", normalized)
    return normalized, flags
