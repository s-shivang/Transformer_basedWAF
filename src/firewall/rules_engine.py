from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import re
from pathlib import PurePosixPath
from src.pipeline.schema import ParsedRequest


# Standard HTTP Methods compliant with RFC 9110
STANDARD_HTTP_METHODS: Set[str] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"
}

# Compiled regex patterns for fast protocol & attack detection
RE_NULL_BYTE = re.compile(r"(\x00|%00|\\0)", re.IGNORECASE)
RE_MALFORMED_PCT = re.compile(r"%(?![0-9a-fA-F]{2})")
RE_PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e)", re.IGNORECASE)

# High-confidence deterministic attack signatures (Layer 1 fast reject)
CRITICAL_SIGNATURES = [
    ("SQLI_UNION_SELECT", re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.IGNORECASE)),
    ("SQLI_INFO_SCHEMA", re.compile(r"\b(INFORMATION_SCHEMA|SYS\.TABLES|SYSOBJECTS)\b", re.IGNORECASE)),
    ("SQLI_TAUTOLOGY_OR", re.compile(r"(\'|\")\s*(OR|AND)\s*[\'\"0-9\(\)]+\s*=\s*[\'\"0-9\(\)]+", re.IGNORECASE)),
    ("SQLI_STACKED_WAITFOR", re.compile(r";\s*WAITFOR\s+DELAY\b", re.IGNORECASE)),
    ("XSS_SCRIPT_TAG", re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE)),
    ("XSS_JS_URI", re.compile(r"javascript\s*:\s*[^\s]", re.IGNORECASE)),
    ("XSS_EVENT_HANDLER", re.compile(r"\bon(error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE)),
    ("CMD_INJECTION_PASSWD", re.compile(r"(/etc/passwd|/etc/shadow|/windows/win\.ini)", re.IGNORECASE)),
    ("CMD_EXEC_CALL", re.compile(r"(;|\||`|\$\()\s*(cat|ls|nc|bash|sh|cmd\.exe|powershell)\b", re.IGNORECASE)),
]


@dataclass
class RuleViolation:
    rule_id: str
    category: str
    message: str
    severity: str  # 'BLOCK', 'WARN'
    field: str
    matched_value: str


@dataclass
class RuleValidationResult:
    is_valid: bool
    action: str  # 'BLOCK' or 'ALLOW'
    violations: List[RuleViolation] = field(default_factory=list)

    @property
    def has_blocking_violation(self) -> bool:
        return any(v.severity == "BLOCK" for v in self.violations)


class RulesEngine:
    """
    Layer 1: Rules & Protocol Validator.
    Executes sub-millisecond RFC protocol compliance checks, size constraints,
    path boundary constraints, and deterministic attack pattern recognition.
    """

    def __init__(
        self,
        max_uri_length: int = 4096,
        max_header_size: int = 8192,
        max_body_size: int = 1_048_576,  # 1 MB
        allowed_methods: Optional[Set[str]] = None,
        enforce_strict_rfc: bool = True,
    ):
        self.max_uri_length = max_uri_length
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.allowed_methods = allowed_methods or STANDARD_HTTP_METHODS
        self.enforce_strict_rfc = enforce_strict_rfc

    def validate(self, req: ParsedRequest) -> RuleValidationResult:
        violations: List[RuleViolation] = []

        # 1. Method validation
        method_upper = req.method.upper().strip()
        if method_upper not in self.allowed_methods:
            violations.append(
                RuleViolation(
                    rule_id="RFC_METHOD_INVALID",
                    category="protocol",
                    message=f"Non-standard or disallowed HTTP method: '{req.method}'",
                    severity="BLOCK",
                    field="method",
                    matched_value=req.method,
                )
            )

        # 2. URI Length constraint
        full_uri = req.path
        if req.query_params:
            q_str = "&".join(f"{k}={v}" for k, v in req.query_params.items())
            full_uri = f"{req.path}?{q_str}"

        if len(full_uri) > self.max_uri_length:
            violations.append(
                RuleViolation(
                    rule_id="RFC_URI_TOO_LONG",
                    category="protocol",
                    message=f"URI length {len(full_uri)} exceeds maximum allowed {self.max_uri_length}",
                    severity="BLOCK",
                    field="uri",
                    matched_value=full_uri[:100] + "...",
                )
            )

        # 3. Path Traversal & Normalization Boundary Check
        if RE_PATH_TRAVERSAL.search(req.path) or ".." in req.path:
            # Check if canonical resolution escapes root
            norm_path = PurePosixPath(req.path)
            if ".." in norm_path.parts or req.path.startswith(".."):
                violations.append(
                    RuleViolation(
                        rule_id="SEC_PATH_TRAVERSAL",
                        category="traversal",
                        message=f"Path traversal sequence detected in path: '{req.path}'",
                        severity="BLOCK",
                        field="path",
                        matched_value=req.path,
                    )
                )

        # 4. Null byte injection checks (URI, Path, or Parameters)
        if req.encoding_flags.get("has_null_bytes") or RE_NULL_BYTE.search(req.raw_text):
            violations.append(
                RuleViolation(
                    rule_id="SEC_NULL_BYTE_INJECTION",
                    category="encoding",
                    message="Null byte detected in request text or parameters",
                    severity="BLOCK",
                    field="raw_text",
                    matched_value=r"\x00",
                )
            )

        # 5. Malformed percent encoding check
        if RE_MALFORMED_PCT.search(req.path) or any(
            isinstance(v, str) and RE_MALFORMED_PCT.search(v)
            for v in req.query_params.values()
        ):
            violations.append(
                RuleViolation(
                    rule_id="RFC_MALFORMED_ENCODING",
                    category="protocol",
                    message="Malformed percent-encoding syntax found",
                    severity="BLOCK",
                    field="query/path",
                    matched_value="%",
                )
            )

        # 6. High-Confidence Deterministic Attack Signatures across payloads
        # We check canonical payloads as well as query/body text
        inspect_targets = list(req.canonical_payloads)
        for k, v in req.query_params.items():
            inspect_targets.append(str(k))
            if isinstance(v, list):
                inspect_targets.extend(str(i) for i in v)
            else:
                inspect_targets.append(str(v))

        for k, v in req.body_params.items():
            inspect_targets.append(str(k))
            inspect_targets.append(str(v))

        target_text = " \n ".join(inspect_targets)
        for rule_id, pattern in CRITICAL_SIGNATURES:
            m = pattern.search(target_text)
            if m:
                violations.append(
                    RuleViolation(
                        rule_id=rule_id,
                        category="signature",
                        message=f"Deterministic attack signature matched: {rule_id}",
                        severity="BLOCK",
                        field="payload",
                        matched_value=m.group(0),
                    )
                )
                break  # Fast exit on first critical signature

        is_valid = not any(v.severity == "BLOCK" for v in violations)
        action = "ALLOW" if is_valid else "BLOCK"

        return RuleValidationResult(
            is_valid=is_valid,
            action=action,
            violations=violations,
        )
