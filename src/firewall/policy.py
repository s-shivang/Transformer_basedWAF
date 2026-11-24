"""
Firewall Policy Schema and Configuration Models.

Supports multi-tenant / site-ready configurations, inspection modes,
granular thresholds, path exclusions, and failure mode policies.
"""
from typing import List, Literal, Optional, Dict, Any, Set
from pydantic import BaseModel, Field


class ThresholdConfig(BaseModel):
    """Calibrated operational decision thresholds."""
    monitor: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description="Threshold above which alerts are emitted in Monitor mode."
    )
    challenge: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description="Threshold band start for CAPTCHA/challenge or anomaly escalation."
    )
    block: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="High-confidence low-FPR threshold for automated blocking."
    )
    strict_block: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description="Aggressive block threshold used when inspection_mode is 'strict'."
    )


class FirewallPolicy(BaseModel):
    """
    Tenant- and Site-aware WAF Policy Configuration.
    Default inspection mode is strictly 'monitor' for advisory safety.
    """
    policy_version: str = Field(default="1.0.0", description="Policy schema version")
    tenant_id: str = Field(default="default", description="Tenant identifier for multi-tenancy")
    site_id: str = Field(default="default", description="Protected site or domain identifier")
    inspection_mode: Literal["monitor", "blocking", "strict", "disabled"] = Field(
        default="monitor",
        description="Operational enforcement mode. Default is 'monitor' (never auto-blocks)."
    )
    rules_enabled: bool = Field(default=True, description="Enable Layer 1 deterministic rules")
    ml_enabled: bool = Field(default=True, description="Enable Layer 2/3 ML inference")
    anomaly_enabled: bool = Field(default=True, description="Enable Layer 4 behavioral tracking")
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    max_request_size_bytes: int = Field(
        default=65536,
        description="Maximum allowable total request size in bytes (default 64 KB)"
    )
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        description="Permitted HTTP methods"
    )
    path_exclusions: List[str] = Field(
        default_factory=lambda: ["/healthcheck", "/health", "/ready", "/robots.txt"],
        description="Exact or prefix URL paths exempt from automated ML blocking"
    )
    ml_failure_mode: Literal["fail_open", "fail_closed"] = Field(
        default="fail_open",
        description="Action when ML service is degraded/unreachable (fail_open or fail_closed)"
    )

    def is_method_allowed(self, method: str) -> bool:
        """Checks if HTTP method is within configured allowed list."""
        m_upper = method.upper().strip()
        return m_upper in {m.upper() for m in self.allowed_methods}

    def is_path_excluded(self, path: str) -> bool:
        """Checks if path matches any excluded path (exact match or path prefix)."""
        clean_path = path.split("?")[0].strip().lower()
        for excl in self.path_exclusions:
            clean_excl = excl.strip().lower()
            if clean_path == clean_excl or clean_path.startswith(clean_excl.rstrip("/") + "/"):
                return True
        return False
