"""
Thread-safe Atomic Host Registry for WAF Gateway.

Manages versioned, multi-tenant site routing and policy configurations in-memory.
Provides atomic updates, rollback protection, SSRF origin validation, and last-known-good guarantees.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import re
import threading
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator, model_validator


DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$"
)

FORBIDDEN_ORIGIN_HOSTS = {
    "169.254.169.254",       # AWS/GCP/Azure link-local metadata
    "metadata.google.internal",
    "0.0.0.0",
    "100.100.100.200",       # Tailscale metadata
}


class SitePolicyConfig(BaseModel):
    mode: str = Field(default="monitor")
    block_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    challenge_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    monitor_threshold: float = Field(default=0.20, ge=0.0, le=1.0)
    strict_block_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    ml_enabled: bool = Field(default=True)
    rules_enabled: bool = Field(default=True)
    challenge_enabled: bool = Field(default=True)
    anomaly_enabled: bool = Field(default=True)
    exclusions: List[Dict[str, Any]] = Field(default_factory=list)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        clean = v.strip().lower()
        allowed = ("monitor", "blocking", "strict", "corroborated", "disabled")
        if clean not in allowed:
            raise ValueError(f"Invalid mode '{clean}'. Must be one of: {allowed}")
        return clean

    @model_validator(mode="after")
    def validate_threshold_ordering(self) -> "SitePolicyConfig":
        if not (self.monitor_threshold <= self.challenge_threshold <= self.block_threshold):
            raise ValueError(
                f"Thresholds must satisfy monitor ({self.monitor_threshold}) <= "
                f"challenge ({self.challenge_threshold}) <= block ({self.block_threshold})"
            )
        return self


class SiteRouteConfig(BaseModel):
    site_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    domain: str = Field(..., min_length=1)
    origin_url: str = Field(..., min_length=1)
    enabled: bool = Field(default=True)
    config_version: int = Field(default=1, ge=1)
    policy: SitePolicyConfig = Field(default_factory=SitePolicyConfig)

    @field_validator("domain")
    @classmethod
    def validate_and_normalize_domain(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Domain must be a string")
        clean = v.strip().lower()

        if "://" in clean or "/" in clean or ":" in clean:
            raise ValueError("Domain must not include URL scheme, path, or port")
        if "*" in clean:
            raise ValueError("Wildcard domains are not permitted")
        if not DOMAIN_REGEX.match(clean):
            raise ValueError(f"Invalid domain format: '{clean}'")
        return clean

    @field_validator("origin_url")
    @classmethod
    def validate_origin_url(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Origin URL must be a string")
        clean = v.strip()

        parsed = urlparse(clean)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Origin URL must start with http:// or https://")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("Origin URL must include a valid host")

        if hostname in FORBIDDEN_ORIGIN_HOSTS:
            raise ValueError(f"Forbidden SSRF origin host: '{hostname}'")

        return clean.rstrip("/")


class HostRegistry:
    """
    Thread-safe HostRegistry storing versioned route configs for domains.
    Provides atomic updates and guarantees last-known-good configuration.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._routes: Dict[str, SiteRouteConfig] = {}
        self._last_sync_at: Optional[str] = None
        self._acknowledged_versions: Dict[str, int] = {}

    @property
    def last_sync_at(self) -> Optional[str]:
        with self._lock:
            return self._last_sync_at

    @property
    def active_sites_count(self) -> int:
        with self._lock:
            return len(self._routes)

    def upsert_site(
        self,
        config: SiteRouteConfig | Dict[str, Any],
        force_rollback: bool = False,
    ) -> SiteRouteConfig:
        """
        Validates payload completely before updating in-memory state.
        Guarantees that invalid payloads leave existing configurations untouched.
        """
        if not isinstance(config, SiteRouteConfig):
            route_config = SiteRouteConfig(**config)
        else:
            route_config = config

        domain_key = route_config.domain

        with self._lock:
            existing = self._routes.get(domain_key)
            if existing is not None and not force_rollback:
                if route_config.config_version < existing.config_version:
                    raise ValueError(
                        f"Stale config version {route_config.config_version} is lower than "
                        f"active version {existing.config_version} for domain '{domain_key}'. "
                        "Set force_rollback=True to force a rollback."
                    )

            self._routes[domain_key] = route_config
            self._acknowledged_versions[domain_key] = route_config.config_version
            self._last_sync_at = datetime.now(timezone.utc).isoformat()
            return route_config

    def sync_snapshot(self, configs: List[SiteRouteConfig | Dict[str, Any]]) -> int:
        """
        Atomically replaces all route configurations only if ALL entries validate cleanly.
        """
        validated_map: Dict[str, SiteRouteConfig] = {}
        for item in configs:
            if not isinstance(item, SiteRouteConfig):
                route_config = SiteRouteConfig(**item)
            else:
                route_config = item
            validated_map[route_config.domain] = route_config

        with self._lock:
            self._routes = validated_map
            self._acknowledged_versions = {
                domain: cfg.config_version for domain, cfg in validated_map.items()
            }
            self._last_sync_at = datetime.now(timezone.utc).isoformat()
            return len(self._routes)

    def remove_site(self, domain: str) -> bool:
        """
        Removes a route by domain name. Returns True if removed, False if not found.
        """
        clean_domain = domain.split(":")[0].strip().lower()
        with self._lock:
            removed = self._routes.pop(clean_domain, None)
            self._acknowledged_versions.pop(clean_domain, None)
            if removed is not None:
                self._last_sync_at = datetime.now(timezone.utc).isoformat()
                return True
            return False

    def lookup(self, host_header: Optional[str]) -> Optional[SiteRouteConfig]:
        """
        Looks up route config for incoming host header (stripping port and lowercase).
        Returns matching enabled SiteRouteConfig or None.
        """
        if not host_header:
            return None

        clean_host = host_header.split(":")[0].strip().lower()
        with self._lock:
            route = self._routes.get(clean_host)
            if route is not None and route.enabled:
                return route
            return None

    def get_route(self, domain: str) -> Optional[SiteRouteConfig]:
        clean_domain = domain.split(":")[0].strip().lower()
        with self._lock:
            return self._routes.get(clean_domain)

    def get_active_routes(self) -> List[Dict[str, Any]]:
        """
        Returns serializable summary of loaded routes.
        """
        with self._lock:
            result = []
            for domain, cfg in self._routes.items():
                result.append({
                    "site_id": cfg.site_id,
                    "tenant_id": cfg.tenant_id,
                    "domain": cfg.domain,
                    "origin_url": cfg.origin_url,
                    "enabled": cfg.enabled,
                    "config_version": cfg.config_version,
                    "policy_mode": cfg.policy.mode,
                })
            return result

    def clear(self) -> None:
        with self._lock:
            self._routes.clear()
            self._acknowledged_versions.clear()
            self._last_sync_at = None


# Global HostRegistry singleton
host_registry = HostRegistry()
