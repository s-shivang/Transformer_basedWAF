"""
Level 4 Enterprise Multi-Tenant LoRA Adapter Contract & Registry.

Provides multi-tenant adapter registration, hot-swap resolution,
strict parameter/VRAM bounds (rank <= 16, memory budget <= 64 MB),
and cryptographic SHA-256 integrity verification.
Base encoder remains frozen (models/frozen/v1_0/ untouched).
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import hashlib
import os
import time


class AdapterStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SHADOW = "SHADOW"
    ARCHIVED = "ARCHIVED"


MAX_LORA_RANK = 16
MAX_ADAPTER_MEMORY_MB = 64.0  # Per-adapter memory budget for 4 GB VRAM headroom
MAX_TOTAL_ACTIVE_MEMORY_MB = 512.0  # Total active pool memory budget
BASE_MODEL_SENTINEL = "base_v1_0"


@dataclass
class LoRAAdapterMetadata:
    tenant_id: str
    adapter_id: str
    rank: int
    alpha: float
    target_modules: List[str]
    artifact_path: str
    sha256: str
    site_id: Optional[str] = None
    status: AdapterStatus = AdapterStatus.ACTIVE
    estimated_memory_mb: float = 0.0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.tenant_id or not self.tenant_id.strip():
            raise ValueError("tenant_id must not be empty")
        if not self.adapter_id or not self.adapter_id.strip():
            raise ValueError("adapter_id must not be empty")
        if not isinstance(self.rank, int) or self.rank < 1:
            raise ValueError(f"LoRA rank must be a positive integer, got {self.rank}")
        if self.rank > MAX_LORA_RANK:
            raise ValueError(
                f"LoRA rank {self.rank} exceeds maximum allowed rank ({MAX_LORA_RANK}) "
                f"for 4GB VRAM safety budget"
            )
        if self.alpha <= 0:
            raise ValueError(f"LoRA alpha must be positive, got {self.alpha}")
        if not self.target_modules:
            raise ValueError("target_modules list must not be empty")

        # Normalize status
        if isinstance(self.status, str):
            self.status = AdapterStatus(self.status.upper())

        # If estimated_memory_mb not set, estimate based on rank (approx 0.75 MB per rank unit)
        if self.estimated_memory_mb <= 0.0:
            self.estimated_memory_mb = round(self.rank * 0.75 + len(self.target_modules) * 0.5, 2)

        if self.estimated_memory_mb > MAX_ADAPTER_MEMORY_MB:
            raise ValueError(
                f"Estimated adapter memory ({self.estimated_memory_mb:.1f} MB) exceeds "
                f"budget limit of {MAX_ADAPTER_MEMORY_MB:.1f} MB"
            )


def compute_file_sha256(file_path: Union[str, Path]) -> str:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Artifact file not found: {path}")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


class LoRAAdapterRegistry:
    """
    Registry for enterprise Level 4 tenant-specific LoRA adapters.
    Provides fast O(1) resolution to active adapters or fallback to base_v1_0.
    """

    def __init__(self, max_total_memory_mb: float = MAX_TOTAL_ACTIVE_MEMORY_MB):
        self._adapters_by_id: Dict[str, LoRAAdapterMetadata] = {}
        # Composite lookup keys: (tenant_id, site_id) -> adapter_id, and (tenant_id, None) -> adapter_id
        self._tenant_lookup: Dict[str, str] = {}
        self._site_lookup: Dict[str, str] = {}
        self.max_total_memory_mb = max_total_memory_mb

    def _make_site_key(self, tenant_id: str, site_id: str) -> str:
        return f"{tenant_id}::{site_id}"

    def register_adapter(
        self,
        metadata: LoRAAdapterMetadata,
        verify_sha256_on_disk: bool = False,
    ) -> LoRAAdapterMetadata:
        """
        Registers an adapter with safety validations.
        """
        # Validate memory budget across active adapters
        if metadata.status == AdapterStatus.ACTIVE:
            current_active_mem = sum(
                a.estimated_memory_mb
                for a in self._adapters_by_id.values()
                if a.status == AdapterStatus.ACTIVE and a.adapter_id != metadata.adapter_id
            )
            if current_active_mem + metadata.estimated_memory_mb > self.max_total_memory_mb:
                raise ValueError(
                    f"Registering adapter {metadata.adapter_id} ({metadata.estimated_memory_mb:.1f} MB) "
                    f"exceeds total active VRAM budget ({self.max_total_memory_mb:.1f} MB, "
                    f"current: {current_active_mem:.1f} MB)"
                )

        if verify_sha256_on_disk:
            actual_sha = compute_file_sha256(metadata.artifact_path)
            if actual_sha.lower() != metadata.sha256.lower():
                raise ValueError(
                    f"SHA-256 integrity check failed for {metadata.adapter_id}: "
                    f"expected {metadata.sha256}, got {actual_sha}"
                )

        self._adapters_by_id[metadata.adapter_id] = metadata

        # Index active adapters for fast resolution
        if metadata.status == AdapterStatus.ACTIVE:
            if metadata.site_id:
                self._site_lookup[self._make_site_key(metadata.tenant_id, metadata.site_id)] = metadata.adapter_id
            else:
                self._tenant_lookup[metadata.tenant_id] = metadata.adapter_id

        return metadata

    def resolve_adapter(
        self,
        tenant_id: Optional[str] = None,
        site_id: Optional[str] = None,
    ) -> Union[LoRAAdapterMetadata, str]:
        """
        Resolves the appropriate adapter for a request:
        1. Site-specific adapter for tenant if active
        2. Tenant-default adapter if active
        3. Fallback to shared frozen base model sentinel ('base_v1_0')
        """
        if not tenant_id:
            return BASE_MODEL_SENTINEL

        # 1. Check site-specific active adapter
        if site_id:
            site_key = self._make_site_key(tenant_id, site_id)
            if site_key in self._site_lookup:
                adapter_id = self._site_lookup[site_key]
                adapter = self._adapters_by_id.get(adapter_id)
                if adapter and adapter.status == AdapterStatus.ACTIVE:
                    return adapter

        # 2. Check tenant-wide active adapter
        if tenant_id in self._tenant_lookup:
            adapter_id = self._tenant_lookup[tenant_id]
            adapter = self._adapters_by_id.get(adapter_id)
            if adapter and adapter.status == AdapterStatus.ACTIVE:
                return adapter

        # 3. Clean fallback to frozen base model
        return BASE_MODEL_SENTINEL

    def get_adapter(self, adapter_id: str) -> Optional[LoRAAdapterMetadata]:
        return self._adapters_by_id.get(adapter_id)

    def set_adapter_status(self, adapter_id: str, status: Union[AdapterStatus, str]) -> LoRAAdapterMetadata:
        if adapter_id not in self._adapters_by_id:
            raise KeyError(f"Adapter not found: {adapter_id}")

        if isinstance(status, str):
            status = AdapterStatus(status.upper())

        adapter = self._adapters_by_id[adapter_id]
        adapter.status = status

        # Refresh index
        if status == AdapterStatus.ACTIVE:
            if adapter.site_id:
                self._site_lookup[self._make_site_key(adapter.tenant_id, adapter.site_id)] = adapter.adapter_id
            else:
                self._tenant_lookup[adapter.tenant_id] = adapter.adapter_id
        else:
            # Remove from active lookup
            if adapter.site_id:
                self._site_lookup.pop(self._make_site_key(adapter.tenant_id, adapter.site_id), None)
            else:
                self._tenant_lookup.pop(adapter.tenant_id, None)

        return adapter

    def list_adapters(
        self,
        tenant_id: Optional[str] = None,
        status: Optional[AdapterStatus] = None,
    ) -> List[LoRAAdapterMetadata]:
        adapters = list(self._adapters_by_id.values())
        if tenant_id:
            adapters = [a for a in adapters if a.tenant_id == tenant_id]
        if status:
            adapters = [a for a in adapters if a.status == status]
        return adapters

    def verify_adapter_integrity(self, adapter_id: str) -> bool:
        adapter = self.get_adapter(adapter_id)
        if not adapter:
            raise KeyError(f"Adapter not found: {adapter_id}")
        actual_sha = compute_file_sha256(adapter.artifact_path)
        return actual_sha.lower() == adapter.sha256.lower()

    def clear(self):
        self._adapters_by_id.clear()
        self._tenant_lookup.clear()
        self._site_lookup.clear()


# Default singleton instance
default_lora_registry = LoRAAdapterRegistry()
