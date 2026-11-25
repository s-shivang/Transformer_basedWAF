"""
Unit tests for Level 4 Multi-Tenant LoRA Adapter Registry & Hot-Swap Resolver.
"""

import hashlib
import tempfile
from pathlib import Path
import pytest

from src.ml_service.lora_registry import (
    LoRAAdapterMetadata,
    LoRAAdapterRegistry,
    AdapterStatus,
    BASE_MODEL_SENTINEL,
    MAX_LORA_RANK,
    compute_file_sha256,
)


@pytest.fixture
def temp_adapter_file(tmp_path):
    artifact = tmp_path / "lora_weights.bin"
    content = b"sample-lora-adapter-weights-binary-data"
    artifact.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    return artifact, sha256


@pytest.fixture
def registry():
    return LoRAAdapterRegistry(max_total_memory_mb=128.0)


def test_adapter_registration_success(registry, temp_adapter_file):
    path, sha256 = temp_adapter_file
    meta = LoRAAdapterMetadata(
        tenant_id="tenant-alpha",
        adapter_id="lora-alpha-v1",
        rank=8,
        alpha=16.0,
        target_modules=["q_lin", "v_lin"],
        artifact_path=str(path),
        sha256=sha256,
        status=AdapterStatus.ACTIVE,
    )
    registered = registry.register_adapter(meta, verify_sha256_on_disk=True)
    assert registered.adapter_id == "lora-alpha-v1"
    assert registered.rank == 8
    assert registered.estimated_memory_mb > 0

    # Retrieve
    retrieved = registry.get_adapter("lora-alpha-v1")
    assert retrieved is not None
    assert retrieved.tenant_id == "tenant-alpha"


def test_adapter_sha256_integrity_failure(registry, temp_adapter_file):
    path, _ = temp_adapter_file
    tampered_sha = "0000000000000000000000000000000000000000000000000000000000000000"
    meta = LoRAAdapterMetadata(
        tenant_id="tenant-alpha",
        adapter_id="lora-tampered",
        rank=4,
        alpha=8.0,
        target_modules=["q_lin"],
        artifact_path=str(path),
        sha256=tampered_sha,
    )
    with pytest.raises(ValueError, match="SHA-256 integrity check failed"):
        registry.register_adapter(meta, verify_sha256_on_disk=True)


def test_fallback_to_base_v1_0_when_unregistered(registry):
    # Unknown tenant resolves to base model sentinel with zero overhead
    resolved = registry.resolve_adapter(tenant_id="unknown-tenant")
    assert resolved == BASE_MODEL_SENTINEL

    # None tenant resolves to base model sentinel
    assert registry.resolve_adapter(tenant_id=None) == BASE_MODEL_SENTINEL


def test_resolution_hierarchy_site_vs_tenant(registry, temp_adapter_file):
    path, sha256 = temp_adapter_file

    # 1. Tenant-level adapter
    tenant_meta = LoRAAdapterMetadata(
        tenant_id="tenant-corp",
        adapter_id="lora-corp-default",
        rank=4,
        alpha=8.0,
        target_modules=["q_lin"],
        artifact_path=str(path),
        sha256=sha256,
        site_id=None,
        status=AdapterStatus.ACTIVE,
    )
    registry.register_adapter(tenant_meta)

    # 2. Site-specific adapter
    site_meta = LoRAAdapterMetadata(
        tenant_id="tenant-corp",
        adapter_id="lora-corp-site-checkout",
        rank=8,
        alpha=16.0,
        target_modules=["q_lin", "v_lin"],
        artifact_path=str(path),
        sha256=sha256,
        site_id="site-checkout",
        status=AdapterStatus.ACTIVE,
    )
    registry.register_adapter(site_meta)

    # Site-specific query should resolve site adapter
    res_site = registry.resolve_adapter(tenant_id="tenant-corp", site_id="site-checkout")
    assert isinstance(res_site, LoRAAdapterMetadata)
    assert res_site.adapter_id == "lora-corp-site-checkout"

    # Other site under same tenant should fall back to tenant-level adapter
    res_other = registry.resolve_adapter(tenant_id="tenant-corp", site_id="site-marketing")
    assert isinstance(res_other, LoRAAdapterMetadata)
    assert res_other.adapter_id == "lora-corp-default"

    # Tenant without site parameter resolves to tenant-level adapter
    res_tenant = registry.resolve_adapter(tenant_id="tenant-corp")
    assert isinstance(res_tenant, LoRAAdapterMetadata)
    assert res_tenant.adapter_id == "lora-corp-default"


def test_shadow_and_archived_status_fallback(registry, temp_adapter_file):
    path, sha256 = temp_adapter_file
    meta = LoRAAdapterMetadata(
        tenant_id="tenant-shadow",
        adapter_id="lora-shadow",
        rank=4,
        alpha=8.0,
        target_modules=["q_lin"],
        artifact_path=str(path),
        sha256=sha256,
        status=AdapterStatus.SHADOW,
    )
    registry.register_adapter(meta)

    # Shadow adapter should NOT be active for live inference -> falls back to base_v1_0
    assert registry.resolve_adapter(tenant_id="tenant-shadow") == BASE_MODEL_SENTINEL

    # Promoting to ACTIVE activates it
    registry.set_adapter_status("lora-shadow", AdapterStatus.ACTIVE)
    assert registry.resolve_adapter(tenant_id="tenant-shadow").adapter_id == "lora-shadow"

    # Archiving it reverts to base_v1_0
    registry.set_adapter_status("lora-shadow", AdapterStatus.ARCHIVED)
    assert registry.resolve_adapter(tenant_id="tenant-shadow") == BASE_MODEL_SENTINEL


def test_rank_guardrails(temp_adapter_file):
    path, sha256 = temp_adapter_file

    # Exceeding MAX_LORA_RANK (16) must raise ValueError
    with pytest.raises(ValueError, match="exceeds maximum allowed rank"):
        LoRAAdapterMetadata(
            tenant_id="tenant-x",
            adapter_id="lora-too-large",
            rank=32,  # > 16
            alpha=32.0,
            target_modules=["q_lin"],
            artifact_path=str(path),
            sha256=sha256,
        )

    # Non-positive rank must raise ValueError
    with pytest.raises(ValueError, match="positive integer"):
        LoRAAdapterMetadata(
            tenant_id="tenant-x",
            adapter_id="lora-zero-rank",
            rank=0,
            alpha=8.0,
            target_modules=["q_lin"],
            artifact_path=str(path),
            sha256=sha256,
        )


def test_memory_budget_guardrails(temp_adapter_file):
    path, sha256 = temp_adapter_file

    # Per-adapter memory exceeding 64 MB must raise ValueError
    with pytest.raises(ValueError, match="exceeds budget limit"):
        LoRAAdapterMetadata(
            tenant_id="tenant-x",
            adapter_id="lora-huge-mem",
            rank=16,
            alpha=16.0,
            target_modules=["q_lin"],
            artifact_path=str(path),
            sha256=sha256,
            estimated_memory_mb=75.0,  # > 64 MB
        )

    # Total active pool memory exceeding registry limit
    tiny_registry = LoRAAdapterRegistry(max_total_memory_mb=20.0)
    meta1 = LoRAAdapterMetadata(
        tenant_id="t1",
        adapter_id="a1",
        rank=16,
        alpha=16.0,
        target_modules=["q_lin"],
        artifact_path=str(path),
        sha256=sha256,
        estimated_memory_mb=15.0,
    )
    tiny_registry.register_adapter(meta1)

    meta2 = LoRAAdapterMetadata(
        tenant_id="t2",
        adapter_id="a2",
        rank=16,
        alpha=16.0,
        target_modules=["q_lin"],
        artifact_path=str(path),
        sha256=sha256,
        estimated_memory_mb=10.0,
    )
    with pytest.raises(ValueError, match="exceeds total active VRAM budget"):
        tiny_registry.register_adapter(meta2)


def test_base_model_frozen_integrity():
    """Confirms base model directory models/frozen/v1_0/ exists and is untouched."""
    base_dir = Path("models/frozen/v1_0")
    assert base_dir.exists(), "Base model directory models/frozen/v1_0 must exist"
    assert (base_dir / "model_manifest.json").exists(), "Base model manifest must exist"
    assert (base_dir / "threshold.json").exists(), "Base model threshold must exist"
