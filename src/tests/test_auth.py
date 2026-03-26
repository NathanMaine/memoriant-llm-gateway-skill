"""Tests for API key authentication.

Covers:
- hash_api_key determinism and output format
- validate_api_key with valid, missing, and invalid keys
- Integration: missing key returns 401 when auth enabled
- Integration: invalid key returns 401
- Integration: valid key returns 200
- Integration: auth disabled allows requests without a key
- Integration: auth failure recorded in audit trail
"""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from src import app as app_module
from src.app import app
from src.auth import AuthenticationError, hash_api_key, validate_api_key


# --- Unit tests for auth module ---


class TestHashApiKey:
    """Tests for the hash_api_key helper."""

    def test_deterministic(self) -> None:
        assert hash_api_key("test") == hash_api_key("test")

    def test_returns_hex_sha256(self) -> None:
        result = hash_api_key("anything")
        assert len(result) == 64
        int(result, 16)  # Should not raise

    def test_different_inputs_different_hashes(self) -> None:
        assert hash_api_key("key-a") != hash_api_key("key-b")


class TestValidateApiKey:
    """Tests for the validate_api_key function."""

    def test_valid_key_returns_name(self) -> None:
        key_hash = hash_api_key("my-secret")
        result = validate_api_key("my-secret", {"dev-1": key_hash})
        assert result == "dev-1"

    def test_missing_key_raises(self) -> None:
        with pytest.raises(AuthenticationError, match="Missing"):
            validate_api_key(None, {"dev-1": "abc"})

    def test_empty_key_raises(self) -> None:
        with pytest.raises(AuthenticationError, match="Missing"):
            validate_api_key("", {"dev-1": "abc"})

    def test_invalid_key_raises(self) -> None:
        key_hash = hash_api_key("correct-key")
        with pytest.raises(AuthenticationError, match="Invalid"):
            validate_api_key("wrong-key", {"dev-1": key_hash})

    def test_multiple_keys_finds_match(self) -> None:
        keys = {
            "key-a": hash_api_key("secret-a"),
            "key-b": hash_api_key("secret-b"),
        }
        assert validate_api_key("secret-b", keys) == "key-b"


# --- Integration tests against the FastAPI app ---

VALID_KEY = "test-key-1"
VALID_KEY_HASH = hash_api_key(VALID_KEY)


def _auth_config(tmp_path: Path, *, auth_enabled: bool = True) -> dict:
    """Build a test config dict with auth settings."""
    return {
        "providers": {
            "test-provider": {
                "base_url": "https://api.example.com/v1",
                "api_key_env": "TEST_API_KEY",
                "default_model": "test-model",
            }
        },
        "aliases": {
            "default-chat": {
                "provider": "test-provider",
                "model": "test-model",
            }
        },
        "rate_limit": {"requests_per_minute": 10, "tokens_per_minute": 10000},
        "max_prompt_tokens": 500,
        "log_file": str(tmp_path / "test.log"),
        "audit_log_file": str(tmp_path / "audit.jsonl"),
        "auth": {
            "enabled": auth_enabled,
            "api_keys": {"dev-key-1": VALID_KEY_HASH},
        },
    }


@pytest.fixture(autouse=True)
def _reset_app_with_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset app state and configure auth-enabled test config."""
    config = _auth_config(tmp_path, auth_enabled=True)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    monkeypatch.delenv("TEST_API_KEY", raising=False)
    monkeypatch.setattr(app_module, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(app_module, "_config", None)
    monkeypatch.setattr(app_module, "_limiter", None)
    monkeypatch.setattr(app_module, "_audit_trail", None)
    monkeypatch.setattr(app_module, "_policy_engine", None)


def _body() -> dict:
    return {
        "client_id": "test-client",
        "model": "default-chat",
        "messages": [{"role": "user", "content": "Hello"}],
    }


@pytest.mark.asyncio
async def test_missing_api_key_returns_401() -> None:
    """Request without X-API-Key header returns 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/chat", json=_body())

    assert resp.status_code == 401
    data = resp.json()
    assert data["error"]["type"] == "authentication_error"
    assert "Missing" in data["error"]["message"]


@pytest.mark.asyncio
async def test_invalid_api_key_returns_401() -> None:
    """Request with wrong X-API-Key returns 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat",
            json=_body(),
            headers={"X-API-Key": "wrong-key"},
        )

    assert resp.status_code == 401
    data = resp.json()
    assert data["error"]["type"] == "authentication_error"
    assert "Invalid" in data["error"]["message"]


@pytest.mark.asyncio
async def test_valid_api_key_passes_auth() -> None:
    """Request with valid X-API-Key passes auth check."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat",
            json=_body(),
            headers={"X-API-Key": VALID_KEY},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["model"] == "default-chat"


@pytest.mark.asyncio
async def test_auth_disabled_allows_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When auth.enabled is false, requests pass without a key."""
    config = _auth_config(tmp_path, auth_enabled=False)
    config_path = tmp_path / "config_noauth.json"
    config_path.write_text(json.dumps(config))

    monkeypatch.delenv("TEST_API_KEY", raising=False)
    monkeypatch.setattr(app_module, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(app_module, "_config", None)
    monkeypatch.setattr(app_module, "_limiter", None)
    monkeypatch.setattr(app_module, "_audit_trail", None)
    monkeypatch.setattr(app_module, "_policy_engine", None)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/chat", json=_body())

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_auth_failure_recorded_in_audit(tmp_path: Path) -> None:
    """Failed auth produces an audit trail entry with action=auth_failure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/v1/chat", json=_body())

    audit_file = tmp_path / "audit.jsonl"
    assert audit_file.exists()
    lines = audit_file.read_text().strip().split("\n")
    assert len(lines) >= 1
    entry = json.loads(lines[0])
    assert entry["action"] == "auth_failure"
    assert entry["policy_decision"] == "DENY"
