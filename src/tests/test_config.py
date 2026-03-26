"""Tests for the configuration loader."""

import json
from pathlib import Path

import pytest

from src.config import load_config


def test_load_config_success(test_config_path: str) -> None:
    """Loading a valid config file returns a populated GatewayConfig."""
    config = load_config(test_config_path)

    assert "test-provider" in config.providers
    assert config.providers["test-provider"].base_url == "https://api.example.com/v1"
    assert "default-chat" in config.aliases
    assert config.aliases["default-chat"].provider == "test-provider"
    assert config.rate_limit.requests_per_minute == 5
    assert config.max_prompt_tokens == 500


def test_load_config_missing_file() -> None:
    """Loading from a nonexistent path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_config("/tmp/nonexistent_config.json")


def test_provider_api_key_from_env(
    test_config_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider.api_key resolves from the environment variable."""
    monkeypatch.setenv("TEST_API_KEY", "sk-test-12345")
    config = load_config(test_config_path)
    assert config.providers["test-provider"].api_key == "sk-test-12345"


def test_provider_api_key_missing(
    test_config_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider.api_key returns None when the env var is not set."""
    monkeypatch.delenv("TEST_API_KEY", raising=False)
    config = load_config(test_config_path)
    assert config.providers["test-provider"].api_key is None
