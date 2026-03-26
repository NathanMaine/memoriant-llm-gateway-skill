"""Shared test fixtures for the governed LLM gateway tests."""

import json
from pathlib import Path
from typing import Dict, Optional

import pytest

from src.config import GatewayConfig, load_config


def _make_config(tmp_path: Path, overrides: Optional[Dict] = None) -> str:
    """Write a minimal test config and return its path."""
    config = {
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
        "rate_limit": {
            "requests_per_minute": 5,
            "tokens_per_minute": 10000,
        },
        "max_prompt_tokens": 500,
        "log_file": str(tmp_path / "test.log"),
    }
    if overrides:
        config.update(overrides)

    path = tmp_path / "test_config.json"
    path.write_text(json.dumps(config))
    return str(path)


@pytest.fixture()
def test_config_path(tmp_path: Path) -> str:
    """Return the path to a temporary test config file."""
    return _make_config(tmp_path)


@pytest.fixture()
def test_config(test_config_path: str) -> GatewayConfig:
    """Return a loaded test GatewayConfig."""
    return load_config(test_config_path)
