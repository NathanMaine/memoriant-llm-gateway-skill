"""Tests for the alias router."""

import pytest

from src.config import GatewayConfig
from src.router import RoutingError, resolve_route


def test_resolve_known_alias(test_config: GatewayConfig) -> None:
    """A known alias resolves to the correct provider and model."""
    result = resolve_route(test_config, "default-chat")
    assert result.provider.name == "test-provider"
    assert result.model == "test-model"


def test_resolve_unknown_alias(test_config: GatewayConfig) -> None:
    """An unknown alias raises RoutingError with a helpful message."""
    with pytest.raises(RoutingError, match="Unknown model alias"):
        resolve_route(test_config, "nonexistent-alias")
