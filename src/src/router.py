"""Routing: resolve a model alias to a concrete provider and model.

The router looks up the alias in the gateway configuration and returns the
matching provider config and target model name.
"""

from dataclasses import dataclass

from src.config import GatewayConfig, ProviderConfig


@dataclass
class RouteResult:
    """Resolved route for a model alias."""

    provider: ProviderConfig
    model: str


class RoutingError(Exception):
    """Raised when a model alias cannot be resolved."""

    def __init__(self, alias: str, reason: str) -> None:
        self.alias = alias
        self.reason = reason
        super().__init__("Routing error for alias '{}': {}".format(alias, reason))


def resolve_route(config: GatewayConfig, alias: str) -> RouteResult:
    """Resolve a model alias to a provider and concrete model.

    Args:
        config: The loaded gateway configuration.
        alias: The user-supplied model alias (e.g. "default-chat").

    Returns:
        A RouteResult with the provider config and model name.

    Raises:
        RoutingError: If the alias is unknown or maps to an unconfigured provider.
    """
    mapping = config.aliases.get(alias)
    if mapping is None:
        available = ", ".join(sorted(config.aliases.keys())) or "(none)"
        raise RoutingError(
            alias,
            "Unknown model alias. Available aliases: {}".format(available),
        )

    provider = config.providers.get(mapping.provider)
    if provider is None:
        raise RoutingError(
            alias,
            "Alias maps to provider '{}' which is not configured.".format(
                mapping.provider
            ),
        )

    return RouteResult(provider=provider, model=mapping.model)
