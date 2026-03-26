"""Configuration loader for the governed LLM gateway.

Reads a JSON config file containing provider definitions, model alias mappings,
and rate-limit parameters. API keys are resolved from environment variables.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider."""

    name: str
    base_url: str
    api_key_env: str
    default_model: str

    @property
    def api_key(self) -> Optional[str]:
        """Resolve the API key from the environment variable."""
        return os.getenv(self.api_key_env)


@dataclass
class ModelAlias:
    """Maps a user-facing alias to a specific provider and model."""

    alias: str
    provider: str
    model: str


@dataclass
class RateLimitConfig:
    """Rate-limit parameters (per client_id)."""

    requests_per_minute: int = 20
    tokens_per_minute: Optional[int] = None


@dataclass
class AuthConfig:
    """API key authentication configuration."""

    enabled: bool = False
    api_keys: Dict[str, str] = field(default_factory=dict)  # key_name -> sha256_hash


@dataclass
class ComplianceConfig:
    """Compliance-related configuration."""

    enabled: bool = True
    frameworks: List[str] = field(default_factory=lambda: ["SOC2", "HIPAA"])
    evidence_output_dir: str = "evidence/"
    retention_days: int = 2555  # ~7 years, common for regulated industries


@dataclass
class GatewayConfig:
    """Top-level gateway configuration."""

    providers: Dict[str, ProviderConfig] = field(default_factory=dict)
    aliases: Dict[str, ModelAlias] = field(default_factory=dict)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    max_prompt_tokens: Optional[int] = None
    log_file: str = "logs/gateway.log"
    policy_file: Optional[str] = None
    audit_log_file: str = "logs/audit.jsonl"
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)


def load_config(path: Union[str, Path]) -> GatewayConfig:
    """Load gateway configuration from a JSON file.

    Args:
        path: Path to the JSON config file.

    Returns:
        A fully resolved GatewayConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the config file contains invalid data.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("Config file not found: {}".format(path))

    with open(path) as f:
        raw: Dict[str, Any] = json.load(f)

    providers: Dict[str, ProviderConfig] = {}
    for name, prov in raw.get("providers", {}).items():
        providers[name] = ProviderConfig(
            name=name,
            base_url=prov["base_url"],
            api_key_env=prov["api_key_env"],
            default_model=prov.get("default_model", ""),
        )

    aliases: Dict[str, ModelAlias] = {}
    for alias, mapping in raw.get("aliases", {}).items():
        aliases[alias] = ModelAlias(
            alias=alias,
            provider=mapping["provider"],
            model=mapping["model"],
        )

    rate_limit_raw = raw.get("rate_limit", {})
    rate_limit = RateLimitConfig(
        requests_per_minute=rate_limit_raw.get("requests_per_minute", 20),
        tokens_per_minute=rate_limit_raw.get("tokens_per_minute"),
    )

    auth_raw = raw.get("auth", {})
    auth = AuthConfig(
        enabled=auth_raw.get("enabled", False),
        api_keys=auth_raw.get("api_keys", {}),
    )

    compliance_raw = raw.get("compliance", {})
    compliance = ComplianceConfig(
        enabled=compliance_raw.get("enabled", True),
        frameworks=compliance_raw.get("frameworks", ["SOC2", "HIPAA"]),
        evidence_output_dir=compliance_raw.get("evidence_output_dir", "evidence/"),
        retention_days=compliance_raw.get("retention_days", 2555),
    )

    return GatewayConfig(
        providers=providers,
        aliases=aliases,
        rate_limit=rate_limit,
        auth=auth,
        max_prompt_tokens=raw.get("max_prompt_tokens"),
        log_file=raw.get("log_file", "logs/gateway.log"),
        policy_file=raw.get("policy_file"),
        audit_log_file=raw.get("audit_log_file", "logs/audit.jsonl"),
        compliance=compliance,
    )
