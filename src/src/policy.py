"""Policy-as-code engine for the governed LLM gateway.

Evaluates YAML-defined policies against incoming requests to produce
ALLOW, DENY, or REQUIRE_APPROVAL decisions. Designed to be the
enforcement point that sits between request validation and provider
dispatch.

Policy rules support:
- PII pattern detection (SSN, credit card, email, phone)
- Data classification gating (PHI, PCI, confidential)
- Jurisdiction-based routing (EU data residency)
- Model access control (restrict certain models to certain clients)
- Content keyword blocking
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class PolicyDecision(str, Enum):
    """The outcome of a policy evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class PolicyResult:
    """Result of evaluating all policies against a request."""

    decision: PolicyDecision
    triggered_rules: List[str]
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_allowed(self) -> bool:
        """Return True if the request is allowed to proceed."""
        return self.decision == PolicyDecision.ALLOW


# Common PII patterns used for content scanning (precompiled for performance)
_PII_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_us": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
}


@dataclass
class PolicyRule:
    """A single policy rule parsed from YAML configuration."""

    name: str
    description: str
    action: PolicyDecision
    conditions: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyRule":
        """Create a PolicyRule from a dictionary (YAML-parsed)."""
        action_str = data.get("action", "DENY").upper()
        try:
            action = PolicyDecision(action_str)
        except ValueError:
            action = PolicyDecision.DENY

        return cls(
            name=data.get("name", "unnamed-rule"),
            description=data.get("description", ""),
            action=action,
            conditions=data.get("conditions", {}),
            enabled=data.get("enabled", True),
        )


@dataclass
class PolicyConfig:
    """Top-level policy configuration."""

    version: str = "1.0"
    rules: List[PolicyRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyConfig":
        """Create a PolicyConfig from a dictionary (YAML-parsed)."""
        rules = [PolicyRule.from_dict(r) for r in data.get("rules", [])]
        return cls(
            version=data.get("version", "1.0"),
            rules=rules,
        )


def load_policies(path: str) -> PolicyConfig:
    """Load policy rules from a YAML file.

    Args:
        path: Path to the YAML policy file.

    Returns:
        A PolicyConfig with all parsed rules.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        ValueError: If the YAML is invalid.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError("Policy file not found: {}".format(path))

    with open(policy_path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError("Policy file must contain a YAML mapping at the top level")

    return PolicyConfig.from_dict(raw)


@dataclass
class RequestContext:
    """Context extracted from an incoming request for policy evaluation.

    This represents the data that policy rules can evaluate against.
    """

    client_id: str
    model: str
    prompt_text: str
    data_classification: Optional[str] = None
    jurisdiction: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyEngine:
    """Evaluates policy rules against request contexts.

    The engine processes rules in order. The first DENY or REQUIRE_APPROVAL
    match wins. If no rules trigger, the default decision is ALLOW.
    """

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        self._config = config or PolicyConfig()

    @property
    def rules(self) -> List[PolicyRule]:
        """Return the list of configured policy rules."""
        return self._config.rules

    def evaluate(self, context: RequestContext) -> PolicyResult:
        """Evaluate all enabled policy rules against a request context.

        Rules are evaluated in order. The first rule that matches and has
        a DENY or REQUIRE_APPROVAL action determines the outcome. If no
        rules match, the request is ALLOWED.

        Args:
            context: The request context to evaluate.

        Returns:
            A PolicyResult with the decision and list of triggered rules.
        """
        triggered: List[str] = []
        worst_decision = PolicyDecision.ALLOW
        details: Dict[str, Any] = {}

        for rule in self._config.rules:
            if not rule.enabled:
                continue

            if self._rule_matches(rule, context):
                triggered.append(rule.name)
                details[rule.name] = rule.description

                # DENY beats REQUIRE_APPROVAL beats ALLOW
                if rule.action == PolicyDecision.DENY:
                    worst_decision = PolicyDecision.DENY
                elif (
                    rule.action == PolicyDecision.REQUIRE_APPROVAL
                    and worst_decision != PolicyDecision.DENY
                ):
                    worst_decision = PolicyDecision.REQUIRE_APPROVAL

        return PolicyResult(
            decision=worst_decision,
            triggered_rules=triggered,
            details=details,
        )

    def _rule_matches(self, rule: PolicyRule, context: RequestContext) -> bool:
        """Check if a single rule's conditions match the request context.

        Supported condition types:
        - pii_detected: Check prompt for PII patterns
        - data_classification: Match against metadata classification
        - jurisdiction: Match against request jurisdiction
        - blocked_models: List of model names that are blocked
        - blocked_clients: List of client IDs that are blocked
        - blocked_keywords: List of keywords to check in prompt
        - max_prompt_length: Maximum allowed prompt length (characters)

        Args:
            rule: The rule to evaluate.
            context: The request context.

        Returns:
            True if all conditions in the rule are satisfied.
        """
        conditions = rule.conditions

        if not conditions:
            return False

        all_match = True

        if "pii_detected" in conditions and conditions["pii_detected"]:
            if not self._check_pii(context.prompt_text):
                all_match = False

        if "data_classification" in conditions:
            required = conditions["data_classification"]
            if isinstance(required, str):
                required = [required]
            actual = context.data_classification or context.metadata.get(
                "data_classification", ""
            )
            if actual not in required:
                all_match = False

        if "jurisdiction" in conditions:
            required = conditions["jurisdiction"]
            if isinstance(required, str):
                required = [required]
            actual = context.jurisdiction or context.metadata.get("jurisdiction", "")
            if actual not in required:
                all_match = False

        if "blocked_models" in conditions:
            if context.model not in conditions["blocked_models"]:
                all_match = False

        if "blocked_clients" in conditions:
            if context.client_id not in conditions["blocked_clients"]:
                all_match = False

        if "blocked_keywords" in conditions:
            prompt_lower = context.prompt_text.lower()
            keyword_found = any(
                kw.lower() in prompt_lower for kw in conditions["blocked_keywords"]
            )
            if not keyword_found:
                all_match = False

        if "max_prompt_length" in conditions:
            if len(context.prompt_text) <= conditions["max_prompt_length"]:
                all_match = False

        return all_match

    @staticmethod
    def _check_pii(text: str) -> bool:
        """Check if text contains any PII patterns.

        Args:
            text: The text to scan.

        Returns:
            True if any PII pattern is detected.
        """
        for pattern in _PII_PATTERNS.values():
            if pattern.search(text):
                return True
        return False
