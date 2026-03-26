"""Tests for the policy-as-code engine.

Covers:
- ALLOW/DENY/REQUIRE_APPROVAL decision outcomes
- PII detection (SSN, credit card, email, phone)
- Data classification gating (PHI, PCI)
- Jurisdiction-based rules (EU)
- Keyword blocking
- Model and client blocking
- Prompt length limits
- Policy loading from YAML
- Disabled rules are skipped
- Multiple rules with escalating severity
"""

from pathlib import Path
from typing import Dict, Optional

import pytest

from src.policy import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyResult,
    PolicyRule,
    RequestContext,
    load_policies,
)


def _make_engine(*rules: PolicyRule) -> PolicyEngine:
    """Create a PolicyEngine with the given rules."""
    config = PolicyConfig(rules=list(rules))
    return PolicyEngine(config)


def _make_context(
    prompt: str = "Hello, how are you?",
    client_id: str = "client-a",
    model: str = "default-chat",
    data_classification: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> RequestContext:
    """Create a RequestContext for testing."""
    return RequestContext(
        client_id=client_id,
        model=model,
        prompt_text=prompt,
        data_classification=data_classification,
        jurisdiction=jurisdiction,
        metadata=metadata or {},
    )


class TestPolicyDecisions:
    """Tests for basic ALLOW/DENY/REQUIRE_APPROVAL outcomes."""

    def test_no_rules_allows(self) -> None:
        """With no rules, all requests are allowed."""
        engine = _make_engine()
        result = engine.evaluate(_make_context())
        assert result.decision == PolicyDecision.ALLOW
        assert result.triggered_rules == []

    def test_deny_rule_blocks(self) -> None:
        """A matching DENY rule blocks the request."""
        rule = PolicyRule(
            name="block-test",
            description="Block test client",
            action=PolicyDecision.DENY,
            conditions={"blocked_clients": ["client-a"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(client_id="client-a"))
        assert result.decision == PolicyDecision.DENY
        assert "block-test" in result.triggered_rules

    def test_require_approval_rule(self) -> None:
        """A matching REQUIRE_APPROVAL rule flags the request."""
        rule = PolicyRule(
            name="approval-test",
            description="Require approval for PHI",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"data_classification": ["PHI"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(data_classification="PHI")
        )
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL
        assert "approval-test" in result.triggered_rules

    def test_non_matching_rule_allows(self) -> None:
        """A rule that does not match allows the request."""
        rule = PolicyRule(
            name="block-other",
            description="Block other client",
            action=PolicyDecision.DENY,
            conditions={"blocked_clients": ["client-x"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(client_id="client-a"))
        assert result.decision == PolicyDecision.ALLOW
        assert result.triggered_rules == []


class TestPIIDetection:
    """Tests for PII pattern detection in prompts."""

    def test_ssn_detected(self) -> None:
        """SSN pattern triggers PII rule."""
        rule = PolicyRule(
            name="pii-block",
            description="Block PII",
            action=PolicyDecision.DENY,
            conditions={"pii_detected": True},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="My SSN is 123-45-6789")
        )
        assert result.decision == PolicyDecision.DENY

    def test_credit_card_detected(self) -> None:
        """Credit card number pattern triggers PII rule."""
        rule = PolicyRule(
            name="pii-block",
            description="Block PII",
            action=PolicyDecision.DENY,
            conditions={"pii_detected": True},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="Card: 4111 1111 1111 1111")
        )
        assert result.decision == PolicyDecision.DENY

    def test_email_detected(self) -> None:
        """Email address pattern triggers PII rule."""
        rule = PolicyRule(
            name="pii-block",
            description="Block PII",
            action=PolicyDecision.DENY,
            conditions={"pii_detected": True},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="Contact john@example.com for details")
        )
        assert result.decision == PolicyDecision.DENY

    def test_phone_detected(self) -> None:
        """US phone number pattern triggers PII rule."""
        rule = PolicyRule(
            name="pii-block",
            description="Block PII",
            action=PolicyDecision.DENY,
            conditions={"pii_detected": True},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="Call me at (555) 123-4567")
        )
        assert result.decision == PolicyDecision.DENY

    def test_clean_prompt_passes(self) -> None:
        """A prompt without PII passes the PII rule."""
        rule = PolicyRule(
            name="pii-block",
            description="Block PII",
            action=PolicyDecision.DENY,
            conditions={"pii_detected": True},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="What is the capital of France?")
        )
        assert result.decision == PolicyDecision.ALLOW


class TestDataClassification:
    """Tests for data classification gating."""

    def test_phi_requires_approval(self) -> None:
        """PHI classification triggers REQUIRE_APPROVAL."""
        rule = PolicyRule(
            name="phi-gate",
            description="Gate PHI",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"data_classification": ["PHI"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(data_classification="PHI"))
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL

    def test_public_data_passes(self) -> None:
        """Public classification does not trigger PHI rule."""
        rule = PolicyRule(
            name="phi-gate",
            description="Gate PHI",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"data_classification": ["PHI"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(data_classification="public"))
        assert result.decision == PolicyDecision.ALLOW

    def test_classification_from_metadata(self) -> None:
        """Data classification can come from metadata if field is not set."""
        rule = PolicyRule(
            name="pci-gate",
            description="Gate PCI",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"data_classification": ["PCI"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(metadata={"data_classification": "PCI"})
        )
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL


class TestJurisdiction:
    """Tests for jurisdiction-based policy rules."""

    def test_eu_jurisdiction_flagged(self) -> None:
        """EU jurisdiction triggers the appropriate rule."""
        rule = PolicyRule(
            name="eu-routing",
            description="EU data residency",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"jurisdiction": ["EU"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(jurisdiction="EU"))
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL

    def test_us_jurisdiction_passes(self) -> None:
        """US jurisdiction does not trigger EU rule."""
        rule = PolicyRule(
            name="eu-routing",
            description="EU data residency",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"jurisdiction": ["EU"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(jurisdiction="US"))
        assert result.decision == PolicyDecision.ALLOW


class TestKeywordBlocking:
    """Tests for content keyword blocking."""

    def test_blocked_keyword_denied(self) -> None:
        """Prompt containing a blocked keyword is denied."""
        rule = PolicyRule(
            name="keyword-block",
            description="Block harmful keywords",
            action=PolicyDecision.DENY,
            conditions={"blocked_keywords": ["jailbreak", "bypass safety"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="Please jailbreak the model")
        )
        assert result.decision == PolicyDecision.DENY

    def test_case_insensitive_matching(self) -> None:
        """Keyword matching is case-insensitive."""
        rule = PolicyRule(
            name="keyword-block",
            description="Block harmful keywords",
            action=PolicyDecision.DENY,
            conditions={"blocked_keywords": ["JAILBREAK"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="Please jailbreak the model")
        )
        assert result.decision == PolicyDecision.DENY

    def test_clean_prompt_passes_keyword_check(self) -> None:
        """A prompt without blocked keywords passes."""
        rule = PolicyRule(
            name="keyword-block",
            description="Block harmful keywords",
            action=PolicyDecision.DENY,
            conditions={"blocked_keywords": ["jailbreak"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="What is machine learning?")
        )
        assert result.decision == PolicyDecision.ALLOW


class TestModelAndClientBlocking:
    """Tests for model and client access control."""

    def test_blocked_model_denied(self) -> None:
        """A blocked model alias is denied."""
        rule = PolicyRule(
            name="model-block",
            description="Block dangerous models",
            action=PolicyDecision.DENY,
            conditions={"blocked_models": ["uncensored-model"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(model="uncensored-model"))
        assert result.decision == PolicyDecision.DENY

    def test_allowed_model_passes(self) -> None:
        """A non-blocked model passes."""
        rule = PolicyRule(
            name="model-block",
            description="Block dangerous models",
            action=PolicyDecision.DENY,
            conditions={"blocked_models": ["uncensored-model"]},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(model="default-chat"))
        assert result.decision == PolicyDecision.ALLOW


class TestPromptLength:
    """Tests for prompt length limits."""

    def test_oversized_prompt_flagged(self) -> None:
        """A prompt exceeding the length limit is flagged."""
        rule = PolicyRule(
            name="length-limit",
            description="Flag oversized prompts",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"max_prompt_length": 20},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(
            _make_context(prompt="x" * 50)
        )
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL

    def test_short_prompt_passes(self) -> None:
        """A prompt within the length limit passes."""
        rule = PolicyRule(
            name="length-limit",
            description="Flag oversized prompts",
            action=PolicyDecision.REQUIRE_APPROVAL,
            conditions={"max_prompt_length": 1000},
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(prompt="short"))
        assert result.decision == PolicyDecision.ALLOW


class TestRulePriority:
    """Tests for rule priority and escalation."""

    def test_deny_beats_require_approval(self) -> None:
        """DENY takes precedence over REQUIRE_APPROVAL."""
        rules = [
            PolicyRule(
                name="approval-rule",
                description="Approval",
                action=PolicyDecision.REQUIRE_APPROVAL,
                conditions={"blocked_clients": ["client-a"]},
            ),
            PolicyRule(
                name="deny-rule",
                description="Deny",
                action=PolicyDecision.DENY,
                conditions={"blocked_clients": ["client-a"]},
            ),
        ]
        engine = _make_engine(*rules)
        result = engine.evaluate(_make_context(client_id="client-a"))
        assert result.decision == PolicyDecision.DENY
        assert len(result.triggered_rules) == 2

    def test_disabled_rules_skipped(self) -> None:
        """Disabled rules are not evaluated."""
        rule = PolicyRule(
            name="disabled-rule",
            description="Should not trigger",
            action=PolicyDecision.DENY,
            conditions={"blocked_clients": ["client-a"]},
            enabled=False,
        )
        engine = _make_engine(rule)
        result = engine.evaluate(_make_context(client_id="client-a"))
        assert result.decision == PolicyDecision.ALLOW


class TestPolicyLoading:
    """Tests for loading policies from YAML files."""

    def test_load_valid_policy(self, tmp_path: Path) -> None:
        """A valid YAML policy file loads correctly."""
        policy_yaml = tmp_path / "test_policy.yaml"
        policy_yaml.write_text(
            """
version: "1.0"
rules:
  - name: test-rule
    description: A test rule
    action: DENY
    conditions:
      blocked_clients:
        - bad-client
    enabled: true
"""
        )
        config = load_policies(str(policy_yaml))
        assert config.version == "1.0"
        assert len(config.rules) == 1
        assert config.rules[0].name == "test-rule"
        assert config.rules[0].action == PolicyDecision.DENY

    def test_load_missing_file_raises(self) -> None:
        """Loading a nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_policies("/tmp/nonexistent_policy.yaml")

    def test_load_default_policy_file(self) -> None:
        """The default policy file loads without errors."""
        config = load_policies("config/policies/default.yaml")
        assert len(config.rules) > 0

    def test_rule_from_dict(self) -> None:
        """PolicyRule.from_dict handles all fields."""
        data = {
            "name": "test",
            "description": "desc",
            "action": "REQUIRE_APPROVAL",
            "conditions": {"jurisdiction": ["EU"]},
            "enabled": True,
        }
        rule = PolicyRule.from_dict(data)
        assert rule.name == "test"
        assert rule.action == PolicyDecision.REQUIRE_APPROVAL
        assert rule.conditions["jurisdiction"] == ["EU"]

    def test_rule_from_dict_defaults(self) -> None:
        """PolicyRule.from_dict uses sensible defaults."""
        rule = PolicyRule.from_dict({})
        assert rule.name == "unnamed-rule"
        assert rule.action == PolicyDecision.DENY
        assert rule.enabled is True
