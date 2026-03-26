"""Tests for the compliance evidence collector.

Covers:
- Control ID mapping for SOC2 and HIPAA frameworks
- Evidence package generation with correct structure
- Date range filtering
- Chain verification inclusion in evidence packages
- Summary statistics computation
- Export to JSON file
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from src.audit import GENESIS_HASH, AuditEntry, AuditTrail, hash_content
from src.compliance import (
    ALL_CONTROLS,
    EvidencePackage,
    HIPAA_CONTROLS,
    SOC2_CONTROLS,
    export_evidence_package,
    filter_entries_for_control,
    generate_evidence_package,
    get_controls,
)


def _make_entries(count: int = 5, base_time: str = "2025-06-") -> List[AuditEntry]:
    """Create a list of linked audit entries for testing."""
    entries: List[AuditEntry] = []
    previous_hash = GENESIS_HASH

    for i in range(count):
        day = str(i + 1).zfill(2)
        entry = AuditEntry(
            timestamp="{}{}T12:00:00+00:00".format(base_time, day),
            request_id="req-{:03d}".format(i + 1),
            client_id="client-{}".format("a" if i % 2 == 0 else "b"),
            model="default-chat",
            action="chat_completion",
            prompt_hash=hash_content("prompt {}".format(i)),
            response_hash=hash_content("response {}".format(i)),
            policy_decision="ALLOW" if i % 3 != 0 else "DENY",
            previous_hash=previous_hash,
        )
        entry.chain_hash = entry.compute_chain_hash()
        previous_hash = entry.chain_hash
        entries.append(entry)

    return entries


def _make_trail_with_entries(tmp_path: Path, count: int = 5) -> List[AuditEntry]:
    """Create an AuditTrail on disk and return the entries."""
    trail = AuditTrail(str(tmp_path / "audit.jsonl"))
    entries: List[AuditEntry] = []
    for i in range(count):
        entry = trail.append(
            request_id="req-{:03d}".format(i + 1),
            client_id="client-{}".format("a" if i % 2 == 0 else "b"),
            model="default-chat",
            action="chat_completion",
            prompt_hash=hash_content("prompt {}".format(i)),
            response_hash=hash_content("response {}".format(i)),
            policy_decision="ALLOW" if i % 3 != 0 else "DENY",
        )
        entries.append(entry)
    return entries


class TestControlRegistry:
    """Tests for the compliance control definitions."""

    def test_soc2_controls_exist(self) -> None:
        """SOC2 controls are defined."""
        assert len(SOC2_CONTROLS) > 0

    def test_hipaa_controls_exist(self) -> None:
        """HIPAA controls are defined."""
        assert len(HIPAA_CONTROLS) > 0

    def test_get_all_controls(self) -> None:
        """get_controls() without a framework returns all controls."""
        all_controls = get_controls()
        assert len(all_controls) == len(SOC2_CONTROLS) + len(HIPAA_CONTROLS)

    def test_get_soc2_controls(self) -> None:
        """get_controls('SOC2') returns only SOC2 controls."""
        controls = get_controls("SOC2")
        assert all(c.framework == "SOC2" for c in controls)
        assert len(controls) == len(SOC2_CONTROLS)

    def test_get_hipaa_controls(self) -> None:
        """get_controls('HIPAA') returns only HIPAA controls."""
        controls = get_controls("HIPAA")
        assert all(c.framework == "HIPAA" for c in controls)
        assert len(controls) == len(HIPAA_CONTROLS)

    def test_unknown_framework_returns_empty(self) -> None:
        """An unknown framework returns an empty list."""
        controls = get_controls("UNKNOWN")
        assert controls == []

    def test_soc2_cc61_exists(self) -> None:
        """SOC2 CC6.1 (access control) is defined."""
        controls = get_controls("SOC2")
        ids = [c.control_id for c in controls]
        assert "CC6.1" in ids

    def test_soc2_cc66_exists(self) -> None:
        """SOC2 CC6.6 (system boundaries) is defined."""
        controls = get_controls("SOC2")
        ids = [c.control_id for c in controls]
        assert "CC6.6" in ids

    def test_soc2_cc72_exists(self) -> None:
        """SOC2 CC7.2 (monitoring) is defined."""
        controls = get_controls("SOC2")
        ids = [c.control_id for c in controls]
        assert "CC7.2" in ids

    def test_hipaa_access_control_exists(self) -> None:
        """HIPAA 164.312(a)(1) (access control) is defined."""
        controls = get_controls("HIPAA")
        ids = [c.control_id for c in controls]
        assert "164.312(a)(1)" in ids

    def test_hipaa_audit_controls_exists(self) -> None:
        """HIPAA 164.312(b) (audit controls) is defined."""
        controls = get_controls("HIPAA")
        ids = [c.control_id for c in controls]
        assert "164.312(b)" in ids

    def test_hipaa_transmission_security_exists(self) -> None:
        """HIPAA 164.312(e)(1) (transmission security) is defined."""
        controls = get_controls("HIPAA")
        ids = [c.control_id for c in controls]
        assert "164.312(e)(1)" in ids


class TestFilterEntries:
    """Tests for filtering entries by control criteria."""

    def test_filter_by_action(self) -> None:
        """Entries are filtered by allowed actions."""
        entries = _make_entries(5)
        control = SOC2_CONTROLS[0]  # CC6.1 -- filters by chat_completion action
        filtered = filter_entries_for_control(entries, control)
        assert all(e.action == "chat_completion" for e in filtered)

    def test_filter_by_policy_decision(self) -> None:
        """Entries are filtered by policy decision."""
        entries = _make_entries(6)
        control = SOC2_CONTROLS[1]  # CC6.6 -- filters for DENY/REQUIRE_APPROVAL
        filtered = filter_entries_for_control(entries, control)
        for e in filtered:
            assert e.policy_decision in ("DENY", "REQUIRE_APPROVAL")

    def test_filter_returns_subset(self) -> None:
        """Filtering returns a subset of the original entries."""
        entries = _make_entries(10)
        control = SOC2_CONTROLS[1]  # CC6.6
        filtered = filter_entries_for_control(entries, control)
        assert len(filtered) <= len(entries)


class TestGenerateEvidencePackage:
    """Tests for evidence package generation."""

    def test_basic_evidence_package(self, tmp_path: Path) -> None:
        """A basic evidence package has the correct structure."""
        entries = _make_trail_with_entries(tmp_path, 5)
        package = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
            package_id="test-pkg-001",
        )

        assert package.package_id == "test-pkg-001"
        assert package.framework == "SOC2"
        assert package.control_id == "CC7.2"
        assert package.control_title == "Monitoring System Components"
        assert package.total_entries == 5
        assert package.matching_entries > 0
        assert package.chain_verification["valid"] is True

    def test_evidence_package_chain_verification(self, tmp_path: Path) -> None:
        """Evidence package includes chain verification results."""
        entries = _make_trail_with_entries(tmp_path, 3)
        package = generate_evidence_package(
            entries=entries,
            control_id="164.312(b)",
            framework="HIPAA",
        )

        assert "valid" in package.chain_verification
        assert "merkle_root" in package.chain_verification
        assert "entry_count" in package.chain_verification
        assert package.chain_verification["valid"] is True
        assert package.chain_verification["entry_count"] == 3

    def test_evidence_package_with_date_range(self) -> None:
        """Date range filtering limits evidence entries."""
        entries = _make_entries(10)
        package = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
            date_start="2025-06-03T00:00:00+00:00",
            date_end="2025-06-07T00:00:00+00:00",
        )

        assert package.date_range_start == "2025-06-03T00:00:00+00:00"
        assert package.date_range_end == "2025-06-07T00:00:00+00:00"
        # Matching entries should be a subset within the date range
        assert package.matching_entries <= 5

    def test_unknown_control_raises(self) -> None:
        """Requesting an unknown control ID raises ValueError."""
        entries = _make_entries(3)
        with pytest.raises(ValueError, match="not found"):
            generate_evidence_package(
                entries=entries,
                control_id="NONEXISTENT",
                framework="SOC2",
            )

    def test_unknown_framework_raises(self) -> None:
        """Requesting an unknown framework raises ValueError."""
        entries = _make_entries(3)
        with pytest.raises(ValueError, match="not found"):
            generate_evidence_package(
                entries=entries,
                control_id="CC6.1",
                framework="UNKNOWN",
            )

    def test_summary_statistics(self, tmp_path: Path) -> None:
        """Summary includes correct aggregate statistics."""
        entries = _make_trail_with_entries(tmp_path, 6)
        package = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
        )

        assert "total_requests" in package.summary
        assert "unique_clients" in package.summary
        assert "policy_decisions" in package.summary
        assert "models_used" in package.summary
        assert package.summary["total_requests"] > 0

    def test_empty_entries(self) -> None:
        """An evidence package with no entries still has valid structure."""
        package = generate_evidence_package(
            entries=[],
            control_id="CC6.6",
            framework="SOC2",
        )

        assert package.matching_entries == 0
        assert package.total_entries == 0
        assert package.chain_verification["valid"] is True
        assert package.entries == []


class TestEvidencePackageSerialization:
    """Tests for evidence package serialization."""

    def test_to_dict(self, tmp_path: Path) -> None:
        """to_dict returns a plain dictionary."""
        entries = _make_trail_with_entries(tmp_path, 3)
        package = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
        )
        d = package.to_dict()
        assert isinstance(d, dict)
        assert d["framework"] == "SOC2"
        assert d["control_id"] == "CC7.2"

    def test_to_json(self, tmp_path: Path) -> None:
        """to_json returns valid JSON."""
        entries = _make_trail_with_entries(tmp_path, 3)
        package = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
        )
        json_str = package.to_json()
        parsed = json.loads(json_str)
        assert parsed["framework"] == "SOC2"

    def test_export_to_file(self, tmp_path: Path) -> None:
        """export_evidence_package writes a JSON file."""
        entries = _make_trail_with_entries(tmp_path, 3)
        package = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
        )
        output_path = str(tmp_path / "evidence" / "test_package.json")
        result_path = export_evidence_package(package, output_path)

        assert Path(result_path).exists()
        with open(result_path) as f:
            data = json.load(f)
        assert data["control_id"] == "CC7.2"
        assert data["framework"] == "SOC2"


class TestCrossFramework:
    """Tests that evidence packages work across frameworks."""

    def test_soc2_and_hipaa_same_entries(self, tmp_path: Path) -> None:
        """The same entries can generate packages for different frameworks."""
        entries = _make_trail_with_entries(tmp_path, 5)

        soc2_pkg = generate_evidence_package(
            entries=entries,
            control_id="CC7.2",
            framework="SOC2",
        )
        hipaa_pkg = generate_evidence_package(
            entries=entries,
            control_id="164.312(b)",
            framework="HIPAA",
        )

        assert soc2_pkg.framework == "SOC2"
        assert hipaa_pkg.framework == "HIPAA"
        assert soc2_pkg.total_entries == hipaa_pkg.total_entries
        # Both should pass chain verification
        assert soc2_pkg.chain_verification["valid"] is True
        assert hipaa_pkg.chain_verification["valid"] is True
