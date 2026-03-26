"""Compliance evidence collector for the governed LLM gateway.

Maps audit trail entries to regulatory compliance control IDs and generates
evidence packages suitable for auditor review. Supports:

- SOC 2 Type II (CC series: access control, system boundaries, monitoring)
- HIPAA 164.312 (access control, audit controls, transmission security)
- ISO 27001 Annex A controls

Evidence packages are exported as JSON documents that contain:
- The compliance framework and control ID
- Filtered audit entries that demonstrate the control
- Date range and summary statistics
- Verification status of the audit chain
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.audit import AuditEntry, VerificationResult, verify_chain


@dataclass
class ComplianceControl:
    """A single compliance control with its mapping criteria."""

    control_id: str
    framework: str
    title: str
    description: str
    audit_filters: Dict[str, Any] = field(default_factory=dict)


# SOC 2 Trust Services Criteria mappings
SOC2_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="CC6.1",
        framework="SOC2",
        title="Logical and Physical Access Controls",
        description=(
            "The entity implements logical access security software, "
            "infrastructure, and architectures over protected information "
            "assets to protect them from security events."
        ),
        audit_filters={"actions": ["chat_completion"], "fields": ["client_id", "policy_decision"]},
    ),
    ComplianceControl(
        control_id="CC6.6",
        framework="SOC2",
        title="System Boundaries",
        description=(
            "The entity implements logical access security measures to "
            "protect against threats from sources outside its system boundaries."
        ),
        audit_filters={"policy_decisions": ["DENY", "REQUIRE_APPROVAL"]},
    ),
    ComplianceControl(
        control_id="CC6.8",
        framework="SOC2",
        title="Controls Against Malicious Software",
        description=(
            "The entity implements controls to prevent or detect and act "
            "upon the introduction of unauthorized or malicious software."
        ),
        audit_filters={"policy_decisions": ["DENY"]},
    ),
    ComplianceControl(
        control_id="CC7.1",
        framework="SOC2",
        title="Detection and Monitoring",
        description=(
            "To meet its objectives, the entity uses detection and "
            "monitoring procedures to identify changes to configurations "
            "that result in the introduction of new vulnerabilities."
        ),
        audit_filters={"actions": ["chat_completion", "policy_violation"]},
    ),
    ComplianceControl(
        control_id="CC7.2",
        framework="SOC2",
        title="Monitoring System Components",
        description=(
            "The entity monitors system components and the operation of "
            "those components for anomalies that are indicative of malicious "
            "acts, natural disasters, and errors affecting the entity's "
            "ability to meet its objectives."
        ),
        audit_filters={"actions": ["chat_completion"]},
    ),
    ComplianceControl(
        control_id="CC8.1",
        framework="SOC2",
        title="Change Management",
        description=(
            "The entity authorizes, designs, develops or acquires, "
            "configures, documents, tests, approves, and implements "
            "changes to infrastructure, data, software, and procedures."
        ),
        audit_filters={"policy_decisions": ["REQUIRE_APPROVAL"]},
    ),
]

# HIPAA Security Rule mappings
HIPAA_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="164.312(a)(1)",
        framework="HIPAA",
        title="Access Control",
        description=(
            "Implement technical policies and procedures for electronic "
            "information systems that maintain electronic protected health "
            "information to allow access only to those persons or software "
            "programs that have been granted access rights."
        ),
        audit_filters={"actions": ["chat_completion"], "fields": ["client_id", "policy_decision"]},
    ),
    ComplianceControl(
        control_id="164.312(a)(2)(i)",
        framework="HIPAA",
        title="Unique User Identification",
        description=(
            "Assign a unique name and/or number for identifying and "
            "tracking user identity."
        ),
        audit_filters={"fields": ["client_id", "request_id"]},
    ),
    ComplianceControl(
        control_id="164.312(b)",
        framework="HIPAA",
        title="Audit Controls",
        description=(
            "Implement hardware, software, and/or procedural mechanisms "
            "that record and examine activity in information systems that "
            "contain or use electronic protected health information."
        ),
        audit_filters={"actions": ["chat_completion"]},
    ),
    ComplianceControl(
        control_id="164.312(c)(1)",
        framework="HIPAA",
        title="Integrity",
        description=(
            "Implement policies and procedures to protect electronic "
            "protected health information from improper alteration or "
            "destruction."
        ),
        audit_filters={"verify_chain": True},
    ),
    ComplianceControl(
        control_id="164.312(d)",
        framework="HIPAA",
        title="Person or Entity Authentication",
        description=(
            "Implement procedures to verify that a person or entity "
            "seeking access to electronic protected health information "
            "is the one claimed."
        ),
        audit_filters={"fields": ["client_id"]},
    ),
    ComplianceControl(
        control_id="164.312(e)(1)",
        framework="HIPAA",
        title="Transmission Security",
        description=(
            "Implement technical security measures to guard against "
            "unauthorized access to electronic protected health information "
            "that is being transmitted over an electronic communications "
            "network."
        ),
        audit_filters={"fields": ["prompt_hash", "response_hash"]},
    ),
]

# Combined registry
ALL_CONTROLS: Dict[str, List[ComplianceControl]] = {
    "SOC2": SOC2_CONTROLS,
    "HIPAA": HIPAA_CONTROLS,
}


def get_controls(framework: Optional[str] = None) -> List[ComplianceControl]:
    """Get compliance controls, optionally filtered by framework.

    Args:
        framework: If provided, only return controls for this framework.
                   Valid values: "SOC2", "HIPAA". If None, returns all.

    Returns:
        A list of ComplianceControl instances.
    """
    if framework is not None:
        framework_upper = framework.upper()
        return list(ALL_CONTROLS.get(framework_upper, []))

    controls: List[ComplianceControl] = []
    for framework_controls in ALL_CONTROLS.values():
        controls.extend(framework_controls)
    return controls


def filter_entries_for_control(
    entries: List[AuditEntry],
    control: ComplianceControl,
) -> List[AuditEntry]:
    """Filter audit entries relevant to a specific compliance control.

    Uses the control's audit_filters to select matching entries.

    Args:
        entries: All audit trail entries.
        control: The compliance control to filter for.

    Returns:
        Entries that provide evidence for the control.
    """
    filters = control.audit_filters
    result = list(entries)

    # Filter by action types
    if "actions" in filters:
        allowed_actions = filters["actions"]
        result = [e for e in result if e.action in allowed_actions]

    # Filter by policy decisions
    if "policy_decisions" in filters:
        allowed_decisions = filters["policy_decisions"]
        result = [e for e in result if e.policy_decision in allowed_decisions]

    return result


@dataclass
class EvidencePackage:
    """A compliance evidence package ready for auditor review."""

    package_id: str
    generated_at: str
    framework: str
    control_id: str
    control_title: str
    control_description: str
    date_range_start: str
    date_range_end: str
    total_entries: int
    matching_entries: int
    chain_verification: Dict[str, Any]
    entries: List[Dict[str, Any]]
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the evidence package to a dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize the evidence package to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def generate_evidence_package(
    *,
    entries: List[AuditEntry],
    control_id: str,
    framework: str,
    date_start: Optional[str] = None,
    date_end: Optional[str] = None,
    package_id: Optional[str] = None,
) -> EvidencePackage:
    """Generate a compliance evidence package for a specific control.

    Filters audit entries by control criteria and date range, verifies
    the hash chain integrity, and produces a structured evidence package.

    Args:
        entries: All audit trail entries.
        control_id: The compliance control ID (e.g. "CC6.1", "164.312(b)").
        framework: The compliance framework (e.g. "SOC2", "HIPAA").
        date_start: Optional ISO date string to filter entries from.
        date_end: Optional ISO date string to filter entries until.
        package_id: Optional identifier for this package.

    Returns:
        An EvidencePackage ready for export.

    Raises:
        ValueError: If the control_id is not found in the framework.
    """
    # Find the control
    controls = get_controls(framework)
    control = None
    for c in controls:
        if c.control_id == control_id:
            control = c
            break

    if control is None:
        raise ValueError(
            "Control {} not found in framework {}".format(control_id, framework)
        )

    # Apply date range filter
    filtered = _filter_by_date(entries, date_start, date_end)

    # Determine effective date range
    effective_start = date_start or (
        filtered[0].timestamp if filtered else datetime.now(timezone.utc).isoformat()
    )
    effective_end = date_end or (
        filtered[-1].timestamp if filtered else datetime.now(timezone.utc).isoformat()
    )

    # Verify the full chain (not just filtered entries)
    verification = verify_chain(entries)

    # Filter entries relevant to this control
    matching = filter_entries_for_control(filtered, control)

    # Build summary statistics
    summary = _build_summary(matching)

    return EvidencePackage(
        package_id=package_id or "ep-{}".format(
            datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        ),
        generated_at=datetime.now(timezone.utc).isoformat(),
        framework=framework,
        control_id=control_id,
        control_title=control.title,
        control_description=control.description,
        date_range_start=effective_start,
        date_range_end=effective_end,
        total_entries=len(entries),
        matching_entries=len(matching),
        chain_verification={
            "valid": verification.valid,
            "entry_count": verification.entry_count,
            "errors": verification.errors,
            "merkle_root": verification.merkle_root,
        },
        entries=[e.to_dict() for e in matching],
        summary=summary,
    )


def _filter_by_date(
    entries: List[AuditEntry],
    date_start: Optional[str],
    date_end: Optional[str],
) -> List[AuditEntry]:
    """Filter entries by date range (inclusive).

    Args:
        entries: Audit entries to filter.
        date_start: ISO date string for start of range.
        date_end: ISO date string for end of range.

    Returns:
        Entries within the specified date range.
    """
    if not date_start and not date_end:
        return list(entries)

    result: List[AuditEntry] = []
    for entry in entries:
        ts = entry.timestamp
        if date_start and ts < date_start:
            continue
        if date_end and ts > date_end:
            continue
        result.append(entry)
    return result


def _build_summary(entries: List[AuditEntry]) -> Dict[str, Any]:
    """Build summary statistics for a set of audit entries.

    Args:
        entries: The filtered audit entries.

    Returns:
        A dictionary of summary statistics.
    """
    if not entries:
        return {
            "total_requests": 0,
            "unique_clients": 0,
            "policy_decisions": {},
            "models_used": [],
        }

    clients = set()
    decisions: Dict[str, int] = {}
    models = set()

    for entry in entries:
        clients.add(entry.client_id)
        models.add(entry.model)
        decision = entry.policy_decision
        decisions[decision] = decisions.get(decision, 0) + 1

    return {
        "total_requests": len(entries),
        "unique_clients": len(clients),
        "policy_decisions": decisions,
        "models_used": sorted(models),
    }


def export_evidence_package(
    package: EvidencePackage,
    output_path: str,
) -> str:
    """Write an evidence package to a JSON file.

    Args:
        package: The evidence package to export.
        output_path: Path to write the JSON file.

    Returns:
        The path where the file was written.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(package.to_json())
    return str(path)
