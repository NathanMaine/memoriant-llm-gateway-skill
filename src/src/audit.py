"""Immutable, tamper-evident audit trail for the governed LLM gateway.

Implements a hash-chain linked audit log where each entry includes a SHA-256
hash of the previous entry, creating a cryptographic chain of custody. This
provides tamper evidence -- if any historical entry is modified, the chain
breaks and verify_chain() will detect it.

Design principles:
- Append-only JSONL storage (never overwrite or delete)
- Hash the prompt and response, never store raw content
- Merkle tree root computation for periodic verification
- Every entry includes: timestamp, request_id, client_id, model, action,
  prompt_hash, response_hash, policy_decision, chain_hash
"""

import hashlib
import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger("gateway")


# The genesis hash used as the "previous hash" for the first entry in the chain.
GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    """A single immutable audit log entry in the hash chain."""

    timestamp: str
    request_id: str
    client_id: str
    model: str
    action: str
    prompt_hash: str
    response_hash: str
    policy_decision: str
    previous_hash: str
    chain_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_chain_hash(self) -> str:
        """Compute the SHA-256 chain hash for this entry.

        The hash covers all fields except chain_hash itself, ensuring that
        any modification to the entry (including the previous_hash link)
        will produce a different hash.
        """
        fields = {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "client_id": self.client_id,
            "model": self.model,
            "action": self.action,
            "prompt_hash": self.prompt_hash,
            "response_hash": self.response_hash,
            "policy_decision": self.policy_decision,
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the entry to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Deserialize an entry from a dictionary."""
        return cls(**data)


def hash_content(content: str) -> str:
    """Hash content using SHA-256. Used for prompts and responses.

    We never store raw prompt or response text in the audit trail.
    Instead we store a cryptographic hash that can be used to verify
    content without exposing it.

    Args:
        content: The raw text to hash.

    Returns:
        A hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AuditTrail:
    """Append-only, hash-chain linked audit log.

    Thread-safe. Writes entries as JSONL (one JSON object per line) to the
    configured file path. The chain is initialized from existing entries on
    disk if the file already exists.
    """

    def __init__(self, log_path: str) -> None:
        self._log_path = Path(log_path)
        self._lock = threading.Lock()
        self._last_hash: str = GENESIS_HASH
        self._entry_count: int = 0

        # Ensure the parent directory exists
        os.makedirs(self._log_path.parent, exist_ok=True)

        # If the file exists, read the last hash to continue the chain
        if self._log_path.exists() and self._log_path.stat().st_size > 0:
            self._resume_chain()

    def _resume_chain(self) -> None:
        """Read existing entries to find the last chain hash."""
        with open(self._log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry_data = json.loads(line)
                    self._last_hash = entry_data.get("chain_hash", GENESIS_HASH)
                    self._entry_count += 1
                except json.JSONDecodeError as e:
                    _logger.warning(
                        "Corrupt audit entry at line %d: %s",
                        self._entry_count + 1,
                        e,
                    )
                    continue

    def append(
        self,
        *,
        request_id: str,
        client_id: str,
        model: str,
        action: str,
        prompt_hash: str,
        response_hash: str,
        policy_decision: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Create and persist a new audit entry linked to the chain.

        Args:
            request_id: Gateway-assigned request identifier.
            client_id: The caller's identifier.
            model: The model alias or identifier used.
            action: The action performed (e.g. "chat_completion").
            prompt_hash: SHA-256 hash of the prompt content.
            response_hash: SHA-256 hash of the response content.
            policy_decision: The policy engine's decision (ALLOW/DENY/REQUIRE_APPROVAL).
            metadata: Optional additional metadata.

        Returns:
            The persisted AuditEntry with computed chain_hash.
        """
        with self._lock:
            entry = AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                request_id=request_id,
                client_id=client_id,
                model=model,
                action=action,
                prompt_hash=prompt_hash,
                response_hash=response_hash,
                policy_decision=policy_decision,
                previous_hash=self._last_hash,
                metadata=metadata or {},
            )
            entry.chain_hash = entry.compute_chain_hash()

            # Append to the JSONL file (atomic within a single write)
            with open(self._log_path, "a") as f:
                f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")

            self._last_hash = entry.chain_hash
            self._entry_count += 1

            return entry

    @property
    def last_hash(self) -> str:
        """Return the most recent chain hash."""
        return self._last_hash

    @property
    def entry_count(self) -> int:
        """Return the total number of entries in the chain."""
        return self._entry_count

    def read_entries(self) -> List[AuditEntry]:
        """Read all entries from the audit log file.

        Returns:
            A list of AuditEntry objects in chronological order.
        """
        entries: List[AuditEntry] = []
        if not self._log_path.exists():
            return entries

        with open(self._log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry.from_dict(data))
                except (json.JSONDecodeError, TypeError) as e:
                    _logger.warning("Skipping corrupt audit entry: %s", e)
                    continue

        return entries


def verify_chain(entries: List[AuditEntry]) -> "VerificationResult":
    """Verify the integrity of a sequence of audit entries.

    Checks that:
    1. Each entry's chain_hash matches its computed hash.
    2. Each entry's previous_hash matches the prior entry's chain_hash.
    3. The first entry's previous_hash is the genesis hash.

    Args:
        entries: Ordered list of audit entries to verify.

    Returns:
        A VerificationResult indicating whether the chain is intact.
    """
    if not entries:
        return VerificationResult(
            valid=True, entry_count=0, errors=[], merkle_root=GENESIS_HASH
        )

    errors: List[str] = []

    # Check genesis entry
    if entries[0].previous_hash != GENESIS_HASH:
        errors.append(
            "Entry 0 ({}): previous_hash is not the genesis hash".format(
                entries[0].request_id
            )
        )

    for i, entry in enumerate(entries):
        # Verify the entry's own hash
        expected_hash = entry.compute_chain_hash()
        if entry.chain_hash != expected_hash:
            errors.append(
                "Entry {} ({}): chain_hash mismatch (expected {}, got {})".format(
                    i, entry.request_id, expected_hash[:16], entry.chain_hash[:16]
                )
            )

        # Verify chain linkage (skip for the first entry, already checked above)
        if i > 0:
            if entry.previous_hash != entries[i - 1].chain_hash:
                errors.append(
                    "Entry {} ({}): previous_hash does not match entry {}'s chain_hash".format(
                        i, entry.request_id, i - 1
                    )
                )

    # Compute Merkle root from all chain hashes
    merkle_root = compute_merkle_root([e.chain_hash for e in entries])

    return VerificationResult(
        valid=len(errors) == 0,
        entry_count=len(entries),
        errors=errors,
        merkle_root=merkle_root,
    )


@dataclass
class VerificationResult:
    """Result of a hash-chain verification."""

    valid: bool
    entry_count: int
    errors: List[str]
    merkle_root: str


def compute_merkle_root(hashes: List[str]) -> str:
    """Compute a Merkle tree root from a list of hash strings.

    Uses SHA-256 to combine pairs of hashes bottom-up. If the number of
    hashes at any level is odd, the last hash is duplicated.

    Args:
        hashes: List of hex-encoded hash strings.

    Returns:
        The hex-encoded Merkle root hash.
    """
    if not hashes:
        return GENESIS_HASH

    current_level = list(hashes)

    while len(current_level) > 1:
        next_level: List[str] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number of nodes, duplicate the last one
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256(
                (left + right).encode("utf-8")
            ).hexdigest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0]
