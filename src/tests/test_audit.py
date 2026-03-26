"""Tests for the immutable, tamper-evident audit trail.

Covers:
- Hash chain integrity (each entry links to the previous)
- Tamper detection (modifying an entry breaks verification)
- Chain verification (verify_chain detects both valid and invalid chains)
- Merkle tree root computation
- Append-only storage semantics
- Chain resumption from existing file
"""

import json
from pathlib import Path

import pytest

from src.audit import (
    GENESIS_HASH,
    AuditEntry,
    AuditTrail,
    VerificationResult,
    compute_merkle_root,
    hash_content,
    verify_chain,
)


def _make_trail(tmp_path: Path) -> AuditTrail:
    """Create an AuditTrail writing to a temp directory."""
    return AuditTrail(str(tmp_path / "audit.jsonl"))


def _append_entry(
    trail: AuditTrail,
    request_id: str = "req-001",
    client_id: str = "client-a",
    model: str = "default-chat",
) -> AuditEntry:
    """Append a simple test entry to the trail."""
    return trail.append(
        request_id=request_id,
        client_id=client_id,
        model=model,
        action="chat_completion",
        prompt_hash=hash_content("test prompt"),
        response_hash=hash_content("test response"),
        policy_decision="ALLOW",
    )


class TestHashContent:
    """Tests for the hash_content helper."""

    def test_deterministic(self) -> None:
        """Same input produces the same hash."""
        assert hash_content("hello") == hash_content("hello")

    def test_different_inputs(self) -> None:
        """Different inputs produce different hashes."""
        assert hash_content("hello") != hash_content("world")

    def test_returns_hex_string(self) -> None:
        """Hash is a 64-character hex string (SHA-256)."""
        h = hash_content("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestAuditEntry:
    """Tests for AuditEntry hash computation and serialization."""

    def test_compute_chain_hash_deterministic(self) -> None:
        """The same entry always produces the same chain hash."""
        entry = AuditEntry(
            timestamp="2025-01-01T00:00:00+00:00",
            request_id="req-001",
            client_id="client-a",
            model="gpt-4o",
            action="chat_completion",
            prompt_hash="abc123",
            response_hash="def456",
            policy_decision="ALLOW",
            previous_hash=GENESIS_HASH,
        )
        h1 = entry.compute_chain_hash()
        h2 = entry.compute_chain_hash()
        assert h1 == h2

    def test_chain_hash_changes_with_content(self) -> None:
        """Modifying any field changes the chain hash."""
        entry = AuditEntry(
            timestamp="2025-01-01T00:00:00+00:00",
            request_id="req-001",
            client_id="client-a",
            model="gpt-4o",
            action="chat_completion",
            prompt_hash="abc123",
            response_hash="def456",
            policy_decision="ALLOW",
            previous_hash=GENESIS_HASH,
        )
        original_hash = entry.compute_chain_hash()

        # Modify the client_id
        entry.client_id = "client-b"
        modified_hash = entry.compute_chain_hash()
        assert original_hash != modified_hash

    def test_round_trip_serialization(self) -> None:
        """to_dict / from_dict preserves all fields."""
        entry = AuditEntry(
            timestamp="2025-01-01T00:00:00+00:00",
            request_id="req-001",
            client_id="client-a",
            model="gpt-4o",
            action="chat_completion",
            prompt_hash="abc123",
            response_hash="def456",
            policy_decision="ALLOW",
            previous_hash=GENESIS_HASH,
            chain_hash="somehash",
            metadata={"key": "value"},
        )
        restored = AuditEntry.from_dict(entry.to_dict())
        assert restored.request_id == entry.request_id
        assert restored.chain_hash == entry.chain_hash
        assert restored.metadata == entry.metadata


class TestAuditTrail:
    """Tests for the AuditTrail append-only log."""

    def test_first_entry_links_to_genesis(self, tmp_path: Path) -> None:
        """The first entry's previous_hash should be the genesis hash."""
        trail = _make_trail(tmp_path)
        entry = _append_entry(trail)
        assert entry.previous_hash == GENESIS_HASH

    def test_chain_linkage(self, tmp_path: Path) -> None:
        """Each entry's previous_hash equals the prior entry's chain_hash."""
        trail = _make_trail(tmp_path)
        e1 = _append_entry(trail, request_id="req-001")
        e2 = _append_entry(trail, request_id="req-002")
        e3 = _append_entry(trail, request_id="req-003")

        assert e2.previous_hash == e1.chain_hash
        assert e3.previous_hash == e2.chain_hash

    def test_entry_count(self, tmp_path: Path) -> None:
        """Entry count tracks the number of appended entries."""
        trail = _make_trail(tmp_path)
        assert trail.entry_count == 0

        _append_entry(trail, request_id="req-001")
        assert trail.entry_count == 1

        _append_entry(trail, request_id="req-002")
        assert trail.entry_count == 2

    def test_last_hash_updates(self, tmp_path: Path) -> None:
        """last_hash updates after each append."""
        trail = _make_trail(tmp_path)
        assert trail.last_hash == GENESIS_HASH

        e1 = _append_entry(trail)
        assert trail.last_hash == e1.chain_hash

    def test_append_only_file(self, tmp_path: Path) -> None:
        """Entries are written as JSONL (one JSON object per line)."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")
        _append_entry(trail, request_id="req-002")

        log_file = tmp_path / "audit.jsonl"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2

        for line in lines:
            data = json.loads(line)
            assert "chain_hash" in data
            assert "previous_hash" in data

    def test_read_entries(self, tmp_path: Path) -> None:
        """read_entries returns all persisted entries in order."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")
        _append_entry(trail, request_id="req-002")
        _append_entry(trail, request_id="req-003")

        entries = trail.read_entries()
        assert len(entries) == 3
        assert entries[0].request_id == "req-001"
        assert entries[2].request_id == "req-003"

    def test_resume_chain_from_existing_file(self, tmp_path: Path) -> None:
        """A new AuditTrail instance continues the chain from an existing file."""
        trail1 = _make_trail(tmp_path)
        e1 = _append_entry(trail1, request_id="req-001")
        e2 = _append_entry(trail1, request_id="req-002")

        # Create a new trail instance pointing to the same file
        trail2 = _make_trail(tmp_path)
        assert trail2.last_hash == e2.chain_hash
        assert trail2.entry_count == 2

        # New entry should link to e2
        e3 = _append_entry(trail2, request_id="req-003")
        assert e3.previous_hash == e2.chain_hash

    def test_metadata_stored(self, tmp_path: Path) -> None:
        """Custom metadata is persisted in the audit entry."""
        trail = _make_trail(tmp_path)
        entry = trail.append(
            request_id="req-meta",
            client_id="client-a",
            model="gpt-4o",
            action="chat_completion",
            prompt_hash="abc",
            response_hash="def",
            policy_decision="DENY",
            metadata={"reason": "pii_detected", "rule": "block-pii"},
        )
        assert entry.metadata["reason"] == "pii_detected"

        # Verify it persists to disk
        entries = trail.read_entries()
        assert entries[0].metadata["rule"] == "block-pii"


class TestVerifyChain:
    """Tests for the verify_chain function."""

    def test_empty_chain_is_valid(self) -> None:
        """An empty chain is considered valid."""
        result = verify_chain([])
        assert result.valid is True
        assert result.entry_count == 0

    def test_valid_chain(self, tmp_path: Path) -> None:
        """A properly constructed chain passes verification."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")
        _append_entry(trail, request_id="req-002")
        _append_entry(trail, request_id="req-003")

        entries = trail.read_entries()
        result = verify_chain(entries)

        assert result.valid is True
        assert result.entry_count == 3
        assert result.errors == []
        assert len(result.merkle_root) == 64

    def test_tampered_entry_detected(self, tmp_path: Path) -> None:
        """Modifying an entry's field causes verification to fail."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")
        _append_entry(trail, request_id="req-002")
        _append_entry(trail, request_id="req-003")

        entries = trail.read_entries()

        # Tamper with the second entry's client_id
        entries[1].client_id = "tampered-client"

        result = verify_chain(entries)
        assert result.valid is False
        assert len(result.errors) > 0

    def test_broken_chain_link_detected(self, tmp_path: Path) -> None:
        """Modifying an entry's previous_hash breaks the chain."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")
        _append_entry(trail, request_id="req-002")

        entries = trail.read_entries()

        # Break the chain link
        entries[1].previous_hash = "0" * 64

        result = verify_chain(entries)
        assert result.valid is False
        assert any("previous_hash" in err for err in result.errors)

    def test_corrupted_genesis_detected(self, tmp_path: Path) -> None:
        """A first entry with wrong previous_hash is detected."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")

        entries = trail.read_entries()
        entries[0].previous_hash = "bad" * 21 + "b"

        result = verify_chain(entries)
        assert result.valid is False
        assert any("genesis" in err for err in result.errors)

    def test_deleted_entry_detected(self, tmp_path: Path) -> None:
        """Removing an entry from the middle breaks chain verification."""
        trail = _make_trail(tmp_path)
        _append_entry(trail, request_id="req-001")
        _append_entry(trail, request_id="req-002")
        _append_entry(trail, request_id="req-003")

        entries = trail.read_entries()

        # Remove the middle entry
        del entries[1]

        result = verify_chain(entries)
        assert result.valid is False


class TestMerkleRoot:
    """Tests for the Merkle tree root computation."""

    def test_empty_list(self) -> None:
        """Empty hash list returns genesis hash."""
        assert compute_merkle_root([]) == GENESIS_HASH

    def test_single_hash(self) -> None:
        """Single hash returns itself (no combination needed)."""
        h = "a" * 64
        assert compute_merkle_root([h]) == h

    def test_two_hashes(self) -> None:
        """Two hashes are combined into a single root."""
        h1 = "a" * 64
        h2 = "b" * 64
        root = compute_merkle_root([h1, h2])
        assert len(root) == 64
        assert root != h1
        assert root != h2

    def test_deterministic(self) -> None:
        """Same inputs always produce the same root."""
        hashes = ["a" * 64, "b" * 64, "c" * 64]
        assert compute_merkle_root(hashes) == compute_merkle_root(hashes)

    def test_order_matters(self) -> None:
        """Different ordering produces a different root."""
        h1 = "a" * 64
        h2 = "b" * 64
        root1 = compute_merkle_root([h1, h2])
        root2 = compute_merkle_root([h2, h1])
        assert root1 != root2
