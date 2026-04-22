"""Tests for SignedEvidence envelope and integrity state enum."""

from __future__ import annotations

from datetime import UTC, datetime


def _sample_event():
    from lemma.models.ocsf import ComplianceFinding

    return ComplianceFinding(
        class_name="Compliance Finding",
        category_uid=2000,
        category_name="Findings",
        type_uid=200301,
        activity_id=1,
        time=datetime.now(UTC),
    )


def test_integrity_state_enum_values():
    from lemma.models.signed_evidence import EvidenceIntegrityState

    assert EvidenceIntegrityState.PROVEN.value == "PROVEN"
    assert EvidenceIntegrityState.DEGRADED.value == "DEGRADED"
    assert EvidenceIntegrityState.VIOLATED.value == "VIOLATED"


def test_signed_evidence_requires_event_and_chain_fields():
    from lemma.models.signed_evidence import ProvenanceRecord, SignedEvidence

    envelope = SignedEvidence(
        event=_sample_event(),
        prev_hash="0" * 64,
        entry_hash="a" * 64,
        signature="deadbeef",
        signer_key_id="ed25519:test0000",
        provenance=[ProvenanceRecord(stage="storage", actor="lemma", content_hash="a" * 64)],
    )

    assert envelope.prev_hash == "0" * 64
    assert envelope.entry_hash == "a" * 64
    assert envelope.signature == "deadbeef"
    assert envelope.signer_key_id.startswith("ed25519:")
    assert envelope.event.class_uid == 2003
    assert len(envelope.provenance) == 1
    assert envelope.provenance[0].stage == "storage"


def test_signed_evidence_round_trips_through_json():
    import json

    from lemma.models.ocsf import ComplianceFinding
    from lemma.models.signed_evidence import SignedEvidence

    envelope = SignedEvidence(
        event=_sample_event(),
        prev_hash="0" * 64,
        entry_hash="b" * 64,
        signature="cafe",
        signer_key_id="ed25519:abcd1234",
    )
    serialized = envelope.model_dump_json()
    payload = json.loads(serialized)

    # Event is nested under 'event' with the OCSF shape intact
    assert payload["event"]["class_uid"] == 2003

    # Round-trip back into the model
    revived = SignedEvidence.model_validate_json(serialized)
    assert isinstance(revived.event, ComplianceFinding)
    assert revived.entry_hash == envelope.entry_hash


def test_provenance_record_has_timestamp_by_default():
    from lemma.models.signed_evidence import ProvenanceRecord

    record = ProvenanceRecord(stage="storage", actor="lemma", content_hash="x" * 64)
    assert record.timestamp is not None
    assert record.stage == "storage"


def test_signed_evidence_has_signed_at_timestamp():
    """signed_at records when the envelope was written, distinct from event.time."""
    from lemma.models.signed_evidence import SignedEvidence

    envelope = SignedEvidence(
        event=_sample_event(),
        prev_hash="0" * 64,
        entry_hash="c" * 64,
        signature="sig",
        signer_key_id="ed25519:sample00",
    )
    assert envelope.signed_at is not None
    # Default is UTC-aware
    assert envelope.signed_at.tzinfo is not None
