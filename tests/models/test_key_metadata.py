"""Tests for evidence-signing key lifecycle metadata."""

from __future__ import annotations

from datetime import UTC, datetime


def test_key_status_enum_values():
    from lemma.models.key_metadata import KeyStatus

    assert KeyStatus.ACTIVE.value == "ACTIVE"
    assert KeyStatus.RETIRED.value == "RETIRED"
    assert KeyStatus.REVOKED.value == "REVOKED"


def test_key_record_active_defaults():
    from lemma.models.key_metadata import KeyRecord, KeyStatus

    activated = datetime.now(UTC)
    record = KeyRecord(
        key_id="ed25519:abcd1234",
        status=KeyStatus.ACTIVE,
        activated_at=activated,
    )

    assert record.status == KeyStatus.ACTIVE
    assert record.retired_at is None
    assert record.revoked_at is None
    assert record.revoked_reason == ""
    assert record.successor_key_id == ""


def test_key_record_json_round_trip():
    import json

    from lemma.models.key_metadata import KeyRecord, KeyStatus

    activated = datetime.now(UTC)
    revoked = datetime.now(UTC)
    record = KeyRecord(
        key_id="ed25519:revoked0",
        status=KeyStatus.REVOKED,
        activated_at=activated,
        revoked_at=revoked,
        revoked_reason="private key exposed in commit abc123",
        successor_key_id="ed25519:successor",
    )

    data = json.loads(record.model_dump_json())
    assert data["status"] == "REVOKED"
    assert data["revoked_reason"] == "private key exposed in commit abc123"

    revived = KeyRecord.model_validate_json(record.model_dump_json())
    assert revived.status == KeyStatus.REVOKED
    assert revived.successor_key_id == "ed25519:successor"
