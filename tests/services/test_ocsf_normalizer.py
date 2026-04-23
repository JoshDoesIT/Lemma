"""Tests for the OCSF ingestion normalizer."""

from __future__ import annotations

from datetime import UTC, datetime


def _base_payload(class_uid: int, class_name: str, category_uid: int, category_name: str) -> dict:
    return {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "type_uid": class_uid * 100 + 1,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {"version": "1.3.0", "product": {"name": "Lemma"}},
    }


def test_normalize_dispatches_compliance_finding():
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.ocsf_normalizer import normalize

    event = normalize(_base_payload(2003, "Compliance Finding", 2000, "Findings"))

    assert isinstance(event, ComplianceFinding)
    assert event.class_uid == 2003


def test_normalize_dispatches_detection_finding():
    from lemma.models.ocsf import DetectionFinding
    from lemma.services.ocsf_normalizer import normalize

    event = normalize(_base_payload(2004, "Detection Finding", 2000, "Findings"))

    assert isinstance(event, DetectionFinding)
    assert event.class_uid == 2004


def test_normalize_dispatches_authentication_event():
    from lemma.models.ocsf import AuthenticationEvent
    from lemma.services.ocsf_normalizer import normalize

    event = normalize(_base_payload(3002, "Authentication", 3000, "IAM"))

    assert isinstance(event, AuthenticationEvent)
    assert event.class_uid == 3002


def test_normalize_rejects_missing_class_uid():
    import pytest

    from lemma.services.ocsf_normalizer import normalize

    payload = _base_payload(2003, "Compliance Finding", 2000, "Findings")
    del payload["class_uid"]

    with pytest.raises(ValueError, match="class_uid"):
        normalize(payload)


def test_normalize_rejects_unknown_class_uid():
    import pytest

    from lemma.services.ocsf_normalizer import normalize

    payload = _base_payload(9999, "Made Up", 9000, "Unknown")

    with pytest.raises(ValueError, match="class_uid"):
        normalize(payload)


def test_normalize_rejects_naive_time():
    import pytest

    from lemma.services.ocsf_normalizer import normalize

    payload = _base_payload(2003, "Compliance Finding", 2000, "Findings")
    payload["time"] = datetime(2026, 4, 21, 12, 0, 0).isoformat()  # no tzinfo

    with pytest.raises(ValueError, match=r"time.*tzinfo|tzinfo.*time|timezone"):
        normalize(payload)


class TestNormalizeWithProvenance:
    def test_returns_event_and_normalization_record(self):
        import hashlib
        import json

        from lemma.models.ocsf import ComplianceFinding
        from lemma.services.ocsf_normalizer import NORMALIZER_VERSION, normalize_with_provenance

        payload = _base_payload(2003, "Compliance Finding", 2000, "Findings")

        event, record = normalize_with_provenance(payload)

        assert isinstance(event, ComplianceFinding)
        assert record.stage == "normalization"
        assert record.actor == NORMALIZER_VERSION

        expected_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert record.content_hash == expected_hash

    def test_propagates_validation_errors(self):
        import pytest

        from lemma.services.ocsf_normalizer import normalize_with_provenance

        payload = _base_payload(2003, "Compliance Finding", 2000, "Findings")
        del payload["class_uid"]

        with pytest.raises(ValueError, match="class_uid"):
            normalize_with_provenance(payload)
