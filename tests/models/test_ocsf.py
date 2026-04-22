"""Tests for OCSF (Open Cybersecurity Schema Framework) event type models.

Event payloads used in the fixture-based tests are adapted from examples
published at https://schema.ocsf.io/ (Apache-2.0).
"""

from __future__ import annotations


def test_ocsf_category_enum_has_canonical_ids():
    from lemma.models.ocsf import OcsfCategory

    assert int(OcsfCategory.FINDINGS) == 2000
    assert int(OcsfCategory.IAM) == 3000


def test_ocsf_severity_enum_matches_ocsf_spec():
    from lemma.models.ocsf import OcsfSeverity

    assert int(OcsfSeverity.INFORMATIONAL) == 1
    assert int(OcsfSeverity.LOW) == 2
    assert int(OcsfSeverity.MEDIUM) == 3
    assert int(OcsfSeverity.HIGH) == 4
    assert int(OcsfSeverity.CRITICAL) == 5
    assert int(OcsfSeverity.FATAL) == 6


def test_ocsf_base_event_requires_core_fields():
    from lemma.models.ocsf import OcsfBaseEvent

    event = OcsfBaseEvent(
        class_uid=2003,
        class_name="Compliance Finding",
        category_uid=2000,
        category_name="Findings",
        type_uid=200301,
        activity_id=1,
    )
    # time auto-populates; metadata defaults to empty mapping
    assert event.class_uid == 2003
    assert event.time is not None
    assert event.metadata == {}
    assert event.message == ""


def test_ocsf_base_event_rejects_missing_class_uid():
    import pytest
    from pydantic import ValidationError

    from lemma.models.ocsf import OcsfBaseEvent

    with pytest.raises(ValidationError):
        OcsfBaseEvent(
            class_name="X",
            category_uid=2000,
            category_name="Findings",
            type_uid=1,
            activity_id=1,
        )


def test_compliance_finding_pins_class_uid_2003():
    from lemma.models.ocsf import ComplianceFinding

    finding = ComplianceFinding(
        class_name="Compliance Finding",
        category_uid=2000,
        category_name="Findings",
        type_uid=200301,
        activity_id=1,
    )
    assert finding.class_uid == 2003
    assert finding.category_uid == 2000


def test_compliance_finding_validates_category_consistency():
    import pytest
    from pydantic import ValidationError

    from lemma.models.ocsf import ComplianceFinding

    with pytest.raises(ValidationError):
        ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=3000,  # IAM — wrong category for a Finding
            category_name="IAM",
            type_uid=200301,
            activity_id=1,
        )


def test_detection_finding_pins_class_uid_2004():
    from lemma.models.ocsf import DetectionFinding

    finding = DetectionFinding(
        class_name="Detection Finding",
        category_uid=2000,
        category_name="Findings",
        type_uid=200401,
        activity_id=1,
    )
    assert finding.class_uid == 2004
    assert finding.category_uid == 2000


def test_authentication_event_pins_class_uid_3002_and_category_3000():
    from lemma.models.ocsf import AuthenticationEvent

    event = AuthenticationEvent(
        class_name="Authentication",
        category_uid=3000,
        category_name="IAM",
        type_uid=300201,
        activity_id=1,
    )
    assert event.class_uid == 3002
    assert event.category_uid == 3000


def _load_fixture(name: str) -> dict:
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent.parent / "fixtures" / "ocsf" / name).read_text())


def test_compliance_finding_parses_sample_ocsf_payload():
    """Sample payload adapted from https://schema.ocsf.io/ (Apache-2.0)."""
    from lemma.models.ocsf import ComplianceFinding

    payload = _load_fixture("compliance_finding_sample.json")
    finding = ComplianceFinding.model_validate(payload)

    assert finding.class_uid == 2003
    assert finding.category_uid == 2000
    assert finding.metadata["product"]["name"]


def test_authentication_event_parses_sample_ocsf_payload():
    """Sample payload adapted from https://schema.ocsf.io/ (Apache-2.0)."""
    from lemma.models.ocsf import AuthenticationEvent

    payload = _load_fixture("authentication_sample.json")
    event = AuthenticationEvent.model_validate(payload)

    assert event.class_uid == 3002
    assert event.category_uid == 3000
    assert event.metadata["version"]


def test_ocsf_event_serializes_to_json_with_snake_case_keys():
    import json

    from lemma.models.ocsf import ComplianceFinding

    finding = ComplianceFinding(
        class_name="Compliance Finding",
        category_uid=2000,
        category_name="Findings",
        type_uid=200301,
        activity_id=1,
    )
    data = json.loads(finding.model_dump_json())

    assert data["class_uid"] == 2003
    assert data["category_uid"] == 2000
    assert data["severity_id"] == 1  # default INFORMATIONAL
    assert "time" in data
    assert "metadata" in data
