"""Tests for OSCAL Assessment Plan emission (Refs #25 Slice E)."""

from __future__ import annotations

import json
from datetime import UTC, datetime


def _graph_with_one_framework():
    """nist-800-53 with two controls."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="Access Policy", family="AC")
    g.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    return g


def _graph_with_two_frameworks():
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="X", family="AC")
    g.add_framework("nist-csf-2.0", title="NIST CSF 2.0")
    g.add_control(framework="nist-csf-2.0", control_id="GV.OC-01", title="Y", family="GV.OC")
    return g


# ---------------------------------------------------------------------------
# Cycles 1-4: models + validate_assessment_plan
# ---------------------------------------------------------------------------


def test_oscal_assessment_plan_round_trips_with_kebab_case():
    from lemma.models.oscal_ap import (
        OscalAssessmentPlan,
        OscalControlReference,
        OscalControlSelection,
        OscalImportSsp,
        OscalMetadata,
        OscalReviewedControls,
    )

    doc = OscalAssessmentPlan(
        uuid="11111111-1111-1111-1111-111111111111",
        metadata=OscalMetadata(
            title="Lemma Assessment Plan",
            last_modified=datetime(2026, 4, 28, tzinfo=UTC),
            version="1.0.0",
            oscal_version="1.1.2",
        ),
        import_ssp=OscalImportSsp(href="urn:lemma:system-security-plan:nist-800-53"),
        reviewed_controls=OscalReviewedControls(
            control_selections=[
                OscalControlSelection(
                    description="All controls in nist-800-53.",
                    include_controls=[OscalControlReference(control_id="nist-800-53:ac-1")],
                )
            ]
        ),
    )

    wire = doc.model_dump(by_alias=True, exclude_none=True)
    assert "oscal-version" in wire["metadata"]
    assert "last-modified" in wire["metadata"]
    assert "import-ssp" in wire
    assert "reviewed-controls" in wire
    assert "control-selections" in wire["reviewed-controls"]
    assert "include-controls" in wire["reviewed-controls"]["control-selections"][0]
    assert "control-id" in wire["reviewed-controls"]["control-selections"][0]["include-controls"][0]

    revived = OscalAssessmentPlan.model_validate(wire)
    assert revived.metadata.oscal_version == "1.1.2"
    assert revived.import_ssp.href == "urn:lemma:system-security-plan:nist-800-53"


def test_required_field_omission_raises_validation_error():
    import pytest
    from pydantic import ValidationError

    from lemma.models.oscal_ap import OscalMetadata

    # Missing oscal-version.
    with pytest.raises(ValidationError):
        OscalMetadata(
            title="x",
            last_modified=datetime(2026, 4, 28, tzinfo=UTC),
            version="1.0.0",
            # oscal_version missing
        )


def test_validate_assessment_plan_passes_for_minimal_known_good():
    from lemma.services.oscal_ap import validate_assessment_plan

    ap = {
        "assessment-plan": {
            "uuid": "11111111-1111-1111-1111-111111111111",
            "metadata": {
                "title": "Lemma AP",
                "last-modified": "2026-04-28T00:00:00+00:00",
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "import-ssp": {"href": "urn:lemma:system-security-plan:nist-800-53"},
            "reviewed-controls": {
                "control-selections": [{"description": "all"}],
            },
        }
    }
    validate_assessment_plan(ap)  # no raise


def test_validate_assessment_plan_raises_on_missing_required_field():
    import pytest

    from lemma.services.oscal_ap import validate_assessment_plan

    # Missing import-ssp entirely.
    ap = {
        "assessment-plan": {
            "uuid": "x",
            "metadata": {
                "title": "Lemma AP",
                "last-modified": "2026-04-28T00:00:00+00:00",
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "reviewed-controls": {
                "control-selections": [{"description": "all"}],
            },
        }
    }
    with pytest.raises(ValueError, match=r"import-ssp"):
        validate_assessment_plan(ap)


# ---------------------------------------------------------------------------
# Cycles 5-10: build_assessment_plan service
# ---------------------------------------------------------------------------


def test_build_assessment_plan_empty_graph_returns_placeholder_selection():
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.oscal_ap import build_assessment_plan, validate_assessment_plan

    ap = build_assessment_plan(ComplianceGraph())
    validate_assessment_plan(ap)
    selections = ap["assessment-plan"]["reviewed-controls"]["control-selections"]
    assert len(selections) == 1
    # OSCAL-spec compliance: control-selections is non-empty even when there
    # are no frameworks. Empty include-controls is the right place for "no scope."
    assert selections[0]["description"].lower().startswith("no frameworks")
    assert selections[0]["include-controls"] == []


def test_build_assessment_plan_one_framework_lists_every_control_id():
    from lemma.services.oscal_ap import build_assessment_plan

    ap = build_assessment_plan(_graph_with_one_framework())
    selections = ap["assessment-plan"]["reviewed-controls"]["control-selections"]
    assert len(selections) == 1
    sel = selections[0]
    assert sel["description"] == "All controls in nist-800-53."
    control_ids = [r["control-id"] for r in sel["include-controls"]]
    # OSCAL canonical form: <framework>:<short_id>, NO `control:` prefix.
    assert control_ids == ["nist-800-53:ac-1", "nist-800-53:ac-2"]


def test_build_assessment_plan_framework_filter_narrows_selections():
    from lemma.services.oscal_ap import build_assessment_plan

    ap = build_assessment_plan(_graph_with_two_frameworks(), framework="nist-800-53")
    selections = ap["assessment-plan"]["reviewed-controls"]["control-selections"]
    assert len(selections) == 1
    control_ids = [r["control-id"] for r in selections[0]["include-controls"]]
    assert all(cid.startswith("nist-800-53:") for cid in control_ids)


def test_build_assessment_plan_no_filter_emits_one_selection_per_framework_sorted():
    from lemma.services.oscal_ap import build_assessment_plan

    ap = build_assessment_plan(_graph_with_two_frameworks())
    selections = ap["assessment-plan"]["reviewed-controls"]["control-selections"]
    assert len(selections) == 2
    descriptions = [s["description"] for s in selections]
    # Sorted by framework name, ensures determinism across runs.
    assert descriptions == [
        "All controls in nist-800-53.",
        "All controls in nist-csf-2.0.",
    ]


def test_build_assessment_plan_is_deterministic_for_same_inputs():
    from lemma.services.oscal_ap import build_assessment_plan

    g = _graph_with_one_framework()
    pinned = datetime(2026, 4, 28, tzinfo=UTC)
    ap1 = build_assessment_plan(g, generated_at=pinned)
    ap2 = build_assessment_plan(g, generated_at=pinned)
    assert json.dumps(ap1, sort_keys=True) == json.dumps(ap2, sort_keys=True)


def test_build_assessment_plan_import_ssp_carries_synthetic_urn():
    from lemma.services.oscal_ap import build_assessment_plan

    g = _graph_with_one_framework()
    ap_with = build_assessment_plan(g, framework="nist-800-53")
    assert (
        ap_with["assessment-plan"]["import-ssp"]["href"]
        == "urn:lemma:system-security-plan:nist-800-53"
    )

    ap_all = build_assessment_plan(g)
    assert ap_all["assessment-plan"]["import-ssp"]["href"] == "urn:lemma:system-security-plan:*"
