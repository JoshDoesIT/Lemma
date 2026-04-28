"""Tests for OSCAL Assessment Results emission (Refs #25 Slice A)."""

from __future__ import annotations

import json
from datetime import UTC, datetime


def _graph_with_one_passed_control():
    """Single framework + one control + one mapped policy at confidence 0.9."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.add_control(
        framework="nist-800-53", control_id="ac-1", title="Access Control Policy", family="AC"
    )
    g.add_policy("access-control.md", title="Access Control Policy")
    g.add_mapping(
        policy="access-control.md", framework="nist-800-53", control_id="ac-1", confidence=0.9
    )
    return g


def _graph_with_one_failed_control():
    """Single framework + one control + no mapping."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    return g


# ---------------------------------------------------------------------------
# Cycles 1-3: models + validate_assessment_results
# ---------------------------------------------------------------------------


def test_oscal_assessment_results_round_trips_with_kebab_case():
    from lemma.models.oscal_ar import (
        OscalAssessmentResults,
        OscalControlSelection,
        OscalImportAp,
        OscalMetadata,
        OscalResult,
        OscalReviewedControls,
    )

    doc = OscalAssessmentResults(
        uuid="11111111-1111-1111-1111-111111111111",
        metadata=OscalMetadata(
            title="Lemma Assessment Results",
            last_modified=datetime(2026, 4, 28, tzinfo=UTC),
            version="1.0.0",
            oscal_version="1.1.2",
        ),
        import_ap=OscalImportAp(href="urn:lemma:assessment-plan:nist-800-53"),
        results=[
            OscalResult(
                uuid="22222222-2222-2222-2222-222222222222",
                title="Lemma run",
                description="Run X",
                start=datetime(2026, 4, 28, tzinfo=UTC),
                reviewed_controls=OscalReviewedControls(
                    control_selections=[
                        OscalControlSelection(description="All Lemma-mapped controls.")
                    ]
                ),
            ),
        ],
    )

    wire = doc.model_dump(by_alias=True, exclude_none=True)
    # Wire form must use kebab-case for OSCAL-defined fields.
    assert "oscal-version" in wire["metadata"]
    assert "last-modified" in wire["metadata"]
    assert "import-ap" in wire
    assert "reviewed-controls" in wire["results"][0]
    assert "control-selections" in wire["results"][0]["reviewed-controls"]

    # Round-trip via Python alias-aware validate.
    revived = OscalAssessmentResults.model_validate(wire)
    assert revived.metadata.oscal_version == "1.1.2"
    assert revived.import_ap.href == "urn:lemma:assessment-plan:nist-800-53"


def test_validate_assessment_results_passes_for_minimal_known_good():
    from lemma.services.oscal_ar import validate_assessment_results

    ar = {
        "assessment-results": {
            "uuid": "11111111-1111-1111-1111-111111111111",
            "metadata": {
                "title": "Lemma AR",
                "last-modified": "2026-04-28T00:00:00+00:00",
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "urn:lemma:assessment-plan:all"},
            "results": [
                {
                    "uuid": "22222222-2222-2222-2222-222222222222",
                    "title": "run",
                    "description": "desc",
                    "start": "2026-04-28T00:00:00+00:00",
                    "reviewed-controls": {
                        "control-selections": [{"description": "all"}],
                    },
                }
            ],
        }
    }
    validate_assessment_results(ar)  # no raise


def test_validate_assessment_results_raises_on_missing_required_field():
    import pytest

    from lemma.services.oscal_ar import validate_assessment_results

    # Missing metadata.oscal-version.
    ar = {
        "assessment-results": {
            "uuid": "x",
            "metadata": {
                "title": "Lemma AR",
                "last-modified": "2026-04-28T00:00:00+00:00",
                "version": "1.0.0",
            },
            "import-ap": {"href": "urn:lemma:assessment-plan:all"},
            "results": [
                {
                    "uuid": "y",
                    "title": "run",
                    "description": "desc",
                    "start": "2026-04-28T00:00:00+00:00",
                    "reviewed-controls": {"control-selections": [{"description": "all"}]},
                }
            ],
        }
    }
    with pytest.raises(ValueError, match=r"oscal-version"):
        validate_assessment_results(ar)


# ---------------------------------------------------------------------------
# Cycles 4-9: build_assessment_results service
# ---------------------------------------------------------------------------


def test_build_assessment_results_empty_graph_returns_valid_ar_with_no_findings():
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.oscal_ar import build_assessment_results, validate_assessment_results

    ar = build_assessment_results(ComplianceGraph())
    validate_assessment_results(ar)
    body = ar["assessment-results"]
    assert body["results"], "AR document always carries at least one Result"
    assert "findings" not in body["results"][0], "no controls means no findings; key omitted"


def test_build_assessment_results_passed_control_yields_satisfied_finding():
    from lemma.services.oscal_ar import build_assessment_results

    ar = build_assessment_results(_graph_with_one_passed_control())
    findings = ar["assessment-results"]["results"][0]["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["target"]["type"] == "objective-id"
    assert f["target"]["target-id"] == "control:nist-800-53:ac-1"
    assert {"name": "state", "value": "satisfied"} in f["props"]


def test_build_assessment_results_failed_control_yields_other_than_satisfied():
    from lemma.services.oscal_ar import build_assessment_results

    ar = build_assessment_results(_graph_with_one_failed_control())
    findings = ar["assessment-results"]["results"][0]["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["target"]["target-id"] == "control:nist-800-53:ac-2"
    assert {"name": "state", "value": "other-than-satisfied"} in f["props"]


def test_build_assessment_results_framework_filter_narrows_findings():
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.oscal_ar import build_assessment_results

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="X", family="AC")
    g.add_framework("nist-csf-2.0")
    g.add_control(framework="nist-csf-2.0", control_id="GV.OC-01", title="Y", family="GV.OC")

    ar = build_assessment_results(g, framework="nist-800-53")
    findings = ar["assessment-results"]["results"][0]["findings"]
    target_ids = {f["target"]["target-id"] for f in findings}
    assert target_ids == {"control:nist-800-53:ac-1"}


def test_build_assessment_results_min_confidence_excludes_low_confidence_edges():
    """Mirrors `lemma check --min-confidence` behavior end-to-end into AR."""
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.oscal_ar import build_assessment_results

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="AC-1", family="AC")
    g.add_policy("low.md", title="low")
    g.add_mapping(policy="low.md", framework="nist-800-53", control_id="ac-1", confidence=0.5)

    # min_confidence=0.9 excludes the 0.5 edge -> the control flips to FAILED.
    ar = build_assessment_results(g, min_confidence=0.9)
    findings = ar["assessment-results"]["results"][0]["findings"]
    assert len(findings) == 1
    assert {"name": "state", "value": "other-than-satisfied"} in findings[0]["props"]


def test_build_assessment_results_is_deterministic_for_same_inputs():
    from lemma.services.oscal_ar import build_assessment_results

    g = _graph_with_one_passed_control()
    pinned = datetime(2026, 4, 28, tzinfo=UTC)
    ar1 = build_assessment_results(g, generated_at=pinned)
    ar2 = build_assessment_results(g, generated_at=pinned)
    assert json.dumps(ar1, sort_keys=True) == json.dumps(ar2, sort_keys=True)


def test_build_assessment_results_failed_uses_other_than_satisfied_not_not_satisfied():
    """OSCAL controlled vocab is `satisfied | other-than-satisfied`, NOT `not-satisfied`."""
    from lemma.services.oscal_ar import build_assessment_results

    ar = build_assessment_results(_graph_with_one_failed_control())
    state_props = [
        p
        for f in ar["assessment-results"]["results"][0]["findings"]
        for p in f["props"]
        if p["name"] == "state"
    ]
    values = {p["value"] for p in state_props}
    # Only OSCAL-canonical values; never "not-satisfied".
    assert values <= {"satisfied", "other-than-satisfied"}
    assert "not-satisfied" not in values
