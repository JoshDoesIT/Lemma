"""Tests for the Continuous Scope Validation drift detector."""

from __future__ import annotations


def _scopes():
    from lemma.models.scope import MatchOperator, MatchRule, ScopeDefinition

    return [
        ScopeDefinition(
            name="prod",
            frameworks=["nist-csf-2.0"],
            match_rules=[
                MatchRule(
                    source="env",
                    operator=MatchOperator.EQUALS,
                    value="prod",
                ),
            ],
        ),
        ScopeDefinition(
            name="us-east",
            frameworks=["nist-csf-2.0"],
            match_rules=[
                MatchRule(
                    source="region",
                    operator=MatchOperator.EQUALS,
                    value="us-east-1",
                ),
            ],
        ),
    ]


def _candidate(rid: str, attrs: dict):
    from lemma.models.resource import ResourceDefinition

    return ResourceDefinition(
        id=rid,
        type="aws.ec2.instance",
        scopes=[""],
        attributes=attrs,
    )


def _existing(rid: str, attrs: dict, scopes: list[str]):
    """Mirror of `ComplianceGraph.iter_resources()` shape."""
    return {
        "node_id": f"resource:{rid}",
        "resource_id": rid,
        "resource_type": "aws.ec2.instance",
        "attributes": attrs,
        "scopes": scopes,
    }


class TestComputeDrift:
    def test_created_resource_in_fresh_only(self):
        from lemma.services.scope_drift import compute_drift

        report = compute_drift(
            existing_resources=[],
            fresh_candidates=[_candidate("r1", {"env": "prod", "region": "us-east-1"})],
            scopes=_scopes(),
        )

        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.resource_id == "r1"
        assert entry.status == "created"
        assert entry.entered_scopes == ["prod", "us-east"]
        assert entry.exited_scopes == []

    def test_deleted_resource_in_graph_only(self):
        from lemma.services.scope_drift import compute_drift

        report = compute_drift(
            existing_resources=[_existing("r1", {"env": "prod"}, ["prod"])],
            fresh_candidates=[],
            scopes=_scopes(),
        )

        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.resource_id == "r1"
        assert entry.status == "deleted"
        assert entry.exited_scopes == ["prod"]
        assert entry.entered_scopes == []

    def test_scope_change_when_attributes_cross_boundary(self):
        from lemma.services.scope_drift import compute_drift

        report = compute_drift(
            existing_resources=[_existing("r1", {"env": "dev"}, [])],
            fresh_candidates=[_candidate("r1", {"env": "prod"})],
            scopes=_scopes(),
        )

        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.status == "scope_change"
        assert entry.entered_scopes == ["prod"]
        assert entry.exited_scopes == []

    def test_attribute_drift_when_attrs_change_but_scopes_stable(self):
        from lemma.services.scope_drift import compute_drift

        report = compute_drift(
            existing_resources=[
                _existing("r1", {"env": "prod", "size": "small"}, ["prod"]),
            ],
            fresh_candidates=[_candidate("r1", {"env": "prod", "size": "large"})],
            scopes=_scopes(),
        )

        entry = report.entries[0]
        assert entry.status == "attribute_drift"
        assert entry.entered_scopes == []
        assert entry.exited_scopes == []
        assert entry.attribute_changes == {"size": ("small", "large")}

    def test_unchanged_when_attrs_and_scopes_match(self):
        from lemma.services.scope_drift import compute_drift

        report = compute_drift(
            existing_resources=[_existing("r1", {"env": "prod"}, ["prod"])],
            fresh_candidates=[_candidate("r1", {"env": "prod"})],
            scopes=_scopes(),
        )

        entry = report.entries[0]
        assert entry.status == "unchanged"
        assert entry.entered_scopes == []
        assert entry.exited_scopes == []
        assert entry.attribute_changes == {}

    def test_has_drift_property(self):
        from lemma.services.scope_drift import compute_drift

        no_drift = compute_drift(
            existing_resources=[_existing("r1", {"env": "prod"}, ["prod"])],
            fresh_candidates=[_candidate("r1", {"env": "prod"})],
            scopes=_scopes(),
        )
        assert no_drift.has_drift is False

        with_drift = compute_drift(
            existing_resources=[],
            fresh_candidates=[_candidate("r1", {"env": "prod"})],
            scopes=_scopes(),
        )
        assert with_drift.has_drift is True
