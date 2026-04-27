"""Tests for the QueryPlan model — structured NL-query plan."""

from __future__ import annotations


def test_query_traversal_enum_values():
    from lemma.models.query_plan import QueryTraversal

    assert QueryTraversal.NEIGHBORS.value == "NEIGHBORS"
    assert QueryTraversal.IMPACT.value == "IMPACT"
    assert QueryTraversal.FRAMEWORK_CONTROL_COUNT.value == "FRAMEWORK_CONTROL_COUNT"


def test_query_plan_minimal_construction():
    from lemma.models.query_plan import QueryPlan, QueryTraversal

    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
    )

    assert plan.entry_node == "control:nist-800-53:ac-2"
    assert plan.traversal == QueryTraversal.NEIGHBORS
    # Defaults
    assert plan.edge_filter == []
    assert plan.direction == "both"
    assert plan.output_shape == "list"


def test_query_plan_accepts_edge_filter_and_direction():
    from lemma.models.query_plan import QueryPlan, QueryTraversal

    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["HARMONIZED_WITH"],
        direction="out",
        output_shape="count",
    )

    assert plan.edge_filter == ["HARMONIZED_WITH"]
    assert plan.direction == "out"
    assert plan.output_shape == "count"


def test_query_plan_rejects_unknown_traversal():
    import pytest
    from pydantic import ValidationError

    from lemma.models.query_plan import QueryPlan

    with pytest.raises(ValidationError):
        QueryPlan(entry_node="x", traversal="MADE_UP_TRAVERSAL")


def test_query_plan_rejects_invalid_direction():
    import pytest
    from pydantic import ValidationError

    from lemma.models.query_plan import QueryPlan, QueryTraversal

    with pytest.raises(ValidationError):
        QueryPlan(
            entry_node="x",
            traversal=QueryTraversal.NEIGHBORS,
            direction="sideways",
        )


def test_query_plan_evidence_attribute_filters_default_to_none():
    from lemma.models.query_plan import QueryPlan, QueryTraversal

    plan = QueryPlan(
        entry_node="control:nist-800-53:au-2",
        traversal=QueryTraversal.NEIGHBORS,
    )
    assert plan.time_range is None
    assert plan.severity is None
    assert plan.producer is None
    assert plan.class_uid is None


def test_query_plan_evidence_attribute_filters_round_trip():
    from lemma.models.query_plan import QueryPlan, QueryTraversal

    plan = QueryPlan(
        entry_node="control:nist-800-53:au-2",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
        time_range=("2026-04-26T00:00:00+00:00", "2026-04-27T00:00:00+00:00"),
        severity=["HIGH", "CRITICAL"],
        producer=["GitHub"],
        class_uid=[3002],
    )

    revived = QueryPlan.model_validate_json(plan.model_dump_json())
    assert revived.time_range == (
        "2026-04-26T00:00:00+00:00",
        "2026-04-27T00:00:00+00:00",
    )
    assert revived.severity == ["HIGH", "CRITICAL"]
    assert revived.producer == ["GitHub"]
    assert revived.class_uid == [3002]


def test_query_plan_json_round_trip():
    import json

    from lemma.models.query_plan import QueryPlan, QueryTraversal

    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["HARMONIZED_WITH", "SATISFIES"],
        direction="in",
        output_shape="list",
    )
    data = json.loads(plan.model_dump_json())
    assert data["traversal"] == "NEIGHBORS"

    revived = QueryPlan.model_validate_json(plan.model_dump_json())
    assert revived.edge_filter == ["HARMONIZED_WITH", "SATISFIES"]
    assert revived.direction == "in"
