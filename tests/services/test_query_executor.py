"""Tests for the NL-query executor — plan → graph traversal."""

from __future__ import annotations

import pytest


def _build_graph():
    """Build a small graph covering the three edge types the executor cares about."""
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-800-53")
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-800-53",
        control_id="ac-2",
        title="Account Management",
        family="AC",
    )
    graph.add_control(
        framework="nist-csf-2.0",
        control_id="pr.aa-1",
        title="Identities",
        family="PR",
    )
    graph.add_policy("access-control.md", title="Access Control")
    graph.add_mapping(
        policy="access-control.md",
        framework="nist-800-53",
        control_id="ac-2",
        confidence=0.9,
    )
    graph.add_harmonization(
        framework_a="nist-800-53",
        control_a="ac-2",
        framework_b="nist-csf-2.0",
        control_b="pr.aa-1",
        similarity=0.92,
    )
    return graph


def test_execute_raises_on_unknown_entry_node():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_graph()
    plan = QueryPlan(
        entry_node="control:nist-800-53:does-not-exist",
        traversal=QueryTraversal.NEIGHBORS,
    )

    with pytest.raises(ValueError, match="entry_node"):
        execute(plan, graph)


def test_execute_neighbors_no_filter_returns_all_neighbors():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_graph()
    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
    )

    results = execute(plan, graph)

    neighbor_ids = {r["id"] for r in results}
    # AC-2 connects to: the framework (CONTAINS), the policy (SATISFIES in), and the
    # harmonized CSF control (HARMONIZED_WITH).
    assert "framework:nist-800-53" in neighbor_ids
    assert "policy:access-control.md" in neighbor_ids
    assert "control:nist-csf-2.0:pr.aa-1" in neighbor_ids


def test_execute_neighbors_with_harmonized_filter_returns_only_harmonized():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_graph()
    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["HARMONIZED_WITH"],
    )

    results = execute(plan, graph)
    neighbor_ids = {r["id"] for r in results}

    assert neighbor_ids == {"control:nist-csf-2.0:pr.aa-1"}


def test_execute_neighbors_direction_in_returns_only_inbound():
    """direction='in' on a control returns only things pointing AT it."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_graph()
    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["SATISFIES"],
        direction="in",
    )

    results = execute(plan, graph)
    neighbor_ids = {r["id"] for r in results}
    # Only the policy satisfies the control (SATISFIES edges point policy → control).
    assert neighbor_ids == {"policy:access-control.md"}


def test_execute_neighbors_direction_out_excludes_inbound():
    """direction='out' excludes edges pointing AT the entry node."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_graph()
    plan = QueryPlan(
        entry_node="control:nist-800-53:ac-2",
        traversal=QueryTraversal.NEIGHBORS,
        direction="out",
    )

    results = execute(plan, graph)
    neighbor_ids = {r["id"] for r in results}
    # No SATISFIES-in edges; only the outgoing HARMONIZED_WITH (symmetric so one side shows).
    assert "policy:access-control.md" not in neighbor_ids
