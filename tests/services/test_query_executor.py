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


def _build_full_edge_graph():
    """Graph with one edge of every relationship type #76 introduced."""
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-csf-2.0", control_id="de.cm-01", title="Monitoring", family="DE"
    )
    graph.add_control(
        framework="nist-csf-2.0", control_id="pr.aa-1", title="Identities", family="PR"
    )
    graph.add_scope(name="prod", frameworks=["nist-csf-2.0"])
    graph.add_resource(
        resource_id="audit-bucket",
        type_="aws.s3.bucket",
        scopes=["prod"],
        attributes={},
        impacts=["control:nist-csf-2.0:de.cm-01"],
    )
    graph.add_evidence(
        entry_hash="a" * 64,
        producer="connector:test",
        class_name="ComplianceFinding",
        time_iso="2026-04-01T00:00:00Z",
        control_refs=["nist-csf-2.0:de.cm-01"],
    )
    graph.add_person(
        person_id="alice",
        name="Alice",
        email="alice@example.com",
        owns=["control:nist-csf-2.0:pr.aa-1"],
    )
    graph.add_risk(
        risk_id="data-loss",
        title="Audit log loss",
        description="",
        severity="high",
        threatens=["resource:audit-bucket"],
        mitigated_by=["control:nist-csf-2.0:de.cm-01"],
    )
    graph.add_policy("access-control.md", title="Access Control")
    graph.add_mapping(
        policy="access-control.md",
        framework="nist-csf-2.0",
        control_id="pr.aa-1",
        confidence=0.9,
    )
    return graph


def test_execute_neighbors_walks_evidences_edges():
    """NEIGHBORS with edge_filter=['EVIDENCES'] from a Control returns the Evidence."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_full_edge_graph()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
    )

    results = execute(plan, graph)
    ids = {r["id"] for r in results}
    assert ids == {f"evidence:{'a' * 64}"}


def test_execute_neighbors_walks_owns_edges_direction_in():
    """OWNS points Person -> Control; direction='in' from the Control returns the Person."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_full_edge_graph()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:pr.aa-1",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["OWNS"],
        direction="in",
    )

    results = execute(plan, graph)
    ids = {r["id"] for r in results}
    assert ids == {"person:alice"}


def test_execute_neighbors_distinguishes_mitigated_by_from_impacts():
    """Both edges touch the same Control; filtering each returns disjoint sets."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_full_edge_graph()
    entry = "control:nist-csf-2.0:de.cm-01"

    mit_plan = QueryPlan(
        entry_node=entry,
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["MITIGATED_BY"],
        direction="in",
    )
    imp_plan = QueryPlan(
        entry_node=entry,
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["IMPACTS"],
        direction="in",
    )

    mit_ids = {r["id"] for r in execute(mit_plan, graph)}
    imp_ids = {r["id"] for r in execute(imp_plan, graph)}

    assert mit_ids == {"risk:data-loss"}
    assert imp_ids == {"resource:audit-bucket"}
    assert mit_ids.isdisjoint(imp_ids)


def _graph_with_three_evidences():
    """Control connected to 3 Evidence nodes with distinct severity/producer/time/class_uid."""
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-csf-2.0", control_id="de.cm-01", title="Monitoring", family="DE"
    )
    graph.add_evidence(
        entry_hash="a" * 64,
        producer="GitHub",
        class_name="Authentication",
        time_iso="2026-04-26T08:00:00+00:00",
        control_refs=["nist-csf-2.0:de.cm-01"],
        severity="HIGH",
        class_uid=3002,
    )
    graph.add_evidence(
        entry_hash="b" * 64,
        producer="AWS",
        class_name="Compliance Finding",
        time_iso="2026-04-25T08:00:00+00:00",
        control_refs=["nist-csf-2.0:de.cm-01"],
        severity="MEDIUM",
        class_uid=2003,
    )
    graph.add_evidence(
        entry_hash="c" * 64,
        producer="GitHub",
        class_name="Compliance Finding",
        time_iso="2026-04-26T20:00:00+00:00",
        control_refs=["nist-csf-2.0:de.cm-01"],
        severity="CRITICAL",
        class_uid=2003,
    )
    return graph


def test_execute_filters_evidence_by_time_range_half_open():
    """time_range keeps in-range Evidence and excludes out-of-range."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _graph_with_three_evidences()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
        time_range=(
            "2026-04-26T00:00:00+00:00",
            "2026-04-27T00:00:00+00:00",
        ),
    )

    ids = {r["id"] for r in execute(plan, graph)}
    assert ids == {f"evidence:{'a' * 64}", f"evidence:{'c' * 64}"}


def test_execute_filters_evidence_by_severity_any_of():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _graph_with_three_evidences()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
        severity=["HIGH", "CRITICAL"],
    )

    ids = {r["id"] for r in execute(plan, graph)}
    assert ids == {f"evidence:{'a' * 64}", f"evidence:{'c' * 64}"}


def test_execute_filters_evidence_by_producer_any_of():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _graph_with_three_evidences()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
        producer=["GitHub"],
    )

    ids = {r["id"] for r in execute(plan, graph)}
    assert ids == {f"evidence:{'a' * 64}", f"evidence:{'c' * 64}"}


def test_execute_filters_evidence_by_class_uid_any_of():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _graph_with_three_evidences()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
        class_uid=[3002],
    )

    ids = {r["id"] for r in execute(plan, graph)}
    assert ids == {f"evidence:{'a' * 64}"}


def test_execute_evidence_filters_combine_with_and():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _graph_with_three_evidences()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        edge_filter=["EVIDENCES"],
        direction="in",
        producer=["GitHub"],
        severity=["HIGH"],
    )

    ids = {r["id"] for r in execute(plan, graph)}
    assert ids == {f"evidence:{'a' * 64}"}


def test_execute_evidence_filters_skip_non_evidence_nodes():
    """Resource/Risk/Person nodes pass through evidence filters unchanged."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_full_edge_graph()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
        # Filter values that no Evidence node in this graph has — but
        # non-Evidence nodes still come through.
        severity=["NONEXISTENT"],
        producer=["nope"],
        class_uid=[99999],
    )

    results = execute(plan, graph)
    types = {r.get("type", "") for r in results}
    # Non-Evidence types pass through despite the filters.
    assert "Framework" in types
    assert "Risk" in types
    assert "Resource" in types
    # The single Evidence node in _build_full_edge_graph fails every filter, so it's gone.
    assert "Evidence" not in types


class TestMultiHopTraversal:
    """Multi-hop chained traversal via QueryPlan.follow (Refs #105)."""

    def _graph_for_multihop(self):
        """Framework with mixed-family controls + harmonization + a policy."""
        from lemma.services.knowledge_graph import ComplianceGraph

        graph = ComplianceGraph()
        graph.add_framework("nist-800-53")
        graph.add_framework("nist-csf-2.0")
        # AC family
        graph.add_control(
            framework="nist-800-53",
            control_id="ac-2",
            title="Account Management",
            family="AC",
        )
        # IA family — two controls so the family filter has something to do.
        graph.add_control(
            framework="nist-800-53",
            control_id="ia-2",
            title="Identification and Authentication",
            family="IA",
        )
        graph.add_control(
            framework="nist-800-53",
            control_id="ia-5",
            title="Authenticator Management",
            family="IA",
        )
        # CSF peer for harmonization
        graph.add_control(
            framework="nist-csf-2.0",
            control_id="pr.aa-1",
            title="Identities",
            family="PR.AA",
        )
        graph.add_harmonization(
            framework_a="nist-800-53",
            control_a="ac-2",
            framework_b="nist-csf-2.0",
            control_b="pr.aa-1",
            similarity=0.92,
        )
        # Policy satisfying ia-2 only — gives the family-filter test something
        # to discriminate.
        graph.add_policy("identity-mgmt.md", title="Identity Management Policy")
        graph.add_mapping(
            policy="identity-mgmt.md",
            framework="nist-800-53",
            control_id="ia-2",
            confidence=0.9,
        )
        return graph

    def test_single_hop_unchanged_when_follow_none(self):
        """Regression guard: plans without `follow` walk the v1 path byte-identical."""
        from lemma.models.query_plan import QueryPlan, QueryTraversal
        from lemma.services.query_executor import execute

        graph = self._graph_for_multihop()
        plan = QueryPlan(
            entry_node="control:nist-800-53:ac-2",
            traversal=QueryTraversal.NEIGHBORS,
            edge_filter=["HARMONIZED_WITH"],
        )
        results = execute(plan, graph)
        ids = {r["id"] for r in results}
        assert ids == {"control:nist-csf-2.0:pr.aa-1"}

    def test_multihop_framework_to_harmonized_controls(self):
        """AC #1: framework -> CONTAINS -> controls -> HARMONIZED_WITH -> peers."""
        from lemma.models.query_plan import Hop, QueryPlan, QueryTraversal
        from lemma.services.query_executor import execute

        graph = self._graph_for_multihop()
        plan = QueryPlan(
            entry_node="framework:nist-800-53",
            traversal=QueryTraversal.NEIGHBORS,
            edge_filter=["CONTAINS"],
            direction="out",
            follow=[Hop(edge_filter=["HARMONIZED_WITH"])],
        )

        results = execute(plan, graph)
        ids = {r["id"] for r in results}
        # Only ac-2 is harmonized (with pr.aa-1); ia-2/ia-5 have no peers.
        assert ids == {"control:nist-csf-2.0:pr.aa-1"}

    def test_multihop_with_node_filter_for_ia_family(self):
        """AC #2: framework -> CONTAINS (filtered to IA family) -> SATISFIES (in)."""
        from lemma.models.query_plan import Hop, QueryPlan, QueryTraversal
        from lemma.services.query_executor import execute

        graph = self._graph_for_multihop()
        plan = QueryPlan(
            entry_node="framework:nist-800-53",
            traversal=QueryTraversal.NEIGHBORS,
            edge_filter=["CONTAINS"],
            direction="out",
            follow=[
                Hop(node_filter={"family": "IA"}, edge_filter=["SATISFIES"], direction="in"),
            ],
        )

        results = execute(plan, graph)
        ids = {r["id"] for r in results}
        # Only the IA-family path leads to identity-mgmt.md; AC and PR.AA paths drop out.
        assert ids == {"policy:identity-mgmt.md"}

    def test_multihop_count_output_shape(self):
        """output_shape='count' returns the size of the final-hop result set."""
        from lemma.models.query_plan import Hop, QueryPlan, QueryTraversal
        from lemma.services.query_executor import execute

        graph = self._graph_for_multihop()
        plan = QueryPlan(
            entry_node="framework:nist-800-53",
            traversal=QueryTraversal.NEIGHBORS,
            edge_filter=["CONTAINS"],
            direction="out",
            follow=[Hop(edge_filter=["HARMONIZED_WITH"])],
            output_shape="count",
        )
        result = execute(plan, graph)
        assert result == 1

    def test_executor_raises_on_four_hop_plan_built_bypassing_pydantic(self):
        """Defense-in-depth: if a caller assembles a QueryPlan via model_construct,
        the executor still rejects four-hop walks."""
        from lemma.models.query_plan import Hop, QueryPlan, QueryTraversal
        from lemma.services.query_executor import execute

        graph = self._graph_for_multihop()
        # model_construct skips field_validator; only the executor's own
        # depth check catches the abuse.
        plan = QueryPlan.model_construct(
            entry_node="framework:nist-800-53",
            traversal=QueryTraversal.NEIGHBORS,
            edge_filter=[],
            direction="both",
            output_shape="list",
            time_range=None,
            severity=None,
            producer=None,
            class_uid=None,
            follow=[Hop(), Hop(), Hop()],
        )
        with pytest.raises(ValueError, match=r"(?i)max 3 hops|depth"):
            execute(plan, graph)


def test_execute_neighbors_mixed_type_results_are_all_returned():
    """A Control's full neighborhood returns Policy, Evidence, Risk, Person — no crash."""
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_executor import execute

    graph = _build_full_edge_graph()
    plan = QueryPlan(
        entry_node="control:nist-csf-2.0:de.cm-01",
        traversal=QueryTraversal.NEIGHBORS,
    )

    results = execute(plan, graph)
    types = {r.get("type", "") for r in results}
    # At minimum: Framework (CONTAINS), Evidence (EVIDENCES), Risk (MITIGATED_BY),
    # Resource (IMPACTS). Policy is only attached to pr.aa-1, not de.cm-01.
    assert {"Framework", "Evidence", "Risk", "Resource"}.issubset(types)
