"""Executes a ``QueryPlan`` against the compliance graph.

The executor is deliberately narrow: it only does what ``QueryPlan``
encodes. An LLM cannot ask it to walk arbitrary code — the bounded
plan shape is the safety contract.
"""

from __future__ import annotations

from typing import Any

from lemma.models.query_plan import QueryPlan, QueryTraversal
from lemma.services.knowledge_graph import ComplianceGraph


def _passes_evidence_filters(node: dict[str, Any], plan: QueryPlan) -> bool:
    """Apply ``plan``'s Evidence-attribute filters to a single node.

    Filters are skipped for non-Evidence nodes — applying ``time_range``
    or ``severity`` to a Resource or Framework would be incoherent. Each
    filter is independent any-of; multiple filters compound with AND.
    Time range is half-open ``[start, end)``.
    """
    if node.get("type") != "Evidence":
        return True
    if plan.time_range is not None:
        start_iso, end_iso = plan.time_range
        node_time = node.get("time_iso", "")
        if not (start_iso <= node_time < end_iso):
            return False
    if plan.severity is not None and node.get("severity") not in plan.severity:
        return False
    if plan.producer is not None and node.get("producer") not in plan.producer:
        return False
    return not (plan.class_uid is not None and node.get("class_uid") not in plan.class_uid)


def _neighbors_with_filters(plan: QueryPlan, graph: ComplianceGraph) -> list[dict[str, Any]]:
    export = graph.export_json()
    nodes_by_id = {n["id"]: n for n in export["nodes"]}
    entry = plan.entry_node

    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for edge in export["edges"]:
        source = edge["source"]
        target = edge["target"]
        relationship = edge.get("relationship", "")

        if plan.edge_filter and relationship not in plan.edge_filter:
            continue

        if source == entry:
            if plan.direction == "in":
                continue
            other_id = target
        elif target == entry:
            if plan.direction == "out":
                continue
            other_id = source
        else:
            continue

        if other_id in seen_ids:
            continue
        seen_ids.add(other_id)

        other_node = nodes_by_id.get(other_id, {})
        if not _passes_evidence_filters(other_node, plan):
            continue
        results.append({"id": other_id, **other_node, "_edge": relationship})

    return results


def execute(plan: QueryPlan, graph: ComplianceGraph) -> list[dict[str, Any]] | int:
    """Run a plan against the graph and return the result.

    Args:
        plan: Validated query plan from the translator.
        graph: Loaded compliance graph.

    Returns:
        A list of result dicts for ``output_shape="list"`` or an integer
        count for ``output_shape="count"``.

    Raises:
        ValueError: If ``entry_node`` doesn't exist in the graph or if
            the requested traversal isn't supported.
    """
    # Framework-control-count takes a framework name, not a graph node.
    if plan.traversal == QueryTraversal.FRAMEWORK_CONTROL_COUNT:
        framework_name = plan.entry_node.removeprefix("framework:")
        return graph.framework_control_count(framework_name)

    # Everything else requires the entry node to actually exist.
    if graph.get_node(plan.entry_node) is None:
        msg = f"entry_node '{plan.entry_node}' not found in the compliance graph."
        raise ValueError(msg)

    if plan.traversal == QueryTraversal.NEIGHBORS:
        results = _neighbors_with_filters(plan, graph)
        return len(results) if plan.output_shape == "count" else results

    if plan.traversal == QueryTraversal.IMPACT:
        impact_result = graph.impact(plan.entry_node)
        rows = [
            {"id": f"control:{c.get('framework', '')}:{c.get('id', '')}", **c}
            for c in impact_result.get("controls", [])
        ]
        return len(rows) if plan.output_shape == "count" else rows

    msg = f"Unsupported traversal: {plan.traversal}"
    raise ValueError(msg)
