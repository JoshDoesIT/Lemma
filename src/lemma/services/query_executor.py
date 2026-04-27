"""Executes a ``QueryPlan`` against the compliance graph.

The executor is deliberately narrow: it only does what ``QueryPlan``
encodes. An LLM cannot ask it to walk arbitrary code — the bounded
plan shape is the safety contract.
"""

from __future__ import annotations

from typing import Any

from lemma.models.query_plan import Hop, QueryPlan, QueryTraversal
from lemma.services.knowledge_graph import ComplianceGraph

_MAX_TOTAL_HOPS = 3


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


def _passes_node_filter(node: dict[str, Any], node_filter: dict[str, Any] | None) -> bool:
    """Shallow per-hop attribute match.

    For each ``(key, expected)`` pair: list ``expected`` matches any-of,
    scalar ``expected`` matches equality. Missing keys on the node fail
    the match (treated as a hard mismatch rather than a wildcard) so the
    operator-typed rule shape mirrors the strict semantics of the scope
    matcher elsewhere in the codebase.
    """
    if not node_filter:
        return True
    for key, expected in node_filter.items():
        actual = node.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _step(
    *,
    entry_id: str,
    edge_filter: list[str],
    direction: str,
    node_filter: dict[str, Any] | None,
    plan: QueryPlan,
    export: dict[str, Any],
    nodes_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Single-edge hop from ``entry_id``. Returns dedup'd result dicts.

    Reused by the v1 single-hop path and each follow-hop in the
    multi-hop walker — ``_neighbors_with_filters`` is now a thin wrapper
    over this helper. Evidence-attribute filters (plan-level) and the
    per-hop ``node_filter`` both apply to candidate nodes here.
    """
    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for edge in export["edges"]:
        source = edge["source"]
        target = edge["target"]
        relationship = edge.get("relationship", "")

        if edge_filter and relationship not in edge_filter:
            continue

        if source == entry_id:
            if direction == "in":
                continue
            other_id = target
        elif target == entry_id:
            if direction == "out":
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
        if not _passes_node_filter(other_node, node_filter):
            continue
        results.append({"id": other_id, **other_node, "_edge": relationship})

    return results


def _neighbors_with_filters(plan: QueryPlan, graph: ComplianceGraph) -> list[dict[str, Any]]:
    export = graph.export_json()
    nodes_by_id = {n["id"]: n for n in export["nodes"]}
    return _step(
        entry_id=plan.entry_node,
        edge_filter=plan.edge_filter,
        direction=plan.direction,
        node_filter=None,
        plan=plan,
        export=export,
        nodes_by_id=nodes_by_id,
    )


def _multihop_walk(plan: QueryPlan, graph: ComplianceGraph) -> list[dict[str, Any]]:
    """Run the entry hop plus each follow hop. Final-hop nodes are the result.

    Defense-in-depth on the 3-hop limit: Pydantic already enforces it on
    plan construction, but a caller using ``model_construct`` skips
    validators, so the executor self-checks too.
    """
    follow: list[Hop] = list(plan.follow or [])
    total_hops = 1 + len(follow)
    if total_hops > _MAX_TOTAL_HOPS:
        msg = (
            f"multi-hop traversal depth exceeds limit "
            f"(max {_MAX_TOTAL_HOPS} hops; got {total_hops} hops total)."
        )
        raise ValueError(msg)

    export = graph.export_json()
    nodes_by_id = {n["id"]: n for n in export["nodes"]}

    current = _step(
        entry_id=plan.entry_node,
        edge_filter=plan.edge_filter,
        direction=plan.direction,
        node_filter=None,
        plan=plan,
        export=export,
        nodes_by_id=nodes_by_id,
    )

    for hop in follow:
        next_set: list[dict[str, Any]] = []
        seen: set[str] = set()
        for node in current:
            # node_filter narrows the *source* set of this hop — read as
            # "from prior-hop nodes matching X, walk edge Y." This makes
            # operator-typed plans like {family: "IA"} → SATISFIES read
            # naturally without needing a separate filter-then-walk pair.
            if not _passes_node_filter(node, hop.node_filter):
                continue
            for cand in _step(
                entry_id=node["id"],
                edge_filter=hop.edge_filter,
                direction=hop.direction,
                node_filter=None,
                plan=plan,
                export=export,
                nodes_by_id=nodes_by_id,
            ):
                if cand["id"] in seen:
                    continue
                seen.add(cand["id"])
                next_set.append(cand)
        current = next_set

    return current


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
        if plan.follow is not None:
            results = _multihop_walk(plan, graph)
        else:
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
