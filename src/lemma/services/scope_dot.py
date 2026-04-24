"""Scope-subgraph Graphviz DOT renderer.

Emits the scope-centered slice of the compliance graph as Graphviz
DOT. Includes Scope, Framework, Control, and Resource nodes with
their ``APPLIES_TO``, ``CONTAINS``, and ``SCOPED_TO`` edges.

Pure string output — no runtime dependency on any Graphviz Python
binding. Operators pipe the result to ``dot -Tpng`` (or any other
Graphviz renderer) to turn it into an image.
"""

from __future__ import annotations

from lemma.services.knowledge_graph import ComplianceGraph

_NODE_STYLES = {
    "Scope": 'shape=box, style="rounded,filled", fillcolor="#DDEEFF"',
    "Framework": 'shape=box3d, style=filled, fillcolor="#FFE9B3"',
    "Control": "shape=ellipse",
    "Resource": 'shape=cylinder, style=filled, fillcolor="#E7F5E8"',
}


def _node_line(node_id: str, node_type: str, label: str) -> str:
    style = _NODE_STYLES.get(node_type, "")
    attr = f'label="{label}"'
    if style:
        attr = f"{attr}, {style}"
    return f'  "{node_id}" [{attr}];'


def render_scope_dot(graph: ComplianceGraph, *, scope_filter: str | None = None) -> str:
    """Render the scope-centered subgraph as a DOT string.

    Args:
        graph: Loaded compliance graph.
        scope_filter: If given, only the named scope and its reachable
            frameworks / controls / resources are emitted. Raises
            ``ValueError`` if the scope isn't in the graph.

    Returns:
        A DOT-format digraph. Always wellformed — an empty graph still
        produces ``digraph Lemma {}``.
    """
    export = graph.export_json()
    nodes_by_id = {node["id"]: node for node in export["nodes"]}

    if scope_filter is not None and f"scope:{scope_filter}" not in nodes_by_id:
        msg = (
            f"Scope '{scope_filter}' does not exist in the graph. "
            "Run 'lemma scope load' to register it first."
        )
        raise ValueError(msg)

    # Select the scope set we're rendering.
    scope_ids = {
        node["id"]
        for node in export["nodes"]
        if node.get("type") == "Scope"
        and (scope_filter is None or node.get("name") == scope_filter)
    }

    # Walk APPLIES_TO to collect reachable frameworks; then CONTAINS to controls.
    framework_ids: set[str] = set()
    control_ids: set[str] = set()
    resource_ids: set[str] = set()

    applies_to_edges: list[tuple[str, str]] = []
    contains_edges: list[tuple[str, str]] = []
    scoped_to_edges: list[tuple[str, str]] = []

    for edge in export["edges"]:
        rel = edge.get("relationship")
        src = edge["source"]
        dst = edge["target"]

        if rel == "APPLIES_TO" and src in scope_ids:
            framework_ids.add(dst)
            applies_to_edges.append((src, dst))
        elif rel == "SCOPED_TO" and dst in scope_ids:
            resource_ids.add(src)
            scoped_to_edges.append((src, dst))

    for edge in export["edges"]:
        if edge.get("relationship") != "CONTAINS":
            continue
        src = edge["source"]
        dst = edge["target"]
        if src in framework_ids:
            control_ids.add(dst)
            contains_edges.append((src, dst))

    lines = ["digraph Lemma {", '  rankdir="LR";', '  node [fontname="Helvetica"];']

    # Emit nodes grouped by type for easier visual grouping.
    for node_id in sorted(scope_ids):
        node = nodes_by_id[node_id]
        lines.append(_node_line(node_id, "Scope", node.get("name", node_id)))
    for node_id in sorted(framework_ids):
        node = nodes_by_id[node_id]
        lines.append(_node_line(node_id, "Framework", node.get("name", node_id)))
    for node_id in sorted(control_ids):
        node = nodes_by_id[node_id]
        short_id = node.get("control_id") or node_id
        lines.append(_node_line(node_id, "Control", short_id))
    for node_id in sorted(resource_ids):
        node = nodes_by_id[node_id]
        short_id = node.get("resource_id") or node_id
        lines.append(_node_line(node_id, "Resource", short_id))

    for src, dst in sorted(applies_to_edges):
        lines.append(f'  "{src}" -> "{dst}" [label="APPLIES_TO"];')
    for src, dst in sorted(scoped_to_edges):
        lines.append(f'  "{src}" -> "{dst}" [label="SCOPED_TO"];')
    for src, dst in sorted(contains_edges):
        lines.append(f'  "{src}" -> "{dst}" [label="CONTAINS", style=dashed];')

    lines.append("}")
    return "\n".join(lines) + "\n"
