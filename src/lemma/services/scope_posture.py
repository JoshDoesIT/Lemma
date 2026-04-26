"""Per-scope compliance posture computation.

Walks the graph from ``Scope → APPLIES_TO → Framework → CONTAINS → Control``
to count, per bound framework, how many controls are:

- ``mapped`` — have at least one inbound ``SATISFIES`` edge (a policy
  claims to satisfy them).
- ``evidenced`` — have at least one inbound ``EVIDENCES`` *or*
  ``IMPLICITLY_EVIDENCES`` edge (real-world evidence ties back to them,
  directly or via Cross-Scope Evidence Reuse through ``HARMONIZED_WITH``
  control equivalences).
- ``covered`` — both ``mapped`` and ``evidenced``.
- ``reused`` — controls that are evidenced ONLY via implicit edges
  (no direct EVIDENCES). Subset of ``evidenced``; useful for spotting
  which controls lean on harmonization-driven reuse.

Read-only. Uses ``graph.export_json()`` so it doesn't need access to the
private ``_graph`` attribute.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lemma.services.knowledge_graph import ComplianceGraph


@dataclass(frozen=True)
class FrameworkPosture:
    name: str
    total: int
    mapped: int
    evidenced: int
    covered: int
    reused: int = 0


@dataclass(frozen=True)
class ScopePosture:
    scope: str
    frameworks: list[FrameworkPosture] = field(default_factory=list)


def compute_posture(scope_name: str, graph: ComplianceGraph) -> ScopePosture:
    """Compute per-framework posture counts for a declared scope.

    Raises:
        ValueError: If ``scope_name`` has no corresponding ``Scope`` node
            in the graph. Operators fix this by running ``lemma scope load``.
    """
    export = graph.export_json()
    scope_node_id = f"scope:{scope_name}"
    node_ids = {node["id"] for node in export["nodes"]}
    if scope_node_id not in node_ids:
        msg = (
            f"Scope '{scope_name}' is missing from the graph. "
            "Run 'lemma scope load' to register it first."
        )
        raise ValueError(msg)

    # APPLIES_TO edges from this scope → framework nodes it binds.
    bound_frameworks = sorted(
        edge["target"]
        for edge in export["edges"]
        if edge["source"] == scope_node_id and edge.get("relationship") == "APPLIES_TO"
    )

    # Index controls by their parent framework (via CONTAINS edges).
    controls_by_framework: dict[str, list[str]] = {}
    for edge in export["edges"]:
        if edge.get("relationship") != "CONTAINS":
            continue
        controls_by_framework.setdefault(edge["source"], []).append(edge["target"])

    # Build inbound edge sets per control for O(1) lookup. `direct_evidenced`
    # tracks controls with a real EVIDENCES edge; `implicit_evidenced` tracks
    # controls with only IMPLICITLY_EVIDENCES (Cross-Scope Evidence Reuse).
    satisfied: set[str] = set()
    direct_evidenced: set[str] = set()
    implicit_evidenced: set[str] = set()
    for edge in export["edges"]:
        rel = edge.get("relationship")
        if rel == "SATISFIES":
            satisfied.add(edge["target"])
        elif rel == "EVIDENCES":
            direct_evidenced.add(edge["target"])
        elif rel == "IMPLICITLY_EVIDENCES":
            implicit_evidenced.add(edge["target"])

    evidenced = direct_evidenced | implicit_evidenced
    reused = implicit_evidenced - direct_evidenced

    framework_postures: list[FrameworkPosture] = []
    for framework_node_id in bound_frameworks:
        controls = controls_by_framework.get(framework_node_id, [])
        mapped = sum(1 for c in controls if c in satisfied)
        evidenced_count = sum(1 for c in controls if c in evidenced)
        covered = sum(1 for c in controls if c in satisfied and c in evidenced)
        reused_count = sum(1 for c in controls if c in reused)

        # Strip the "framework:" prefix for the display name.
        name = framework_node_id.removeprefix("framework:")
        framework_postures.append(
            FrameworkPosture(
                name=name,
                total=len(controls),
                mapped=mapped,
                evidenced=evidenced_count,
                covered=covered,
                reused=reused_count,
            )
        )

    return ScopePosture(scope=scope_name, frameworks=framework_postures)
