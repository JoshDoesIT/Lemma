"""Compliance Knowledge Graph — queryable relationship model.

Represents the relationships between frameworks, controls, policies,
mappings, and harmonizations as a directed graph. Uses NetworkX as
an embedded graph engine (no external database required).

Node types:
    - Framework: A compliance framework (e.g., NIST 800-53)
    - Control: A specific control within a framework
    - Policy: An organizational policy document

Edge types:
    - CONTAINS: Framework → Control
    - SATISFIES: Policy → Control (with confidence score)
    - HARMONIZED_WITH: Control ↔ Control (cross-framework equivalence)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx


class ComplianceGraph:
    """In-memory compliance knowledge graph backed by NetworkX."""

    def __init__(self) -> None:
        """Initialize an empty compliance graph."""
        self._graph = nx.MultiDiGraph()

    # --- Node operations ---

    def add_framework(self, name: str, *, title: str = "") -> None:
        """Add a Framework node to the graph.

        Args:
            name: Framework short name (e.g., 'nist-800-53').
            title: Human-readable title.
        """
        node_id = f"framework:{name}"
        self._graph.add_node(node_id, type="Framework", name=name, title=title)

    def add_control(
        self,
        *,
        framework: str,
        control_id: str,
        title: str,
        family: str,
        prose: str = "",
    ) -> None:
        """Add a Control node and a CONTAINS edge from its framework.

        Args:
            framework: Parent framework short name.
            control_id: Control identifier (e.g., 'ac-1').
            title: Control title.
            family: Control family/group.
            prose: Control prose text.
        """
        node_id = f"control:{framework}:{control_id}"
        fw_id = f"framework:{framework}"

        # Ensure framework node exists
        if fw_id not in self._graph:
            self.add_framework(framework)

        self._graph.add_node(
            node_id,
            type="Control",
            control_id=control_id,
            title=title,
            family=family,
            prose=prose,
        )
        self._graph.add_edge(fw_id, node_id, relationship="CONTAINS")

    def add_policy(self, path: str, *, title: str = "") -> None:
        """Add a Policy node to the graph.

        Args:
            path: Policy file path or identifier.
            title: Human-readable policy title.
        """
        node_id = f"policy:{path}"
        self._graph.add_node(node_id, type="Policy", path=path, title=title)

    # --- Edge operations ---

    def add_mapping(
        self,
        *,
        policy: str,
        framework: str,
        control_id: str,
        confidence: float,
    ) -> None:
        """Add a SATISFIES edge from a policy to a control.

        Args:
            policy: Policy path/identifier.
            framework: Framework short name.
            control_id: Control identifier.
            confidence: Mapping confidence score (0.0-1.0).
        """
        policy_id = f"policy:{policy}"
        control_node = f"control:{framework}:{control_id}"

        self._graph.add_edge(
            policy_id,
            control_node,
            relationship="SATISFIES",
            confidence=confidence,
        )

    def add_scope(
        self,
        *,
        name: str,
        frameworks: list[str],
        justification: str = "",
        rule_count: int = 0,
    ) -> None:
        """Add a Scope node with APPLIES_TO edges to each bound framework.

        Args:
            name: Scope identifier (unique within the graph).
            frameworks: Framework short names the scope binds to. Every
                name must already be in the graph — we refuse to create
                edges to non-existent frameworks because a scope that
                references an un-indexed framework is an operator error,
                not a silent warning.
            justification: Free-text audit rationale copied into the node.
            rule_count: How many match rules the scope declares; kept on
                the node so callers can render a summary without reparsing
                the YAML.

        Raises:
            ValueError: If any named framework has no corresponding
                Framework node. The error names the missing frameworks so
                the operator can run ``lemma framework add`` for them.
        """
        missing = [fw for fw in frameworks if f"framework:{fw}" not in self._graph]
        if missing:
            msg = (
                f"Scope '{name}' references framework(s) not indexed in the graph: "
                f"{', '.join(sorted(missing))}. Run 'lemma framework add <name>' first."
            )
            raise ValueError(msg)

        node_id = f"scope:{name}"
        self._graph.add_node(
            node_id,
            type="Scope",
            name=name,
            justification=justification,
            rule_count=rule_count,
        )

        # Idempotent: remove any existing APPLIES_TO edges from this scope
        # before rebuilding, so re-adding a scope with fewer frameworks
        # drops the stale bindings cleanly.
        for _source, target, key, attrs in list(
            self._graph.out_edges(node_id, keys=True, data=True)
        ):
            if attrs.get("relationship") == "APPLIES_TO":
                self._graph.remove_edge(node_id, target, key=key)

        for framework in frameworks:
            self._graph.add_edge(
                node_id,
                f"framework:{framework}",
                relationship="APPLIES_TO",
            )

    def add_harmonization(
        self,
        *,
        framework_a: str,
        control_a: str,
        framework_b: str,
        control_b: str,
        similarity: float,
    ) -> None:
        """Add a HARMONIZED_WITH edge between two controls.

        Args:
            framework_a: First framework short name.
            control_a: First control identifier.
            framework_b: Second framework short name.
            control_b: Second control identifier.
            similarity: Cosine similarity score.
        """
        node_a = f"control:{framework_a}:{control_a}"
        node_b = f"control:{framework_b}:{control_b}"

        self._graph.add_edge(node_a, node_b, relationship="HARMONIZED_WITH", similarity=similarity)
        self._graph.add_edge(node_b, node_a, relationship="HARMONIZED_WITH", similarity=similarity)

    # --- Bulk operations ---

    def populate_from_controls(self, framework: str, controls: list[dict]) -> None:
        """Bulk-load a framework's control records into the graph.

        Idempotent — re-populating the same framework updates existing nodes.

        Args:
            framework: Framework short name.
            controls: List of control record dicts with id, title, prose, family.
        """
        self.add_framework(framework)

        for ctrl in controls:
            self.add_control(
                framework=framework,
                control_id=ctrl["id"],
                title=ctrl.get("title", ""),
                family=ctrl.get("family", ""),
                prose=ctrl.get("prose", ""),
            )

    # --- Query operations ---

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        """Get node attributes by ID.

        Returns:
            Dict of node attributes, or None if not found.
        """
        if node_id in self._graph:
            return dict(self._graph.nodes[node_id])
        return None

    def get_edges(self, source: str, target: str) -> list[dict[str, Any]]:
        """Get all edges between two nodes.

        Returns:
            List of edge attribute dicts.
        """
        if not self._graph.has_node(source) or not self._graph.has_node(target):
            return []

        edges = []
        if self._graph.has_edge(source, target):
            edge_data = self._graph.get_edge_data(source, target)
            if edge_data:
                for _key, attrs in edge_data.items():
                    edges.append(dict(attrs))
        return edges

    def query_neighbors(self, node_id: str) -> list[dict[str, Any]]:
        """Get all nodes connected to the given node.

        Returns:
            List of dicts with 'id' and all node attributes.
        """
        if node_id not in self._graph:
            return []

        neighbors = []
        # Successors (outgoing edges)
        for neighbor in self._graph.successors(node_id):
            attrs = dict(self._graph.nodes[neighbor])
            attrs["id"] = neighbor
            neighbors.append(attrs)
        # Predecessors (incoming edges)
        for neighbor in self._graph.predecessors(node_id):
            if neighbor != node_id:
                attrs = dict(self._graph.nodes[neighbor])
                attrs["id"] = neighbor
                if attrs not in neighbors:
                    neighbors.append(attrs)
        return neighbors

    def impact(self, node_id: str) -> dict[str, Any]:
        """Analyze the compliance impact of a node.

        Traverses the graph to find all controls and frameworks
        reachable from the given node.

        Args:
            node_id: Node to analyze impact for.

        Returns:
            Dict with 'controls' and 'frameworks' lists.
        """
        controls: list[dict] = []
        frameworks: set[str] = set()
        visited: set[str] = set()

        def _traverse(nid: str) -> None:
            if nid in visited:
                return
            visited.add(nid)

            node = self.get_node(nid)
            if node is None:
                return

            if node.get("type") == "Control":
                controls.append({"id": node.get("control_id", ""), **node})
            if node.get("type") == "Framework":
                frameworks.add(node.get("name", ""))

            # Follow outgoing edges
            for neighbor in self._graph.successors(nid):
                _traverse(neighbor)

            # Follow incoming edges (e.g., Framework→Control)
            for neighbor in self._graph.predecessors(nid):
                _traverse(neighbor)

        _traverse(node_id)

        return {"controls": controls, "frameworks": sorted(frameworks)}

    def framework_control_count(self, framework: str) -> int:
        """Count controls belonging to a framework.

        Args:
            framework: Framework short name.

        Returns:
            Number of controls in the framework.
        """
        fw_id = f"framework:{framework}"
        if fw_id not in self._graph:
            return 0

        return sum(
            1
            for n in self._graph.successors(fw_id)
            if self._graph.nodes[n].get("type") == "Control"
        )

    # --- Export ---

    def export_json(self) -> dict[str, Any]:
        """Export the graph as a JSON-serializable dict.

        Returns:
            Dict with 'nodes' and 'edges' lists, suitable for
            D3.js or Cytoscape rendering.
        """
        nodes = []
        for node_id, attrs in self._graph.nodes(data=True):
            nodes.append({"id": node_id, **attrs})

        edges = []
        for source, target, attrs in self._graph.edges(data=True):
            edges.append({"source": source, "target": target, **attrs})

        return {"nodes": nodes, "edges": edges}

    # --- Persistence ---

    def save(self, path: Path) -> None:
        """Save the graph to a JSON file.

        Args:
            path: File path to save the graph to.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        data = nx.node_link_data(self._graph)
        path.write_text(json.dumps(data, indent=2, default=str))

    @classmethod
    def load(cls, path: Path) -> ComplianceGraph:
        """Load a graph from a JSON file.

        If the file does not exist, returns an empty graph.

        Args:
            path: File path to load the graph from.

        Returns:
            Loaded ComplianceGraph instance.
        """
        instance = cls()
        if path.exists():
            data = json.loads(path.read_text())
            instance._graph = nx.node_link_graph(data, directed=True, multigraph=True)
        return instance
