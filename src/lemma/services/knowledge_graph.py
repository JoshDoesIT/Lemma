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

    def add_evidence(
        self,
        *,
        entry_hash: str,
        producer: str,
        class_name: str,
        time_iso: str,
        control_refs: list[str],
    ) -> None:
        """Add an Evidence node with EVIDENCES edges to each referenced control.

        Args:
            entry_hash: Hex-encoded SHA-256 entry hash from the signed
                evidence log. Used as the node identity.
            producer: The event's signing producer (e.g. ``"GitHub"``).
            class_name: OCSF class name (e.g. ``"Compliance Finding"``).
            time_iso: Event time as ISO-8601 string; stored verbatim so
                graph consumers don't need a datetime parser.
            control_refs: ``"<framework>:<control_id>"`` strings naming
                every control this evidence supports. Every ref must
                resolve to an existing Control node in the graph.

        Raises:
            ValueError: If any entry in ``control_refs`` names a control
                that is not indexed. Error lists all unresolved refs so
                the operator can fix them in one pass. Nothing is added
                when validation fails.
        """
        unresolved = [ref for ref in control_refs if f"control:{ref}" not in self._graph]
        if unresolved:
            msg = (
                f"Evidence {entry_hash[:12]}… references control(s) not indexed "
                f"in the graph: {', '.join(unresolved)}. Run "
                f"'lemma framework add <name>' for the parent framework(s) first."
            )
            raise ValueError(msg)

        node_id = f"evidence:{entry_hash}"
        self._graph.add_node(
            node_id,
            type="Evidence",
            entry_hash=entry_hash,
            entry_hash_short=entry_hash[:12],
            producer=producer,
            class_name=class_name,
            time_iso=time_iso,
        )

        # Idempotent: drop stale EVIDENCES edges before rebuilding so a
        # re-add with a narrower control_refs list cleanly removes bindings.
        for _source, target, key, attrs in list(
            self._graph.out_edges(node_id, keys=True, data=True)
        ):
            if attrs.get("relationship") == "EVIDENCES":
                self._graph.remove_edge(node_id, target, key=key)

        for ref in control_refs:
            self._graph.add_edge(
                node_id,
                f"control:{ref}",
                relationship="EVIDENCES",
            )

    def add_evidence_mapping(
        self,
        *,
        entry_hash: str,
        framework: str,
        control_id: str,
        confidence: float,
    ) -> None:
        """Add a single AI-inferred EVIDENCES edge with a confidence attribute.

        Distinct from ``add_evidence``: this method adds one edge between an
        existing Evidence node and an existing Control node without touching
        the Evidence node itself or any other EVIDENCES edges. Re-calling for
        the same (evidence, control) pair replaces the existing edge's
        ``confidence`` rather than duplicating.

        Args:
            entry_hash: SHA-256 hex of an Evidence node already in the graph.
            framework: Framework short name (e.g. ``"nist-csf-2.0"``).
            control_id: Control identifier within the framework.
            confidence: Mapping confidence score (0.0-1.0) recorded on the edge.

        Raises:
            ValueError: If the Evidence node or the Control node is not in
                the graph. The graph is left untouched on failure.
        """
        evidence_id = f"evidence:{entry_hash}"
        control_node = f"control:{framework}:{control_id}"

        missing: list[str] = []
        if evidence_id not in self._graph:
            missing.append(f"evidence node {evidence_id} not found")
        if control_node not in self._graph:
            missing.append(f"control node {control_node} not found")
        if missing:
            msg = "; ".join(missing) + "."
            raise ValueError(msg)

        # Idempotent: drop any prior EVIDENCES edge between this exact pair
        # so re-calling replaces confidence in place rather than duplicating.
        for _source, _target, key, attrs in list(
            self._graph.out_edges(evidence_id, keys=True, data=True)
        ):
            if _target == control_node and attrs.get("relationship") == "EVIDENCES":
                self._graph.remove_edge(evidence_id, control_node, key=key)

        self._graph.add_edge(
            evidence_id,
            control_node,
            relationship="EVIDENCES",
            confidence=confidence,
        )

    def add_resource(
        self,
        *,
        resource_id: str,
        type_: str,
        scopes: list[str],
        attributes: dict | None = None,
        impacts: list[str] | None = None,
        matched_rules_by_scope: dict[str, list[dict]] | None = None,
    ) -> None:
        """Add a Resource node with one SCOPED_TO edge per declared scope.

        Args:
            resource_id: Resource identifier (unique within the graph).
            type_: Free-form type string (e.g. ``"aws.rds.instance"``).
            scopes: Non-empty list of scope names. Every name must
                resolve to a Scope node already in the graph
                (`lemma scope load` first). One ``SCOPED_TO`` edge is
                written per scope; the Resource node itself is single
                regardless of how many scopes it belongs to (the Scope
                Ring Model — boundary overlap, not duplication).
            attributes: Arbitrary attributes copied onto the node for
                display and later scope-rule evaluation.
            impacts: Optional list of control refs (``control:<framework>:<id>``)
                this resource directly contributes to. ``IMPACTS`` is
                distinct from ``SCOPED_TO``: IMPACTS = direct dependency,
                SCOPED_TO = scope membership.
            matched_rules_by_scope: Optional ``{scope_name: [rule_dict, ...]}``
                attribution. Each rule dict is ``{source, operator, value}``
                indicating which scope rule(s) fired during discover. Manual
                declarations (`lemma resource load`) omit this argument; the
                resulting edges carry an empty ``matched_rules`` list, which
                ``lemma scope explain`` renders as "manual declaration."

        Raises:
            ValueError: If ``scopes`` is empty, any scope name has no
                corresponding Scope node, or any ``impacts`` entry doesn't
                resolve to an indexed Control node. Nothing is added when
                validation fails.
        """
        if not scopes:
            msg = f"Resource '{resource_id}' must declare at least one scope; got an empty list."
            raise ValueError(msg)

        missing_scopes = [s for s in scopes if f"scope:{s}" not in self._graph]
        if missing_scopes:
            msg = (
                f"Resource '{resource_id}' references scope(s) not indexed in the graph: "
                f"{', '.join(missing_scopes)}. Run 'lemma scope load' first, then retry."
            )
            raise ValueError(msg)

        impacts_list = list(impacts or [])
        unresolved = [ref for ref in impacts_list if ref not in self._graph]
        if unresolved:
            msg = (
                f"Resource '{resource_id}' impacts target(s) not indexed in the graph: "
                f"{', '.join(unresolved)}. Run 'lemma framework add <name>' for the "
                "parent framework(s) first."
            )
            raise ValueError(msg)

        attribution = matched_rules_by_scope or {}
        node_id = f"resource:{resource_id}"
        self._graph.add_node(
            node_id,
            type="Resource",
            resource_id=resource_id,
            resource_type=type_,
            attributes=dict(attributes or {}),
        )

        # Idempotent: drop stale SCOPED_TO and IMPACTS edges before rebuilding
        # so a resource that rotates scopes or narrows its impacts drops
        # the old edges cleanly.
        for _source, target, key, attrs in list(
            self._graph.out_edges(node_id, keys=True, data=True)
        ):
            if attrs.get("relationship") in {"SCOPED_TO", "IMPACTS"}:
                self._graph.remove_edge(node_id, target, key=key)

        for scope_name in scopes:
            self._graph.add_edge(
                node_id,
                f"scope:{scope_name}",
                relationship="SCOPED_TO",
                matched_rules=list(attribution.get(scope_name, [])),
            )
        for ref in impacts_list:
            self._graph.add_edge(node_id, ref, relationship="IMPACTS")

    def add_risk(
        self,
        *,
        risk_id: str,
        title: str,
        description: str = "",
        severity: str,
        threatens: list[str] | None = None,
        mitigated_by: list[str] | None = None,
    ) -> None:
        """Add a Risk node with THREATENS and MITIGATED_BY edges.

        Args:
            risk_id: Unique identifier within the project.
            title: Short human-readable summary.
            description: Optional longer narrative.
            severity: One of ``low``, ``medium``, ``high``, ``critical``
                (the value of a ``RiskSeverity`` enum).
            threatens: ``resource:<id>`` refs naming Resources whose
                compromise would realize this risk.
            mitigated_by: ``control:<framework>:<id>`` refs naming
                Controls that mitigate this risk.

        Raises:
            ValueError: If any ``threatens`` ref doesn't resolve to a
                Resource node, or any ``mitigated_by`` ref doesn't
                resolve to a Control node. Every unresolved ref is
                listed so the operator can fix them in one pass. Nothing
                is added when validation fails.
        """
        threatens_list = list(threatens or [])
        mitigated_list = list(mitigated_by or [])

        unresolved_threats = [ref for ref in threatens_list if ref not in self._graph]
        unresolved_mitigations = [ref for ref in mitigated_list if ref not in self._graph]
        if unresolved_threats or unresolved_mitigations:
            parts = []
            if unresolved_threats:
                parts.append(f"threatens: {', '.join(unresolved_threats)}")
            if unresolved_mitigations:
                parts.append(f"mitigated_by: {', '.join(unresolved_mitigations)}")
            msg = (
                f"Risk '{risk_id}' references graph node(s) that aren't indexed "
                f"({'; '.join(parts)}). Run 'lemma resource load' for missing "
                "resources, or 'lemma framework add <name>' for missing controls."
            )
            raise ValueError(msg)

        node_id = f"risk:{risk_id}"
        self._graph.add_node(
            node_id,
            type="Risk",
            risk_id=risk_id,
            title=title,
            description=description,
            severity=severity,
        )

        # Idempotent: drop stale THREATENS and MITIGATED_BY edges before
        # rebuilding so dropping a relationship cleanly removes the edge.
        for _source, target, key, attrs in list(
            self._graph.out_edges(node_id, keys=True, data=True)
        ):
            if attrs.get("relationship") in {"THREATENS", "MITIGATED_BY"}:
                self._graph.remove_edge(node_id, target, key=key)

        for ref in threatens_list:
            self._graph.add_edge(node_id, ref, relationship="THREATENS")
        for ref in mitigated_list:
            self._graph.add_edge(node_id, ref, relationship="MITIGATED_BY")

    def add_person(
        self,
        *,
        person_id: str,
        name: str,
        email: str = "",
        role: str = "",
        owns: list[str] | None = None,
    ) -> None:
        """Add a Person node with OWNS edges to declared controls and/or resources.

        Args:
            person_id: Unique identifier within the project.
            name: Human-readable full name (stored as ``full_name`` on the node
                to avoid collision with the built-in ``name`` attr NetworkX
                node dicts sometimes surface).
            email: Optional contact address.
            role: Optional role / title string.
            owns: Refs to controls and/or resources the person is accountable
                for. Each entry is either ``"control:<framework>:<id>"`` or
                ``"resource:<id>"`` — the same prefixed id used elsewhere in
                the graph. Every ref must resolve to an existing node.

        Raises:
            ValueError: If any ``owns`` entry names a node that isn't in the
                graph. Every unresolved ref is listed so the operator can fix
                them in one edit cycle. Nothing is added when validation fails.
        """
        owns_list = list(owns or [])

        unresolved = [ref for ref in owns_list if ref not in self._graph]
        if unresolved:
            msg = (
                f"Person '{person_id}' owns target(s) not indexed in the graph: "
                f"{', '.join(unresolved)}. Run 'lemma framework add <name>' for "
                "missing controls, or 'lemma resource load' for missing resources."
            )
            raise ValueError(msg)

        node_id = f"person:{person_id}"
        self._graph.add_node(
            node_id,
            type="Person",
            person_id=person_id,
            full_name=name,
            email=email,
            role=role,
        )

        # Idempotent: drop stale OWNS edges before rebuilding so dropping an
        # owner relationship removes the edge cleanly.
        for _source, target, key, attrs in list(
            self._graph.out_edges(node_id, keys=True, data=True)
        ):
            if attrs.get("relationship") == "OWNS":
                self._graph.remove_edge(node_id, target, key=key)

        for ref in owns_list:
            self._graph.add_edge(node_id, ref, relationship="OWNS")

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

    def rebuild_implicit_evidences(self, *, min_similarity: float) -> int:
        """Rebuild every IMPLICITLY_EVIDENCES edge from current EVIDENCES + HARMONIZED_WITH.

        Walk: for each Evidence node, for each direct ``EVIDENCES → Control C`` edge,
        for each Control C' reachable via a ``HARMONIZED_WITH`` edge whose
        ``similarity ≥ min_similarity``, write ``IMPLICITLY_EVIDENCES`` from
        Evidence → C' carrying ``via_control=C`` and ``similarity=<harmonization_score>``.

        Skips C' if a direct ``EVIDENCES`` from the same Evidence already exists
        (no point in adding a weaker implicit edge alongside a stronger direct one;
        direct wins for posture math).

        Idempotent: drops every existing ``IMPLICITLY_EVIDENCES`` edge before
        rewriting, so changing the threshold cleanly invalidates stale edges.

        Args:
            min_similarity: Harmonization-similarity floor; edges below are skipped.

        Returns:
            Count of ``IMPLICITLY_EVIDENCES`` edges written.
        """
        # Drop every existing implicit edge first (rebuild-from-scratch).
        for src, tgt, key, attrs in list(self._graph.edges(keys=True, data=True)):
            if attrs.get("relationship") == "IMPLICITLY_EVIDENCES":
                self._graph.remove_edge(src, tgt, key=key)

        evidence_nodes = [
            n for n, attrs in self._graph.nodes(data=True) if attrs.get("type") == "Evidence"
        ]

        written = 0
        for evidence_id in evidence_nodes:
            # Direct EVIDENCES targets for this Evidence node.
            direct_targets: set[str] = set()
            for _src, control_id, attrs in self._graph.out_edges(evidence_id, data=True):
                if attrs.get("relationship") == "EVIDENCES":
                    direct_targets.add(control_id)

            for control_id in direct_targets:
                # Walk this control's harmonized peers.
                for _src, peer_id, h_attrs in self._graph.out_edges(control_id, data=True):
                    if h_attrs.get("relationship") != "HARMONIZED_WITH":
                        continue
                    score = h_attrs.get("similarity", 0.0)
                    if score < min_similarity:
                        continue
                    if peer_id in direct_targets:
                        continue  # direct EVIDENCES already covers this peer
                    self._graph.add_edge(
                        evidence_id,
                        peer_id,
                        relationship="IMPLICITLY_EVIDENCES",
                        via_control=control_id,
                        similarity=score,
                    )
                    written += 1
        return written

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

    def iter_resources(self) -> list[dict[str, Any]]:
        """Return every Resource node as a dict with id, type, attrs, scopes, impacts.

        ``scopes`` is reconstructed by walking outgoing ``SCOPED_TO`` edges
        (post-Ring-Model semantics — edges are the source of truth, not a
        node attribute). Used by ``lemma scope drift`` and ``lemma scope
        watch`` to compute deltas against the current graph.
        """
        out: list[dict[str, Any]] = []
        for node_id, attrs in self._graph.nodes(data=True):
            if attrs.get("type") != "Resource":
                continue
            scopes: list[str] = []
            impacts: list[str] = []
            for _src, target, edge_attrs in self._graph.out_edges(node_id, data=True):
                rel = edge_attrs.get("relationship")
                if rel == "SCOPED_TO":
                    scopes.append(target.removeprefix("scope:"))
                elif rel == "IMPACTS":
                    impacts.append(target)
            out.append(
                {
                    "node_id": node_id,
                    "resource_id": attrs.get("resource_id"),
                    "resource_type": attrs.get("resource_type"),
                    "attributes": dict(attrs.get("attributes") or {}),
                    "scopes": scopes,
                    "impacts": impacts,
                }
            )
        return out

    def remove_resource(self, resource_id: str) -> bool:
        """Remove a Resource node and all its outgoing edges.

        Returns ``True`` if the node existed and was removed; ``False``
        if it wasn't in the graph (no-op). Used by ``lemma scope drift
        --apply`` to prune Resources whose underlying infrastructure no
        longer exists (closes #144).
        """
        node_id = f"resource:{resource_id}"
        if node_id not in self._graph:
            return False
        self._graph.remove_node(node_id)
        return True

    def outgoing_edges(self, node_id: str) -> list[dict[str, Any]]:
        """Return every outgoing edge from ``node_id`` as ``{target, **attrs}`` dicts.

        Used by ``lemma scope explain`` to walk a Resource's SCOPED_TO edges
        without having to know the target scope names up front.
        """
        if node_id not in self._graph:
            return []
        out: list[dict[str, Any]] = []
        for _src, target, attrs in self._graph.out_edges(node_id, data=True):
            out.append({"target": target, **dict(attrs)})
        return out

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
