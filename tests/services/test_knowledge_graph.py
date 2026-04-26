"""Compliance Knowledge Graph — tests for graph data model and population.

Tests the NetworkX-based knowledge graph that represents relationships
between frameworks, controls, policies, and harmonization mappings.
"""

from __future__ import annotations

from lemma.services.knowledge_graph import ComplianceGraph


class TestComplianceGraph:
    """Tests for the compliance knowledge graph."""

    def test_add_framework_creates_framework_node(self):
        """Adding a framework creates a Framework node."""
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53", title="NIST SP 800-53 Rev 5")

        node = graph.get_node("framework:nist-800-53")
        assert node is not None
        assert node["type"] == "Framework"
        assert node["title"] == "NIST SP 800-53 Rev 5"

    def test_add_control_creates_control_with_edges(self):
        """Adding a control creates a Control node and CONTAINS edge from framework."""
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53", title="NIST SP 800-53 Rev 5")
        graph.add_control(
            framework="nist-800-53",
            control_id="ac-1",
            title="Access Control Policy",
            family="Access Control",
        )

        node = graph.get_node("control:nist-800-53:ac-1")
        assert node is not None
        assert node["type"] == "Control"
        assert node["title"] == "Access Control Policy"
        assert node["family"] == "Access Control"

        # Framework → Control edge
        edges = graph.get_edges("framework:nist-800-53", "control:nist-800-53:ac-1")
        assert any(e["relationship"] == "CONTAINS" for e in edges)

    def test_add_policy_creates_policy_node(self):
        """Adding a policy creates a Policy node."""
        graph = ComplianceGraph()
        graph.add_policy("access-control.md", title="Access Control Policy")

        node = graph.get_node("policy:access-control.md")
        assert node is not None
        assert node["type"] == "Policy"

    def test_add_mapping_creates_satisfies_edge(self):
        """Adding a mapping creates a SATISFIES edge from policy to control."""
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53", title="NIST SP 800-53 Rev 5")
        graph.add_control(
            framework="nist-800-53",
            control_id="ac-1",
            title="Access Control Policy",
            family="Access Control",
        )
        graph.add_policy("access-control.md", title="Access Control Policy")
        graph.add_mapping(
            policy="access-control.md",
            framework="nist-800-53",
            control_id="ac-1",
            confidence=0.92,
        )

        edges = graph.get_edges("policy:access-control.md", "control:nist-800-53:ac-1")
        assert len(edges) >= 1
        assert edges[0]["relationship"] == "SATISFIES"
        assert edges[0]["confidence"] == 0.92

    def test_add_harmonization_creates_harmonized_with_edge(self):
        """Adding harmonization creates HARMONIZED_WITH edges between controls."""
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53", title="NIST SP 800-53 Rev 5")
        graph.add_framework("nist-csf-2.0", title="NIST CSF 2.0")
        graph.add_control(
            framework="nist-800-53",
            control_id="ac-1",
            title="Access Control Policy",
            family="Access Control",
        )
        graph.add_control(
            framework="nist-csf-2.0",
            control_id="pr.ac-01",
            title="Identity Management",
            family="Protect",
        )
        graph.add_harmonization(
            framework_a="nist-800-53",
            control_a="ac-1",
            framework_b="nist-csf-2.0",
            control_b="pr.ac-01",
            similarity=0.88,
        )

        edges = graph.get_edges("control:nist-800-53:ac-1", "control:nist-csf-2.0:pr.ac-01")
        assert len(edges) >= 1
        assert edges[0]["relationship"] == "HARMONIZED_WITH"
        assert edges[0]["similarity"] == 0.88

    def test_populate_from_controls(self):
        """populate_from_controls bulk-loads a framework's control records."""
        graph = ComplianceGraph()
        controls = [
            {"id": "ac-1", "title": "Access Control", "prose": "...", "family": "AC"},
            {"id": "ir-1", "title": "Incident Response", "prose": "...", "family": "IR"},
        ]
        graph.populate_from_controls("test-fw", controls)

        assert graph.get_node("framework:test-fw") is not None
        assert graph.get_node("control:test-fw:ac-1") is not None
        assert graph.get_node("control:test-fw:ir-1") is not None
        assert graph.framework_control_count("test-fw") == 2

    def test_query_neighbors(self):
        """query_neighbors returns connected nodes."""
        graph = ComplianceGraph()
        graph.add_framework("fw", title="Test")
        graph.add_control(framework="fw", control_id="c1", title="C1", family="F")
        graph.add_control(framework="fw", control_id="c2", title="C2", family="F")

        neighbors = graph.query_neighbors("framework:fw")
        node_ids = {n["id"] for n in neighbors}
        assert "control:fw:c1" in node_ids
        assert "control:fw:c2" in node_ids

    def test_impact_analysis(self):
        """impact returns all controls and frameworks affected by a policy."""
        graph = ComplianceGraph()
        graph.add_framework("fw-a", title="Framework A")
        graph.add_framework("fw-b", title="Framework B")
        graph.add_control(framework="fw-a", control_id="c1", title="C1", family="F")
        graph.add_control(framework="fw-b", control_id="c2", title="C2", family="F")
        graph.add_policy("policy.md", title="My Policy")
        graph.add_mapping(policy="policy.md", framework="fw-a", control_id="c1", confidence=0.9)
        graph.add_harmonization(
            framework_a="fw-a",
            control_a="c1",
            framework_b="fw-b",
            control_b="c2",
            similarity=0.85,
        )

        impact = graph.impact("policy:policy.md")
        assert "fw-a" in impact["frameworks"]
        assert any(c["id"] == "c1" for c in impact["controls"])

    def test_export_json(self):
        """export_json produces a serializable dict with nodes and edges."""
        graph = ComplianceGraph()
        graph.add_framework("fw", title="Test")
        graph.add_control(framework="fw", control_id="c1", title="C1", family="F")

        data = graph.export_json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1

    def test_idempotent_population(self):
        """Populating the same framework twice does not create duplicate nodes."""
        graph = ComplianceGraph()
        controls = [
            {"id": "ac-1", "title": "Access Control", "prose": "...", "family": "AC"},
        ]
        graph.populate_from_controls("fw", controls)
        graph.populate_from_controls("fw", controls)

        assert graph.framework_control_count("fw") == 1
        assert len(graph.export_json()["nodes"]) == 2  # 1 framework + 1 control


class TestAddScope:
    """Scope nodes + APPLIES_TO edges (Refs #24, Scope-node half of #76)."""

    def test_creates_scope_node_and_applies_to_edges(self):
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53")
        graph.add_framework("nist-csf-2.0")

        graph.add_scope(
            name="prod-us-east",
            frameworks=["nist-800-53", "nist-csf-2.0"],
            justification="Customer-facing prod.",
            rule_count=3,
        )

        node = graph.get_node("scope:prod-us-east")
        assert node is not None
        assert node["type"] == "Scope"
        assert node["justification"] == "Customer-facing prod."
        assert node["rule_count"] == 3

        # APPLIES_TO edges from scope to each framework
        for framework in ("nist-800-53", "nist-csf-2.0"):
            edges = graph.get_edges("scope:prod-us-east", f"framework:{framework}")
            assert any(e.get("relationship") == "APPLIES_TO" for e in edges)

    def test_rejects_unknown_framework(self):
        """Scope bound to a framework not in the graph must fail loud."""
        import pytest

        graph = ComplianceGraph()
        graph.add_framework("nist-800-53")

        with pytest.raises(ValueError, match=r"(?i)iso-27001"):
            graph.add_scope(
                name="broken",
                frameworks=["nist-800-53", "iso-27001"],
                justification="",
                rule_count=0,
            )
        # Nothing should have been added.
        assert graph.get_node("scope:broken") is None

    def test_idempotent(self):
        """Adding the same scope twice updates in place; no duplicate edges."""
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53")

        graph.add_scope(
            name="prod",
            frameworks=["nist-800-53"],
            justification="v1",
            rule_count=2,
        )
        graph.add_scope(
            name="prod",
            frameworks=["nist-800-53"],
            justification="v2",
            rule_count=5,
        )

        node = graph.get_node("scope:prod")
        assert node["justification"] == "v2"
        assert node["rule_count"] == 5
        edges = graph.get_edges("scope:prod", "framework:nist-800-53")
        assert len(edges) == 1


class TestAddEvidence:
    """Evidence nodes + EVIDENCES edges (Refs #76, #88)."""

    def _seed_graph(self) -> ComplianceGraph:
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(
            framework="nist-800-53",
            control_id="ac-2",
            title="Account Management",
            family="AC",
        )
        g.add_framework("nist-csf-2.0")
        g.add_control(
            framework="nist-csf-2.0",
            control_id="pr.aa-1",
            title="Identities and credentials",
            family="PR.AA",
        )
        return g

    def test_creates_evidence_node_with_required_attrs(self):
        graph = self._seed_graph()
        graph.add_evidence(
            entry_hash="abc123def456" * 5 + "0000",  # 64 hex chars
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-23T12:00:00+00:00",
            control_refs=[],
        )

        node_id = "evidence:" + "abc123def456" * 5 + "0000"
        node = graph.get_node(node_id)
        assert node is not None
        assert node["type"] == "Evidence"
        assert node["producer"] == "Lemma"
        assert node["class_name"] == "Compliance Finding"
        assert node["time_iso"] == "2026-04-23T12:00:00+00:00"
        assert node["entry_hash_short"] == "abc123def456"

    def test_empty_control_refs_creates_node_with_zero_edges(self):
        graph = self._seed_graph()
        entry = "a" * 64
        graph.add_evidence(
            entry_hash=entry,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-23T12:00:00+00:00",
            control_refs=[],
        )

        export = graph.export_json()
        evidence_edges = [e for e in export["edges"] if e.get("relationship") == "EVIDENCES"]
        assert evidence_edges == []

    def test_resolvable_refs_create_evidences_edges(self):
        graph = self._seed_graph()
        entry = "b" * 64
        graph.add_evidence(
            entry_hash=entry,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-23T12:00:00+00:00",
            control_refs=["nist-800-53:ac-2", "nist-csf-2.0:pr.aa-1"],
        )

        node_id = f"evidence:{entry}"
        for target in ("control:nist-800-53:ac-2", "control:nist-csf-2.0:pr.aa-1"):
            edges = graph.get_edges(node_id, target)
            assert any(e.get("relationship") == "EVIDENCES" for e in edges)

    def test_unresolved_refs_raise_and_leave_graph_untouched(self):
        import pytest

        graph = self._seed_graph()
        entry = "c" * 64

        with pytest.raises(ValueError, match=r"(?i)nist-800-53:acc-2|typo-fw"):
            graph.add_evidence(
                entry_hash=entry,
                producer="Lemma",
                class_name="Compliance Finding",
                time_iso="2026-04-23T12:00:00+00:00",
                control_refs=["nist-800-53:acc-2", "typo-fw:foo"],
            )
        # No Evidence node should have been added.
        assert graph.get_node(f"evidence:{entry}") is None

    def test_idempotent_rebuilds_edges(self):
        graph = self._seed_graph()
        entry = "d" * 64

        graph.add_evidence(
            entry_hash=entry,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-23T12:00:00+00:00",
            control_refs=["nist-800-53:ac-2", "nist-csf-2.0:pr.aa-1"],
        )
        # Re-add with a narrower ref list — the stale edge should drop.
        graph.add_evidence(
            entry_hash=entry,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-23T12:00:00+00:00",
            control_refs=["nist-800-53:ac-2"],
        )

        node_id = f"evidence:{entry}"
        first_edges = graph.get_edges(node_id, "control:nist-800-53:ac-2")
        second_edges = graph.get_edges(node_id, "control:nist-csf-2.0:pr.aa-1")
        assert len(first_edges) == 1
        assert second_edges == []


class TestAddEvidenceMapping:
    """Single AI-inferred EVIDENCES edge with confidence (Refs #88)."""

    def _seed_graph_with_evidence(self) -> tuple[ComplianceGraph, str]:
        g = ComplianceGraph()
        g.add_framework("nist-csf-2.0")
        g.add_control(
            framework="nist-csf-2.0",
            control_id="de.cm-01",
            title="Continuous monitoring",
            family="DE.CM",
        )
        entry = "a" * 64
        g.add_evidence(
            entry_hash=entry,
            producer="connector:cloudtrail",
            class_name="Compliance Finding",
            time_iso="2026-04-25T00:00:00+00:00",
            control_refs=[],
        )
        return g, entry

    def test_creates_single_evidences_edge_with_confidence(self):
        graph, entry = self._seed_graph_with_evidence()

        graph.add_evidence_mapping(
            entry_hash=entry,
            framework="nist-csf-2.0",
            control_id="de.cm-01",
            confidence=0.83,
        )

        node_id = f"evidence:{entry}"
        target = "control:nist-csf-2.0:de.cm-01"
        edges = graph.get_edges(node_id, target)
        relevant = [e for e in edges if e.get("relationship") == "EVIDENCES"]
        assert len(relevant) == 1
        assert relevant[0]["confidence"] == 0.83

    def test_raises_when_evidence_node_missing(self):
        import pytest

        graph, _entry = self._seed_graph_with_evidence()
        missing = "f" * 64

        with pytest.raises(ValueError, match=r"(?i)evidence|not found|missing"):
            graph.add_evidence_mapping(
                entry_hash=missing,
                framework="nist-csf-2.0",
                control_id="de.cm-01",
                confidence=0.9,
            )

    def test_raises_when_control_node_missing(self):
        import pytest

        graph, entry = self._seed_graph_with_evidence()

        with pytest.raises(ValueError, match=r"(?i)control|not found|missing"):
            graph.add_evidence_mapping(
                entry_hash=entry,
                framework="nist-csf-2.0",
                control_id="does-not-exist",
                confidence=0.9,
            )
        # The Evidence node still exists; only the missing-control call failed.
        assert graph.get_node(f"evidence:{entry}") is not None

    def test_idempotent_replaces_confidence_in_place(self):
        graph, entry = self._seed_graph_with_evidence()

        graph.add_evidence_mapping(
            entry_hash=entry,
            framework="nist-csf-2.0",
            control_id="de.cm-01",
            confidence=0.6,
        )
        graph.add_evidence_mapping(
            entry_hash=entry,
            framework="nist-csf-2.0",
            control_id="de.cm-01",
            confidence=0.9,
        )

        edges = graph.get_edges(f"evidence:{entry}", "control:nist-csf-2.0:de.cm-01")
        evidences = [e for e in edges if e.get("relationship") == "EVIDENCES"]
        assert len(evidences) == 1
        assert evidences[0]["confidence"] == 0.9


class TestAddResource:
    """Resource nodes + SCOPED_TO edges (Refs #76)."""

    def _graph_with_scopes(self) -> ComplianceGraph:
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_scope(
            name="prod",
            frameworks=["nist-800-53"],
            justification="Prod.",
            rule_count=0,
        )
        g.add_scope(
            name="dev",
            frameworks=["nist-800-53"],
            justification="Dev.",
            rule_count=0,
        )
        return g

    def test_creates_node_and_scoped_to_edge(self):
        graph = self._graph_with_scopes()
        graph.add_resource(
            resource_id="prod-rds",
            type_="aws.rds.instance",
            scopes=["prod"],
            attributes={"region": "us-east-1"},
        )

        node = graph.get_node("resource:prod-rds")
        assert node is not None
        assert node["type"] == "Resource"
        assert node["resource_type"] == "aws.rds.instance"
        assert node["attributes"] == {"region": "us-east-1"}
        # Drop the redundant scope/scopes node attribute — edges are the source of truth.
        assert "scope" not in node
        assert "scopes" not in node

        edges = graph.get_edges("resource:prod-rds", "scope:prod")
        assert any(e.get("relationship") == "SCOPED_TO" for e in edges)

    def test_creates_n_scoped_to_edges_for_overlapping_scopes(self):
        """Scope Ring Model: one Resource node, N SCOPED_TO edges."""
        graph = self._graph_with_scopes()
        graph.add_resource(
            resource_id="payments-db",
            type_="aws.rds.instance",
            scopes=["prod", "dev"],
            attributes={"engine": "postgres"},
        )

        prod_edges = graph.get_edges("resource:payments-db", "scope:prod")
        dev_edges = graph.get_edges("resource:payments-db", "scope:dev")
        assert any(e.get("relationship") == "SCOPED_TO" for e in prod_edges)
        assert any(e.get("relationship") == "SCOPED_TO" for e in dev_edges)

    def test_rejects_unknown_scope(self):
        import pytest

        graph = self._graph_with_scopes()
        with pytest.raises(ValueError, match=r"(?i)staging"):
            graph.add_resource(
                resource_id="orphan",
                type_="aws.s3.bucket",
                scopes=["staging"],
                attributes={},
            )
        assert graph.get_node("resource:orphan") is None

    def test_rejects_when_any_scope_missing(self):
        """All-or-nothing: if any scope in the list is unindexed, abort the whole add."""
        import pytest

        graph = self._graph_with_scopes()
        with pytest.raises(ValueError, match=r"(?i)staging"):
            graph.add_resource(
                resource_id="orphan",
                type_="aws.s3.bucket",
                scopes=["prod", "staging"],
                attributes={},
            )
        assert graph.get_node("resource:orphan") is None

    def test_rejects_empty_scopes_list(self):
        import pytest

        graph = self._graph_with_scopes()
        with pytest.raises(ValueError, match=r"(?i)at least one|empty|scopes"):
            graph.add_resource(
                resource_id="orphan",
                type_="aws.s3.bucket",
                scopes=[],
                attributes={},
            )
        assert graph.get_node("resource:orphan") is None

    def test_idempotent_update_rebuilds_edges(self):
        graph = self._graph_with_scopes()

        graph.add_resource(
            resource_id="movable",
            type_="aws.s3.bucket",
            scopes=["dev"],
            attributes={"v": 1},
        )
        # Move to a different scope; the old edge should drop cleanly.
        graph.add_resource(
            resource_id="movable",
            type_="aws.s3.bucket",
            scopes=["prod"],
            attributes={"v": 2},
        )

        node = graph.get_node("resource:movable")
        assert node["attributes"] == {"v": 2}

        dev_edges = graph.get_edges("resource:movable", "scope:dev")
        prod_edges = graph.get_edges("resource:movable", "scope:prod")
        assert dev_edges == []
        assert len(prod_edges) == 1

    def test_idempotent_multi_scope_rotation_drops_stale_and_adds_new(self):
        """Re-adding with scopes=[a, c] (rotating b → c) drops b cleanly."""
        graph = self._graph_with_scopes()

        graph.add_resource(
            resource_id="rotating",
            type_="aws.s3.bucket",
            scopes=["prod", "dev"],
        )
        graph.add_resource(
            resource_id="rotating",
            type_="aws.s3.bucket",
            scopes=["prod"],  # dev dropped
        )

        prod_edges = graph.get_edges("resource:rotating", "scope:prod")
        dev_edges = graph.get_edges("resource:rotating", "scope:dev")
        assert len(prod_edges) == 1
        assert dev_edges == []

    def test_matched_rules_attached_to_scoped_to_edges(self):
        """Edge attribution: each SCOPED_TO edge carries which rule(s) fired."""
        graph = self._graph_with_scopes()
        graph.add_resource(
            resource_id="payments-db",
            type_="aws.rds.instance",
            scopes=["prod", "dev"],
            matched_rules_by_scope={
                "prod": [{"source": "aws.tags.Environment", "operator": "equals", "value": "prod"}],
                "dev": [
                    {"source": "aws.region", "operator": "equals", "value": "us-east-1"},
                    {"source": "aws.tags.Owner", "operator": "equals", "value": "platform"},
                ],
            },
        )

        prod_edges = graph.get_edges("resource:payments-db", "scope:prod")
        dev_edges = graph.get_edges("resource:payments-db", "scope:dev")
        assert prod_edges[0]["matched_rules"] == [
            {"source": "aws.tags.Environment", "operator": "equals", "value": "prod"},
        ]
        assert dev_edges[0]["matched_rules"] == [
            {"source": "aws.region", "operator": "equals", "value": "us-east-1"},
            {"source": "aws.tags.Owner", "operator": "equals", "value": "platform"},
        ]

    def test_matched_rules_default_empty_when_omitted(self):
        """Manual declaration: no rule context → matched_rules is an empty list."""
        graph = self._graph_with_scopes()
        graph.add_resource(
            resource_id="manual-decl",
            type_="aws.s3.bucket",
            scopes=["prod"],
        )

        edges = graph.get_edges("resource:manual-decl", "scope:prod")
        assert edges[0]["matched_rules"] == []


class TestAddPerson:
    """Person nodes + OWNS edges (Refs #76)."""

    def _graph_with_control_and_resource(self) -> ComplianceGraph:
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(
            framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
        )
        g.add_scope(name="prod", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.add_resource(
            resource_id="prod-rds",
            type_="aws.rds.instance",
            scopes=["prod"],
            attributes={},
        )
        return g

    def test_owns_control_creates_person_and_edge(self):
        graph = self._graph_with_control_and_resource()
        graph.add_person(
            person_id="alice",
            name="Alice Chen",
            email="alice@example.com",
            role="Security Lead",
            owns=["control:nist-800-53:ac-2"],
        )

        node = graph.get_node("person:alice")
        assert node is not None
        assert node["type"] == "Person"
        assert node["full_name"] == "Alice Chen"
        assert node["email"] == "alice@example.com"
        assert node["role"] == "Security Lead"

        edges = graph.get_edges("person:alice", "control:nist-800-53:ac-2")
        assert any(e.get("relationship") == "OWNS" for e in edges)

    def test_owns_mixed_control_and_resource(self):
        graph = self._graph_with_control_and_resource()
        graph.add_person(
            person_id="bob",
            name="Bob",
            email="",
            role="",
            owns=["control:nist-800-53:ac-2", "resource:prod-rds"],
        )

        for target in ("control:nist-800-53:ac-2", "resource:prod-rds"):
            edges = graph.get_edges("person:bob", target)
            assert any(e.get("relationship") == "OWNS" for e in edges)

    def test_unresolved_target_raises_and_leaves_graph_untouched(self):
        import pytest

        graph = self._graph_with_control_and_resource()

        with pytest.raises(ValueError, match=r"(?i)missing-ctrl|ghost-resource"):
            graph.add_person(
                person_id="carol",
                name="Carol",
                email="",
                role="",
                owns=[
                    "control:nist-800-53:missing-ctrl",
                    "resource:ghost-resource",
                ],
            )
        assert graph.get_node("person:carol") is None

    def test_idempotent_rebuilds_edges(self):
        graph = self._graph_with_control_and_resource()

        graph.add_person(
            person_id="dave",
            name="Dave",
            email="",
            role="",
            owns=["control:nist-800-53:ac-2", "resource:prod-rds"],
        )
        # Re-add with narrower owns — the stale edge should drop.
        graph.add_person(
            person_id="dave",
            name="Dave",
            email="",
            role="",
            owns=["control:nist-800-53:ac-2"],
        )

        control_edges = graph.get_edges("person:dave", "control:nist-800-53:ac-2")
        resource_edges = graph.get_edges("person:dave", "resource:prod-rds")
        assert len(control_edges) == 1
        assert resource_edges == []


class TestAddRisk:
    """Risk nodes + THREATENS / MITIGATED_BY edges (closes #76 graph expansion)."""

    def _graph(self) -> ComplianceGraph:
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(
            framework="nist-800-53", control_id="au-2", title="Event Logging", family="AU"
        )
        g.add_control(
            framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
        )
        g.add_scope(name="prod", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.add_resource(
            resource_id="audit-bucket",
            type_="aws.s3.bucket",
            scopes=["prod"],
            attributes={},
        )
        return g

    def test_creates_risk_node_and_edges(self):
        graph = self._graph()
        graph.add_risk(
            risk_id="audit-log-loss",
            title="Loss of audit logs",
            description="Bucket compromised.",
            severity="high",
            threatens=["resource:audit-bucket"],
            mitigated_by=["control:nist-800-53:au-2"],
        )

        node = graph.get_node("risk:audit-log-loss")
        assert node is not None
        assert node["type"] == "Risk"
        assert node["title"] == "Loss of audit logs"
        assert node["severity"] == "high"

        threatens = graph.get_edges("risk:audit-log-loss", "resource:audit-bucket")
        mitigated = graph.get_edges("risk:audit-log-loss", "control:nist-800-53:au-2")
        assert any(e.get("relationship") == "THREATENS" for e in threatens)
        assert any(e.get("relationship") == "MITIGATED_BY" for e in mitigated)

    def test_unresolved_target_raises_and_leaves_graph_untouched(self):
        import pytest

        graph = self._graph()

        with pytest.raises(ValueError, match=r"(?i)ghost-resource|missing-control"):
            graph.add_risk(
                risk_id="orphan",
                title="t",
                description="",
                severity="medium",
                threatens=["resource:ghost-resource"],
                mitigated_by=["control:nist-800-53:missing-control"],
            )
        assert graph.get_node("risk:orphan") is None

    def test_idempotent_rebuilds_edges(self):
        graph = self._graph()

        graph.add_risk(
            risk_id="r1",
            title="t",
            description="",
            severity="low",
            threatens=["resource:audit-bucket"],
            mitigated_by=["control:nist-800-53:au-2", "control:nist-800-53:ac-2"],
        )
        # Re-add narrower
        graph.add_risk(
            risk_id="r1",
            title="t",
            description="",
            severity="critical",
            threatens=[],
            mitigated_by=["control:nist-800-53:au-2"],
        )

        node = graph.get_node("risk:r1")
        assert node["severity"] == "critical"

        threatens = graph.get_edges("risk:r1", "resource:audit-bucket")
        au2_edges = graph.get_edges("risk:r1", "control:nist-800-53:au-2")
        ac2_edges = graph.get_edges("risk:r1", "control:nist-800-53:ac-2")
        assert threatens == []
        assert len(au2_edges) == 1
        assert ac2_edges == []


class TestResourceImpacts:
    """Resource → Control IMPACTS edges via add_resource(impacts=...) (closes #76)."""

    def _graph(self) -> ComplianceGraph:
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(
            framework="nist-800-53", control_id="au-2", title="Event Logging", family="AU"
        )
        g.add_scope(name="prod", frameworks=["nist-800-53"], justification="", rule_count=0)
        return g

    def test_resource_with_impacts_creates_edges(self):
        graph = self._graph()
        graph.add_resource(
            resource_id="audit-bucket",
            type_="aws.s3.bucket",
            scopes=["prod"],
            attributes={},
            impacts=["control:nist-800-53:au-2"],
        )

        edges = graph.get_edges("resource:audit-bucket", "control:nist-800-53:au-2")
        assert any(e.get("relationship") == "IMPACTS" for e in edges)

    def test_unresolved_impacts_target_raises(self):
        import pytest

        graph = self._graph()
        with pytest.raises(ValueError, match=r"(?i)missing-ctrl"):
            graph.add_resource(
                resource_id="r",
                type_="aws.s3.bucket",
                scopes=["prod"],
                attributes={},
                impacts=["control:nist-800-53:missing-ctrl"],
            )
        assert graph.get_node("resource:r") is None

    def test_idempotent_rebuilds_impacts_edges(self):
        graph = self._graph()
        graph.add_control(framework="nist-800-53", control_id="ac-2", title="AC-2", family="AC")

        graph.add_resource(
            resource_id="r",
            type_="aws.s3.bucket",
            scopes=["prod"],
            attributes={},
            impacts=["control:nist-800-53:au-2", "control:nist-800-53:ac-2"],
        )
        # Re-add with narrower impacts
        graph.add_resource(
            resource_id="r",
            type_="aws.s3.bucket",
            scopes=["prod"],
            attributes={},
            impacts=["control:nist-800-53:au-2"],
        )

        au_edges = graph.get_edges("resource:r", "control:nist-800-53:au-2")
        ac_edges = graph.get_edges("resource:r", "control:nist-800-53:ac-2")
        assert len(au_edges) == 1
        assert ac_edges == []


class TestRebuildImplicitEvidences:
    """Cross-Scope Evidence Reuse: walk EVIDENCES + HARMONIZED_WITH and
    write IMPLICITLY_EVIDENCES edges so evidence on Control C in one
    framework also satisfies its harmonized peer in another framework.
    """

    def _graph_with_evidence_and_harmonization(
        self, *, similarity: float = 0.85
    ) -> ComplianceGraph:
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_framework("nist-csf-2.0")
        g.add_control(framework="nist-800-53", control_id="ac-2", title="Account Mgmt", family="AC")
        g.add_control(
            framework="nist-csf-2.0",
            control_id="pr.ac-01",
            title="Identities and credentials",
            family="PR",
        )
        g.add_harmonization(
            framework_a="nist-800-53",
            control_a="ac-2",
            framework_b="nist-csf-2.0",
            control_b="pr.ac-01",
            similarity=similarity,
        )
        g.add_evidence(
            entry_hash="a" * 64,
            producer="GitHub",
            class_name="Compliance Finding",
            time_iso="2026-04-26T12:00:00Z",
            control_refs=["nist-800-53:ac-2"],
        )
        return g

    def test_writes_implicit_edge_to_harmonized_peer(self):
        g = self._graph_with_evidence_and_harmonization(similarity=0.9)

        count = g.rebuild_implicit_evidences(min_similarity=0.7)
        assert count == 1

        evidence_id = "evidence:" + "a" * 64
        peer_id = "control:nist-csf-2.0:pr.ac-01"
        edges = g.get_edges(evidence_id, peer_id)
        implicit = [e for e in edges if e.get("relationship") == "IMPLICITLY_EVIDENCES"]
        assert len(implicit) == 1
        assert implicit[0]["via_control"] == "control:nist-800-53:ac-2"
        assert implicit[0]["similarity"] == 0.9

    def test_skips_peers_below_similarity_threshold(self):
        g = self._graph_with_evidence_and_harmonization(similarity=0.6)

        count = g.rebuild_implicit_evidences(min_similarity=0.7)
        assert count == 0

        peer_id = "control:nist-csf-2.0:pr.ac-01"
        edges = g.get_edges("evidence:" + "a" * 64, peer_id)
        assert all(e.get("relationship") != "IMPLICITLY_EVIDENCES" for e in edges)

    def test_skips_peers_already_directly_evidenced(self):
        """No implicit edge alongside a direct EVIDENCES; direct wins."""
        g = self._graph_with_evidence_and_harmonization(similarity=0.95)
        # Add a *direct* EVIDENCES from the same Evidence to the harmonized peer
        # (i.e. the operator declared both control_refs explicitly).
        g.add_evidence(
            entry_hash="a" * 64,
            producer="GitHub",
            class_name="Compliance Finding",
            time_iso="2026-04-26T12:00:00Z",
            control_refs=["nist-800-53:ac-2", "nist-csf-2.0:pr.ac-01"],
        )

        count = g.rebuild_implicit_evidences(min_similarity=0.7)
        assert count == 0

        peer_id = "control:nist-csf-2.0:pr.ac-01"
        edges = g.get_edges("evidence:" + "a" * 64, peer_id)
        relationships = [e.get("relationship") for e in edges]
        assert "EVIDENCES" in relationships
        assert "IMPLICITLY_EVIDENCES" not in relationships

    def test_idempotent_rebuild_drops_stale_edges(self):
        """Lowering then raising the threshold cleanly invalidates stale implicit edges."""
        g = self._graph_with_evidence_and_harmonization(similarity=0.75)

        first = g.rebuild_implicit_evidences(min_similarity=0.7)
        assert first == 1

        # Raise the threshold so the same harmonization no longer qualifies.
        second = g.rebuild_implicit_evidences(min_similarity=0.8)
        assert second == 0

        peer_id = "control:nist-csf-2.0:pr.ac-01"
        edges = g.get_edges("evidence:" + "a" * 64, peer_id)
        assert all(e.get("relationship") != "IMPLICITLY_EVIDENCES" for e in edges)

    def test_returns_zero_when_no_harmonization_edges(self):
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(framework="nist-800-53", control_id="ac-2", title="t", family="AC")
        g.add_evidence(
            entry_hash="b" * 64,
            producer="x",
            class_name="x",
            time_iso="2026-04-26T12:00:00Z",
            control_refs=["nist-800-53:ac-2"],
        )

        count = g.rebuild_implicit_evidences(min_similarity=0.7)
        assert count == 0
