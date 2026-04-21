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
