"""Tests for automatic graph population during framework add and mapping.

Follows TDD: tests written BEFORE the implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from lemma.services.knowledge_graph import ComplianceGraph


class TestFrameworkPopulatesGraph:
    """Tests that framework add operations populate the knowledge graph."""

    def test_add_bundled_framework_populates_graph(self, tmp_path: Path):
        """add_bundled_framework writes Framework and Control nodes to graph."""
        from lemma.services.framework import add_bundled_framework

        # Initialize project structure
        (tmp_path / ".lemma").mkdir()

        add_bundled_framework("nist-800-53", project_dir=tmp_path)

        # Load the persisted graph
        graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        fw_node = graph.get_node("framework:nist-800-53")
        assert fw_node is not None
        assert fw_node["type"] == "Framework"

        # Should have controls
        count = graph.framework_control_count("nist-800-53")
        assert count > 0

    def test_add_framework_is_idempotent(self, tmp_path: Path):
        """Adding the same framework twice doesn't duplicate nodes."""
        from lemma.services.framework import add_bundled_framework

        (tmp_path / ".lemma").mkdir()

        add_bundled_framework("nist-800-53", project_dir=tmp_path)
        count_1 = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json").framework_control_count(
            "nist-800-53"
        )

        add_bundled_framework("nist-800-53", project_dir=tmp_path)
        count_2 = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json").framework_control_count(
            "nist-800-53"
        )

        assert count_1 == count_2

    def test_import_json_framework_populates_graph(self, tmp_path: Path):
        """import_framework for JSON files also populates the graph."""
        from lemma.services.framework import import_framework

        (tmp_path / ".lemma").mkdir()

        # Create a minimal OSCAL catalog JSON
        catalog = {
            "catalog": {
                "uuid": "test-uuid",
                "metadata": {"title": "Test Catalog"},
                "groups": [
                    {
                        "id": "ac",
                        "title": "Access Control",
                        "controls": [
                            {
                                "id": "ac-1",
                                "title": "Policy and Procedures",
                                "parts": [
                                    {
                                        "name": "statement",
                                        "prose": "Develop policy.",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }
        catalog_file = tmp_path / "test-catalog.json"
        catalog_file.write_text(json.dumps(catalog))

        import_framework(catalog_file, project_dir=tmp_path)

        graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert graph.get_node("framework:test-catalog") is not None
        assert graph.framework_control_count("test-catalog") == 1


class TestMapperPopulatesGraph:
    """Tests that mapping operations populate the knowledge graph."""

    def test_map_policies_adds_mapping_edges(self, tmp_path: Path):
        """map_policies writes Policy nodes and SATISFIES edges to graph."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies

        (tmp_path / ".lemma").mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "access.md").write_text("# Access Control\n\nAll users must use MFA.\n")

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "test-fw",
            [
                {
                    "id": "ac-7",
                    "title": "Unsuccessful Logon Attempts",
                    "prose": "Enforce lockout.",
                    "family": "AC",
                },
            ],
        )

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.9, "rationale": "MFA maps to logon controls."}
        )

        map_policies(
            framework="test-fw",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
        )

        graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")

        # Should have policy node(s)
        exported = graph.export_json()
        policy_nodes = [n for n in exported["nodes"] if n.get("type") == "Policy"]
        assert len(policy_nodes) >= 1

        # Should have SATISFIES edges
        satisfies_edges = [e for e in exported["edges"] if e.get("relationship") == "SATISFIES"]
        assert len(satisfies_edges) >= 1
        assert satisfies_edges[0]["confidence"] == 0.9

    def test_map_only_adds_mapped_results_to_graph(self, tmp_path: Path):
        """Only MAPPED results (above threshold) are added as graph edges."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies

        (tmp_path / ".lemma").mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "vague.md").write_text("# Vague Policy\n\nWe do security things.\n")

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "test-fw",
            [
                {
                    "id": "c-1",
                    "title": "Control 1",
                    "prose": "Test.",
                    "family": "F",
                },
            ],
        )

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps({"confidence": 0.2, "rationale": "Weak match."})

        map_policies(
            framework="test-fw",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.6,
        )

        graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        exported = graph.export_json()

        satisfies_edges = [e for e in exported["edges"] if e.get("relationship") == "SATISFIES"]
        # LOW_CONFIDENCE results should NOT create SATISFIES edges
        assert len(satisfies_edges) == 0
