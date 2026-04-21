"""Tests for graph persistence and CLI integration.

Tests the save/load cycle for the knowledge graph and the
`lemma graph` CLI commands.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.services.knowledge_graph import ComplianceGraph

runner = CliRunner()


class TestGraphPersistence:
    """Tests for graph save/load to disk."""

    def test_save_and_load_roundtrip(self, tmp_path: Path):
        """Graph can be saved to JSON and loaded back with all data intact."""
        graph = ComplianceGraph()
        graph.add_framework("fw", title="Test Framework")
        graph.add_control(framework="fw", control_id="c-1", title="Control 1", family="F")
        graph.add_policy("policy.md", title="My Policy")
        graph.add_mapping(policy="policy.md", framework="fw", control_id="c-1", confidence=0.9)

        save_path = tmp_path / "graph.json"
        graph.save(save_path)

        loaded = ComplianceGraph.load(save_path)
        assert loaded.get_node("framework:fw") is not None
        assert loaded.get_node("control:fw:c-1") is not None
        assert loaded.get_node("policy:policy.md") is not None
        assert loaded.framework_control_count("fw") == 1

        edges = loaded.get_edges("policy:policy.md", "control:fw:c-1")
        assert len(edges) >= 1
        assert edges[0]["confidence"] == 0.9

    def test_load_nonexistent_returns_empty_graph(self, tmp_path: Path):
        """Loading from a nonexistent path returns an empty graph."""
        graph = ComplianceGraph.load(tmp_path / "nonexistent.json")
        assert graph.export_json()["nodes"] == []

    def test_save_creates_parent_directories(self, tmp_path: Path):
        """save() creates parent directories if they don't exist."""
        graph = ComplianceGraph()
        graph.add_framework("fw", title="Test")

        save_path = tmp_path / "deep" / "nested" / "graph.json"
        graph.save(save_path)

        assert save_path.exists()


class TestGraphExportCommand:
    """Tests for the `lemma graph export` CLI command."""

    def test_graph_export_outputs_json(self, tmp_path: Path, monkeypatch):
        """lemma graph export outputs the graph as JSON."""
        from lemma.cli import app

        # Initialize project
        (tmp_path / ".lemma").mkdir()
        (tmp_path / ".lemma" / "index").mkdir(parents=True)

        # Pre-populate graph
        graph = ComplianceGraph()
        graph.add_framework("nist-800-53", title="NIST 800-53")
        graph.add_control(
            framework="nist-800-53",
            control_id="ac-1",
            title="Access Control",
            family="AC",
        )
        graph_path = tmp_path / ".lemma" / "graph.json"
        graph.save(graph_path)

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["graph", "export"])
        assert result.exit_code == 0

        output = json.loads(result.stdout)
        assert "nodes" in output
        assert "edges" in output
        assert len(output["nodes"]) == 2

    def test_graph_export_empty_project(self, tmp_path: Path, monkeypatch):
        """lemma graph export with no graph outputs empty structure."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["graph", "export"])
        assert result.exit_code == 0

        output = json.loads(result.stdout)
        assert output["nodes"] == []
        assert output["edges"] == []


class TestImpactCommand:
    """Tests for the `lemma graph impact` CLI command."""

    def test_impact_shows_affected_controls(self, tmp_path: Path, monkeypatch):
        """lemma graph impact shows controls and frameworks affected by a node."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()

        graph = ComplianceGraph()
        graph.add_framework("fw-a", title="Framework A")
        graph.add_control(framework="fw-a", control_id="c-1", title="Control 1", family="F")
        graph.add_policy("policy.md", title="My Policy")
        graph.add_mapping(policy="policy.md", framework="fw-a", control_id="c-1", confidence=0.9)
        graph.save(tmp_path / ".lemma" / "graph.json")

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["graph", "impact", "policy:policy.md"])
        assert result.exit_code == 0
        assert "c-1" in result.stdout
        assert "fw-a" in result.stdout

    def test_impact_unknown_node(self, tmp_path: Path, monkeypatch):
        """lemma graph impact with unknown node shows empty result."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()

        graph = ComplianceGraph()
        graph.save(tmp_path / ".lemma" / "graph.json")

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["graph", "impact", "policy:nonexistent"])
        assert result.exit_code == 0
        assert "No impact" in result.stdout or "0 controls" in result.stdout
