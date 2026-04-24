"""Tests for the `lemma resource` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_yaml(id_: str = "prod-rds", scope: str = "default") -> str:
    return f"id: {id_}\ntype: aws.rds.instance\nscope: {scope}\nattributes:\n  region: us-east-1\n"


def _graph_with_scope(tmp_path: Path, scope: str = "default") -> None:
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_scope(
        name=scope,
        frameworks=["nist-800-53"],
        justification="seeded",
        rule_count=0,
    )
    g.save(tmp_path / ".lemma" / "graph.json")


class TestResourceLoad:
    def test_happy_path_adds_nodes_and_edges(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope(tmp_path)
        resources_dir = tmp_path / "resources"
        resources_dir.mkdir()
        (resources_dir / "rds.yaml").write_text(_valid_yaml("prod-us-east-rds"))

        result = runner.invoke(app, ["resource", "load"])
        assert result.exit_code == 0, result.stdout
        assert "prod-us-east-rds" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:prod-us-east-rds") is not None
        edges = g.get_edges("resource:prod-us-east-rds", "scope:default")
        assert any(e.get("relationship") == "SCOPED_TO" for e in edges)

    def test_unknown_scope_aborts_and_graph_stays_clean(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope(tmp_path)  # only "default"
        resources_dir = tmp_path / "resources"
        resources_dir.mkdir()
        (resources_dir / "bad.yaml").write_text(_valid_yaml("orphan", scope="missing"))

        result = runner.invoke(app, ["resource", "load"])
        assert result.exit_code == 1
        assert "missing" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:orphan") is None

    def test_empty_directory_is_not_an_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope(tmp_path)

        result = runner.invoke(app, ["resource", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no resources" in result.stdout.lower() or "resources/" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["resource", "load"])
        assert result.exit_code == 1


class TestResourceList:
    def test_shows_declared_resources_with_scope_checkmark(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope(tmp_path)
        resources_dir = tmp_path / "resources"
        resources_dir.mkdir()
        (resources_dir / "rds.yaml").write_text(_valid_yaml("prod-rds", scope="default"))
        (resources_dir / "lost.yaml").write_text(_valid_yaml("lost-bucket", scope="missing"))

        result = runner.invoke(app, ["resource", "list"])
        assert result.exit_code == 0, result.stdout
        assert "prod-rds" in result.stdout
        assert "lost-bucket" in result.stdout
        # Declared scope exists → ✓; missing scope → ✗.
        assert "✓" in result.stdout
        assert "✗" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["resource", "list"])
        assert result.exit_code == 1
