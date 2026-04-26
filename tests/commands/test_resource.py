"""Tests for the `lemma resource` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_yaml(id_: str = "prod-rds", scopes: list[str] | None = None) -> str:
    scope_lines = "\n".join(f"  - {s}" for s in (scopes or ["default"]))
    return (
        f"id: {id_}\n"
        f"type: aws.rds.instance\n"
        f"scopes:\n{scope_lines}\n"
        f"attributes:\n  region: us-east-1\n"
    )


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

    def test_multi_scope_yaml_creates_n_scoped_to_edges(self, tmp_path: Path, monkeypatch):
        """Scope Ring Model: a resource declared in 2 scopes lands with 2 edges."""
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        # Seed both scopes.
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_scope(name="prod", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.add_scope(name="pci", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.save(tmp_path / ".lemma" / "graph.json")

        resources_dir = tmp_path / "resources"
        resources_dir.mkdir()
        (resources_dir / "payments.yaml").write_text(
            _valid_yaml("payments-db", scopes=["prod", "pci"])
        )

        result = runner.invoke(app, ["resource", "load"])
        assert result.exit_code == 0, result.stdout

        loaded = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        prod_edges = loaded.get_edges("resource:payments-db", "scope:prod")
        pci_edges = loaded.get_edges("resource:payments-db", "scope:pci")
        assert any(e.get("relationship") == "SCOPED_TO" for e in prod_edges)
        assert any(e.get("relationship") == "SCOPED_TO" for e in pci_edges)

    def test_unknown_scope_aborts_and_graph_stays_clean(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope(tmp_path)  # only "default"
        resources_dir = tmp_path / "resources"
        resources_dir.mkdir()
        (resources_dir / "bad.yaml").write_text(_valid_yaml("orphan", scopes=["missing"]))

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
        (resources_dir / "rds.yaml").write_text(_valid_yaml("prod-rds", scopes=["default"]))
        (resources_dir / "lost.yaml").write_text(_valid_yaml("lost-bucket", scopes=["missing"]))

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


class TestResourceLoadWithImpacts:
    def test_impacts_field_creates_edges_in_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        # Seed graph with a framework, control, and scope.
        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(framework="nist-800-53", control_id="au-2", title="AU-2", family="AU")
        g.add_scope(name="default", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.save(tmp_path / ".lemma" / "graph.json")

        resources_dir = tmp_path / "resources"
        resources_dir.mkdir()
        (resources_dir / "audit.yaml").write_text(
            "id: audit-bucket\n"
            "type: aws.s3.bucket\n"
            "scopes:\n  - default\n"
            "attributes:\n"
            "  region: us-east-1\n"
            "impacts:\n"
            "  - control:nist-800-53:au-2\n"
        )

        result = runner.invoke(app, ["resource", "load"])
        assert result.exit_code == 0, result.stdout

        loaded = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        edges = loaded.get_edges("resource:audit-bucket", "control:nist-800-53:au-2")
        assert any(e.get("relationship") == "IMPACTS" for e in edges)
