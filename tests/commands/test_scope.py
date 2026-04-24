"""Tests for the `lemma scope` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_yaml(name: str = "prod-us-east") -> str:
    return (
        f"name: {name}\n"
        "frameworks:\n"
        "  - nist-800-53\n"
        'justification: "Prod."\n'
        "match_rules:\n"
        "  - source: aws.tags.Environment\n"
        "    operator: equals\n"
        "    value: prod\n"
    )


class TestScopeInit:
    def test_creates_default_yaml(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 0, result.stdout
        target = tmp_path / "scopes" / "default.yaml"
        assert target.exists()
        # Starter content must be a valid scope that parses.
        from lemma.services.scope import load_scope

        scope = load_scope(target)
        assert scope.name  # non-empty
        assert scope.frameworks  # at least one framework in the template

    def test_custom_name_writes_that_file(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init", "--name", "prod"])

        assert result.exit_code == 0, result.stdout
        assert (tmp_path / "scopes" / "prod.yaml").exists()

    def test_refuses_to_overwrite_existing(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        existing = scopes_dir / "default.yaml"
        existing.write_text("hand-authored: true\n")

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 1
        assert "exists" in result.stdout.lower() or "overwrite" in result.stdout.lower()
        # Untouched.
        assert existing.read_text() == "hand-authored: true\n"

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "init"])
        assert result.exit_code == 1


class TestScopeStatus:
    def test_empty_state_exits_zero_with_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "lemma scope init" in result.stdout.lower() or "no scopes" in result.stdout.lower()

    def test_renders_table_for_valid_scopes(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))
        (scopes_dir / "dev.yaml").write_text(_valid_yaml("dev-us-east"))

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout
        assert "dev-us-east" in result.stdout
        assert "nist-800-53" in result.stdout

    def test_exits_nonzero_when_any_scope_has_parse_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "ok.yaml").write_text(_valid_yaml("ok"))
        (scopes_dir / "broken.yaml").write_text(
            "name: broken\nframeworks:\n  - nist-800-53\nmatch_rule:\n  []\n"
        )

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 1
        assert "broken.yaml" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "status"])
        assert result.exit_code == 1

    def test_in_graph_column_reflects_load_state(self, tmp_path: Path, monkeypatch):
        """status must show ✓ after scope load, ✗ beforehand."""
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.save(tmp_path / ".lemma" / "graph.json")

        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))

        before = runner.invoke(app, ["scope", "status"])
        assert before.exit_code == 0
        assert "In Graph" in before.stdout
        assert "✗" in before.stdout  # not yet loaded

        assert runner.invoke(app, ["scope", "load"]).exit_code == 0

        after = runner.invoke(app, ["scope", "status"])
        assert after.exit_code == 0
        assert "✓" in after.stdout


def _graph_with_framework(tmp_path: Path, framework: str = "nist-800-53") -> None:
    """Seed .lemma/graph.json with a single indexed framework."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework(framework, title=framework.upper())
    g.save(tmp_path / ".lemma" / "graph.json")


class TestScopeLoad:
    def test_adds_scopes_and_edges_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("scope:prod-us-east") is not None
        edges = g.get_edges("scope:prod-us-east", "framework:nist-800-53")
        assert any(e.get("relationship") == "APPLIES_TO" for e in edges)

    def test_errors_on_unknown_framework(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)  # only nist-800-53 indexed
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "bad.yaml").write_text(
            "name: bad\nframeworks:\n  - iso-27001\njustification: ''\nmatch_rules: []\n"
        )

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 1
        assert "iso-27001" in result.stdout

        # Graph stays clean on failure.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("scope:bad") is None

    def test_empty_scopes_directory_is_not_an_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no scopes" in result.stdout.lower() or "lemma scope init" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 1
