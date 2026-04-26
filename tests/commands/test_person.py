"""Tests for the `lemma person` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _person_yaml(id_: str, owns: list[str], name: str = "Alice Chen") -> str:
    lines = [f"id: {id_}", f"name: {name}", "email: alice@example.com", "role: Security Lead"]
    if owns:
        lines.append("owns:")
        for ref in owns:
            lines.append(f"  - {ref}")
    else:
        lines.append("owns: []")
    return "\n".join(lines) + "\n"


def _graph_with_control_and_resource(tmp_path: Path) -> None:
    """Seed .lemma/graph.json with a framework, control, scope, and resource."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-2", title="AC-2", family="AC")
    g.add_scope(name="prod", frameworks=["nist-800-53"], justification="", rule_count=0)
    g.add_resource(
        resource_id="prod-rds",
        type_="aws.rds.instance",
        scopes=["prod"],
        attributes={},
    )
    g.save(tmp_path / ".lemma" / "graph.json")


class TestPersonLoad:
    def test_happy_path_adds_person_and_edges(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_control_and_resource(tmp_path)
        people_dir = tmp_path / "people"
        people_dir.mkdir()
        (people_dir / "alice.yaml").write_text(
            _person_yaml(
                "alice",
                ["control:nist-800-53:ac-2", "resource:prod-rds"],
            )
        )

        result = runner.invoke(app, ["person", "load"])
        assert result.exit_code == 0, result.stdout
        assert "alice" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("person:alice") is not None
        assert g.get_edges("person:alice", "control:nist-800-53:ac-2")
        assert g.get_edges("person:alice", "resource:prod-rds")

    def test_unresolved_target_aborts_and_graph_stays_clean(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_control_and_resource(tmp_path)
        people_dir = tmp_path / "people"
        people_dir.mkdir()
        (people_dir / "bad.yaml").write_text(
            _person_yaml("orphan", ["control:nist-800-53:does-not-exist"])
        )

        result = runner.invoke(app, ["person", "load"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("person:orphan") is None

    def test_empty_directory_is_not_an_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_control_and_resource(tmp_path)

        result = runner.invoke(app, ["person", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no people" in result.stdout.lower() or "people/" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["person", "load"])
        assert result.exit_code == 1


class TestPersonList:
    def test_shows_validity_checkmark(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_control_and_resource(tmp_path)
        people_dir = tmp_path / "people"
        people_dir.mkdir()
        (people_dir / "alice.yaml").write_text(_person_yaml("alice", ["control:nist-800-53:ac-2"]))
        (people_dir / "ghost.yaml").write_text(
            _person_yaml("ghost", ["control:nist-800-53:missing"], name="Ghost")
        )

        result = runner.invoke(app, ["person", "list"])
        assert result.exit_code == 0, result.stdout
        assert "alice" in result.stdout
        assert "ghost" in result.stdout
        assert "✓" in result.stdout
        assert "✗" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["person", "list"])
        assert result.exit_code == 1
