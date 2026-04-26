"""Tests for the `lemma risk` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _risk_yaml(
    id_: str,
    severity: str,
    threatens: list[str],
    mitigated_by: list[str],
    title: str = "Loss of audit logs",
) -> str:
    lines = [
        f"id: {id_}",
        f"title: {title}",
        f"severity: {severity}",
    ]
    if threatens:
        lines.append("threatens:")
        for ref in threatens:
            lines.append(f"  - {ref}")
    else:
        lines.append("threatens: []")
    if mitigated_by:
        lines.append("mitigated_by:")
        for ref in mitigated_by:
            lines.append(f"  - {ref}")
    else:
        lines.append("mitigated_by: []")
    return "\n".join(lines) + "\n"


def _seed_graph(tmp_path: Path) -> None:
    """Seed .lemma/graph.json with a framework, control, scope, and resource."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="au-2", title="AU-2", family="AU")
    g.add_scope(name="prod", frameworks=["nist-800-53"], justification="", rule_count=0)
    g.add_resource(
        resource_id="audit-bucket",
        type_="aws.s3.bucket",
        scopes=["prod"],
        attributes={},
    )
    g.save(tmp_path / ".lemma" / "graph.json")


class TestRiskLoad:
    def test_happy_path_adds_risk_and_edges(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph(tmp_path)
        risks_dir = tmp_path / "risks"
        risks_dir.mkdir()
        (risks_dir / "audit-loss.yaml").write_text(
            _risk_yaml(
                "audit-log-loss",
                "high",
                threatens=["resource:audit-bucket"],
                mitigated_by=["control:nist-800-53:au-2"],
            )
        )

        result = runner.invoke(app, ["risk", "load"])
        assert result.exit_code == 0, result.stdout
        assert "audit-log-loss" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("risk:audit-log-loss") is not None
        assert g.get_edges("risk:audit-log-loss", "resource:audit-bucket")
        assert g.get_edges("risk:audit-log-loss", "control:nist-800-53:au-2")

    def test_unresolved_target_aborts_and_graph_stays_clean(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph(tmp_path)
        risks_dir = tmp_path / "risks"
        risks_dir.mkdir()
        (risks_dir / "bad.yaml").write_text(
            _risk_yaml(
                "orphan",
                "medium",
                threatens=["resource:does-not-exist"],
                mitigated_by=[],
            )
        )

        result = runner.invoke(app, ["risk", "load"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("risk:orphan") is None

    def test_empty_directory_is_not_an_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph(tmp_path)

        result = runner.invoke(app, ["risk", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no risks" in result.stdout.lower() or "risks/" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["risk", "load"])
        assert result.exit_code == 1


class TestRiskList:
    def test_shows_severity_per_row(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph(tmp_path)
        risks_dir = tmp_path / "risks"
        risks_dir.mkdir()
        (risks_dir / "low.yaml").write_text(
            _risk_yaml("low-risk", "low", threatens=["resource:audit-bucket"], mitigated_by=[])
        )
        (risks_dir / "crit.yaml").write_text(
            _risk_yaml("crit-risk", "critical", threatens=[], mitigated_by=[])
        )

        result = runner.invoke(app, ["risk", "list"])
        assert result.exit_code == 0, result.stdout
        assert "low-risk" in result.stdout
        assert "crit-risk" in result.stdout
        # Severity values surface in the table.
        assert "low" in result.stdout.lower()
        assert "critical" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["risk", "list"])
        assert result.exit_code == 1
