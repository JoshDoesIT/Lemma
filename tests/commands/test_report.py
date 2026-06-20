"""Tests for the `lemma report` CLI command (Refs #32)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from lemma.services.knowledge_graph import ComplianceGraph

runner = CliRunner()


def _seed_graph(project_dir: Path, *, all_pass: bool) -> None:
    (project_dir / ".lemma").mkdir(exist_ok=True)
    g = ComplianceGraph()
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="Access Control", family="AC")
    g.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    g.add_policy("access-control.md", title="Access Control Policy")
    g.add_mapping(
        policy="access-control.md", framework="nist-800-53", control_id="ac-1", confidence=0.9
    )
    if all_pass:
        g.add_mapping(
            policy="access-control.md", framework="nist-800-53", control_id="ac-2", confidence=0.8
        )
    g.save(project_dir / ".lemma" / "graph.json")


def test_report_to_stdout(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["report"])
    assert result.exit_code == 0, result.stdout
    assert "<!DOCTYPE html>" in result.stdout
    assert "nist-800-53" in result.stdout
    assert "Account Management" in result.stdout  # the failed control


def test_report_to_file(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)
    out = tmp_path / "out" / "posture.html"

    result = runner.invoke(app, ["report", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.is_file()
    html = out.read_text()
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "#00FF41" in html  # brand accent
    assert "Wrote" in result.stdout


def test_report_unknown_framework_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["report", "--framework", "ghost"])
    assert result.exit_code == 1
    assert "ghost" in result.stdout.lower()


def test_report_outside_project_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 1
    assert "lemma init" in result.stdout.lower()
