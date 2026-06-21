"""Tests for the `lemma debt` CLI command (Refs #40)."""

from __future__ import annotations

import json
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


def test_debt_text_with_uncovered(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["debt"])
    assert result.exit_code == 0, result.stdout
    assert "Compliance Debt" in result.stdout
    assert "nist-800-53" in result.stdout
    assert "50" in result.stdout  # 1 of 2 uncovered = 50%


def test_debt_zero_when_all_covered(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["debt"])
    assert result.exit_code == 0, result.stdout
    assert "Zero compliance debt" in result.stdout


def test_debt_json(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["debt", "--format", "json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["total_controls"] == 2
    assert payload["uncovered"] == 1
    assert payload["debt_pct"] == 50.0
    assert payload["frameworks"][0]["framework"] == "nist-800-53"


def test_debt_unknown_framework_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["debt", "--framework", "ghost"])
    assert result.exit_code == 1
    assert "ghost" in result.stdout.lower()


def test_debt_outside_project_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["debt"])
    assert result.exit_code == 1
    assert "lemma init" in result.stdout.lower()


def test_debt_snapshot_records_and_history_shows_trend(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)  # 50% debt

    snap = runner.invoke(app, ["debt", "--snapshot"])
    assert snap.exit_code == 0, snap.stdout
    assert "Recorded" in snap.stdout
    assert (tmp_path / ".lemma" / "analytics" / "debt-history.jsonl").is_file()

    hist = runner.invoke(app, ["debt", "--history"])
    assert hist.exit_code == 0, hist.stdout
    assert "debt over time" in hist.stdout.lower()
    assert "50" in hist.stdout


def test_debt_history_empty_message(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["debt", "--history"])
    assert result.exit_code == 0
    assert "no debt snapshots" in result.stdout.lower()
