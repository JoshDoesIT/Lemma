"""Tests for the `lemma check` CLI command."""

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
        policy="access-control.md",
        framework="nist-800-53",
        control_id="ac-1",
        confidence=0.9,
    )
    if all_pass:
        g.add_mapping(
            policy="access-control.md",
            framework="nist-800-53",
            control_id="ac-2",
            confidence=0.8,
        )
    g.save(project_dir / ".lemma" / "graph.json")


def test_check_text_all_pass_exits_zero(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["check"])

    assert result.exit_code == 0, result.stdout
    assert "2" in result.stdout  # total = 2
    assert "satisfying policy" in result.stdout.lower() or "all controls" in result.stdout.lower()


def test_check_text_with_failures_exits_one(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["check"])

    assert result.exit_code == 1
    assert "ac-2" in result.stdout
    assert "FAILED" in result.stdout


def test_check_format_json_emits_parseable_result(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["check", "--format", "json"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert payload["total"] == 2
    assert payload["passed"] == 1
    assert payload["failed"] == 1
    assert any(o["short_id"] == "ac-2" and o["status"] == "FAILED" for o in payload["outcomes"])
    assert any(o["short_id"] == "ac-1" and o["status"] == "PASSED" for o in payload["outcomes"])


def test_check_framework_filter_limits_scope(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="AC-1", family="AC")
    g.add_framework("nist-csf-2.0")
    g.add_control(framework="nist-csf-2.0", control_id="pr.aa-1", title="PR.AA-1", family="PR.AA")
    g.save(tmp_path / ".lemma" / "graph.json")

    result = runner.invoke(app, ["check", "--framework", "nist-800-53", "--format", "json"])

    assert result.exit_code == 1  # ac-1 has no policy
    payload = json.loads(result.stdout.strip())
    assert payload["total"] == 1
    assert payload["outcomes"][0]["framework"] == "nist-800-53"


def test_check_unknown_framework_exits_with_clear_error(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["check", "--framework", "iso-27001"])

    assert result.exit_code == 1
    assert "iso-27001" in result.stdout.lower() or "unknown" in result.stdout.lower()
    assert "nist-800-53" in result.stdout  # candidate list


def test_check_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 1
