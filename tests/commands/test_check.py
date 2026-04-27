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


def test_check_format_sarif_emits_valid_sarif(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["check", "--format", "sarif"])

    assert result.exit_code == 1  # ac-2 fails
    payload = json.loads(result.stdout.strip())
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].startswith("https://json.schemastore.org/sarif")
    assert len(payload["runs"]) == 1

    results = payload["runs"][0]["results"]
    # Only FAILED controls land in SARIF output.
    rule_ids = [r["ruleId"] for r in results]
    assert "control:nist-800-53:ac-2" in rule_ids
    assert "control:nist-800-53:ac-1" not in rule_ids
    failed = next(r for r in results if r["ruleId"] == "control:nist-800-53:ac-2")
    assert failed["level"] == "error"
    assert "Account Management" in failed["message"]["text"]


def test_check_format_sarif_skips_passed_controls(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["check", "--format", "sarif"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout.strip())
    assert payload["runs"][0]["results"] == []


def test_check_format_sarif_carries_audit_properties(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["check", "--format", "sarif", "--min-confidence", "0.5"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    failed = next(
        r for r in payload["runs"][0]["results"] if r["ruleId"] == "control:nist-800-53:ac-2"
    )
    props = failed["properties"]
    assert props["framework"] == "nist-800-53"
    assert props["short_id"] == "ac-2"
    assert props["min_confidence_applied"] == 0.5


def test_check_min_confidence_filters_low_confidence_edges(tmp_path: Path, monkeypatch):
    """A control whose only SATISFIES edge is below threshold flips PASSED → FAILED."""
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="AC-1", family="AC")
    g.add_policy("low.md", title="Low confidence policy")
    g.add_mapping(policy="low.md", framework="nist-800-53", control_id="ac-1", confidence=0.5)
    g.save(tmp_path / ".lemma" / "graph.json")

    no_filter = runner.invoke(app, ["check", "--format", "json"])
    assert no_filter.exit_code == 0  # 0.5 ≥ 0.0 default → PASSED
    payload = json.loads(no_filter.stdout.strip())
    assert payload["passed"] == 1

    strict = runner.invoke(app, ["check", "--format", "json", "--min-confidence", "0.9"])
    assert strict.exit_code == 1  # 0.5 < 0.9 → FAILED
    payload = json.loads(strict.stdout.strip())
    assert payload["failed"] == 1
    assert payload["min_confidence_applied"] == 0.9


def test_check_min_confidence_default_zero_in_json_output(tmp_path: Path, monkeypatch):
    """With no flag, --min-confidence defaults to 0.0 (preserves v0 behavior)."""
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)

    result = runner.invoke(app, ["check", "--format", "json"])

    payload = json.loads(result.stdout.strip())
    assert payload["min_confidence_applied"] == 0.0


def test_check_unknown_format_errors_loud(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)

    result = runner.invoke(app, ["check", "--format", "toml"])

    assert result.exit_code == 1
    assert "toml" in result.stdout.lower()
    assert "text" in result.stdout.lower()
    assert "json" in result.stdout.lower()
    assert "sarif" in result.stdout.lower()
