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


def _seed_debt_history(project_dir: Path, ages_in_days: list[int]) -> None:
    import json
    from datetime import UTC, datetime, timedelta

    analytics = project_dir / ".lemma" / "analytics"
    analytics.mkdir(parents=True, exist_ok=True)
    lines = []
    for age in ages_in_days:
        ts = (datetime.now(UTC) - timedelta(days=age)).isoformat()
        lines.append(
            json.dumps(
                {
                    "timestamp": ts,
                    "total_controls": 10,
                    "covered": 10 - age,
                    "uncovered": age,
                    "debt_pct": age * 10.0,
                }
            )
        )
    (analytics / "debt-history.jsonl").write_text("\n".join(lines) + "\n")


def test_report_trend_days_filters_snapshot_window(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=False)
    # Two recent snapshots (1 and 2 days old) + one outside a 3-day window (10 days).
    _seed_debt_history(tmp_path, ages_in_days=[10, 2, 1])

    full = runner.invoke(app, ["report"])
    assert full.exit_code == 0, full.stdout
    assert "3 snapshots" in full.stdout

    windowed = runner.invoke(app, ["report", "--trend-days", "3"])
    assert windowed.exit_code == 0, windowed.stdout
    # Only the two in-window snapshots remain in the trend.
    assert "2 snapshots" in windowed.stdout


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


def test_report_includes_ai_decisions_when_traces_exist(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.models.trace import AITrace
    from lemma.services.trace_log import TraceLog

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)
    TraceLog(tmp_path / ".lemma" / "traces").append(
        AITrace(
            operation="map",
            input_text="policy",
            prompt="p",
            model_id="ollama/llama3.2",
            model_version="1",
            raw_output="{}",
            confidence=0.91,
            determination="MAPPED",
            control_id="control:nist-800-53:ac-1",
            framework="nist-800-53",
            status="ACCEPTED",
        )
    )

    result = runner.invoke(app, ["report"])
    assert result.exit_code == 0, result.stdout
    assert "AI Decisions" in result.stdout
    assert "ollama/llama3.2" in result.stdout


def test_report_includes_evidence_timeline_when_log_exists(tmp_path: Path, monkeypatch):
    from datetime import UTC, datetime

    from lemma.cli import app
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    _seed_graph(tmp_path, all_pass=True)
    EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence").append(
        ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200301,
            activity_id=1,
            time=datetime.now(UTC),
            message="m",
            status_id=1,
            metadata={"version": "1.3.0", "product": {"name": "GitHub"}, "uid": "ev-1"},
        )
    )

    result = runner.invoke(app, ["report"])
    assert result.exit_code == 0, result.stdout
    assert "Evidence Timeline" in result.stdout
    assert "GitHub" in result.stdout
