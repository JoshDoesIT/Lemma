"""End-to-end AI trace integration tests.

Asserts that the trace log, the confidence gate, and the policy event
log all work together from the CLI boundary on a real project.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch


def _write_policy(project: Path) -> None:
    (project / "policies" / "access.md").write_text(
        "# Access Control\n\nAll users must use SSO with MFA to reach production systems.\n"
    )


def _write_config_with_threshold(project: Path, threshold: float) -> None:
    (project / "lemma.config.yaml").write_text(
        "ai:\n"
        "  provider: ollama\n"
        "  model: llama3.2\n"
        "  temperature: 0.1\n"
        "  automation:\n"
        "    thresholds:\n"
        f"      map: {threshold}\n"
        "frameworks: []\n"
        "connectors: []\n"
    )


def test_mapping_emits_one_trace_per_decision(lemma_project: Path, monkeypatch):
    from typer.testing import CliRunner

    from lemma.cli import app
    from lemma.services.trace_log import TraceLog

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)
    _write_policy(lemma_project)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {"confidence": 0.77, "rationale": "maps to account management"}
    )

    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])

    traces = TraceLog(lemma_project / ".lemma" / "traces").read_all()
    assert traces, "expected trace entries after map"
    # Every trace should carry full context, not empty fields.
    for t in traces:
        assert t.operation == "map"
        assert t.model_id
        assert t.prompt
        assert t.raw_output
        assert t.control_id


def test_auto_accept_writes_accepted_trace_when_above_threshold(lemma_project: Path, monkeypatch):
    from typer.testing import CliRunner

    from lemma.cli import app
    from lemma.services.trace_log import TraceLog

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)
    _write_policy(lemma_project)
    _write_config_with_threshold(lemma_project, 0.85)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps({"confidence": 0.92, "rationale": "strong match"})

    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])

    traces = TraceLog(lemma_project / ".lemma" / "traces").read_all()
    accepted = [t for t in traces if t.status.value == "ACCEPTED"]
    assert accepted, "expected at least one auto-accepted trace at confidence 0.92 >= 0.85"
    for t in accepted:
        assert t.auto_accepted is True
        assert "0.850" in t.review_rationale  # threshold is recorded in rationale
        assert t.parent_trace_id  # links back to the PROPOSED entry


def test_threshold_change_between_runs_records_policy_event(lemma_project: Path, monkeypatch):
    from typer.testing import CliRunner

    from lemma.cli import app
    from lemma.services.policy_log import PolicyEventLog

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)
    _write_policy(lemma_project)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps({"confidence": 0.7, "rationale": "moderate"})

    # First run at 0.80 threshold
    _write_config_with_threshold(lemma_project, 0.80)
    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])

    # Second run at 0.95 threshold — a real governance change
    _write_config_with_threshold(lemma_project, 0.95)
    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])

    events = PolicyEventLog(lemma_project / ".lemma" / "policy-events").read_all()
    event_types = [e.event_type.value for e in events]
    assert "threshold_set" in event_types, "first run should record threshold_set"
    assert "threshold_changed" in event_types, "second run should record threshold_changed"

    changed = next(e for e in events if e.event_type.value == "threshold_changed")
    assert changed.operation == "map"
    assert changed.previous_value == 0.80
    assert changed.new_value == 0.95
