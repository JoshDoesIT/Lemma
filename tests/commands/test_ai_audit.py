"""Tests for `lemma ai audit` CLI commands.

Follows TDD: tests written BEFORE the implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.models.trace import AITrace
from lemma.services.trace_log import TraceLog

runner = CliRunner()


def _seed_traces(project_dir: Path) -> list[AITrace]:
    """Helper to populate trace log with test data.

    Returns:
        List of the created AITrace records for assertion.
    """
    trace_log = TraceLog(log_dir=project_dir / ".lemma" / "traces")

    traces = [
        AITrace(
            operation="map",
            input_text="All users must use MFA.",
            prompt="Map this policy...",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output='{"confidence": 0.9}',
            confidence=0.9,
            determination="MAPPED",
            control_id="ac-7",
            framework="nist-800-53",
        ),
        AITrace(
            operation="map",
            input_text="Data must be encrypted at rest.",
            prompt="Map this policy...",
            model_id="openai/gpt-4o-mini",
            model_version="2024-07-18",
            raw_output='{"confidence": 0.85}',
            confidence=0.85,
            determination="MAPPED",
            control_id="sc-28",
            framework="nist-800-53",
        ),
        AITrace(
            operation="map",
            input_text="We do security.",
            prompt="Map this policy...",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output='{"confidence": 0.3}',
            confidence=0.3,
            determination="LOW_CONFIDENCE",
            control_id="sa-11",
            framework="nist-800-53",
        ),
    ]

    for trace in traces:
        trace_log.append(trace)

    return traces


class TestAuditCommand:
    """Tests for the `lemma ai audit` CLI command."""

    def test_audit_shows_all_traces(self, tmp_path: Path, monkeypatch):
        """lemma ai audit lists all trace entries in a table."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        _seed_traces(tmp_path)

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "audit", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        control_ids = [d["control_id"] for d in data]
        assert "ac-7" in control_ids
        assert "sc-28" in control_ids
        assert "sa-11" in control_ids

    def test_audit_filter_by_model(self, tmp_path: Path, monkeypatch):
        """lemma ai audit --model filters to specific model traces."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        _seed_traces(tmp_path)

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app, ["ai", "audit", "--model", "openai/gpt-4o-mini", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert data[0]["control_id"] == "sc-28"
        # Should NOT contain ollama traces
        model_ids = [d["model_id"] for d in data]
        assert "ollama/llama3.2" not in model_ids

    def test_audit_filter_by_status(self, tmp_path: Path, monkeypatch):
        """lemma ai audit --status filters by review status."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        traces = _seed_traces(tmp_path)

        # Accept the first trace
        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        trace_log.review(
            traces[0].trace_id,
            status="ACCEPTED",
            rationale="Verified manually.",
        )

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "audit", "--status", "ACCEPTED", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) >= 1
        assert all(d["status"] == "ACCEPTED" for d in data)

    def test_audit_json_format(self, tmp_path: Path, monkeypatch):
        """lemma ai audit --format json outputs machine-readable JSON."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        _seed_traces(tmp_path)

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "audit", "--format", "json"])
        assert result.exit_code == 0

        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]["control_id"] == "ac-7"

    def test_audit_empty_log(self, tmp_path: Path, monkeypatch):
        """lemma ai audit with no traces shows empty message."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "audit"])
        assert result.exit_code == 0
        assert "No trace" in result.stdout or "0 traces" in result.stdout

    def test_audit_summary_flag(self, tmp_path: Path, monkeypatch):
        """lemma ai audit --summary shows aggregate statistics."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        _seed_traces(tmp_path)

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "audit", "--summary"])
        assert result.exit_code == 0
        # Should contain counts
        assert "3" in result.stdout  # total traces
        assert "ollama/llama3.2" in result.stdout
        assert "openai/gpt-4o-mini" in result.stdout
