"""Tests for `lemma evidence export` — SIEM-friendly OCSF export (Refs #41)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _seed_evidence(tmp_path: Path, n: int = 2) -> None:
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.evidence_log import EvidenceLog

    (tmp_path / ".lemma").mkdir(exist_ok=True)
    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    for i in range(n):
        log.append(
            ComplianceFinding(
                class_name="Compliance Finding",
                category_uid=2000,
                category_name="Findings",
                type_uid=200301,
                activity_id=1,
                time=datetime.now(UTC),
                message=f"finding {i}",
                status_id=1,
                metadata={"version": "1.3.0", "product": {"name": "GitHub"}, "uid": f"ev-{i}"},
            )
        )


def test_export_ndjson_to_stdout(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_evidence(tmp_path, n=2)

    result = runner.invoke(app, ["evidence", "export"])
    assert result.exit_code == 0, result.stdout
    lines = [ln for ln in result.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        event = json.loads(line)
        assert event["class_uid"] == 2003


def test_export_json_array_to_file(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_evidence(tmp_path, n=3)
    out = tmp_path / "out" / "evidence.json"

    result = runner.invoke(app, ["evidence", "export", "--format", "json", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.is_file()
    payload = json.loads(out.read_text())
    assert isinstance(payload, list)
    assert len(payload) == 3
    assert "Exported" in result.stdout


def test_export_empty_log(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()

    result = runner.invoke(app, ["evidence", "export"])
    assert result.exit_code == 0
    assert result.stdout.strip() == ""


def test_export_unknown_format_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_evidence(tmp_path, n=1)

    result = runner.invoke(app, ["evidence", "export", "--format", "csv"])
    assert result.exit_code == 1
    assert "ndjson" in result.stdout.lower()


def test_export_outside_project_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["evidence", "export"])
    assert result.exit_code == 1
