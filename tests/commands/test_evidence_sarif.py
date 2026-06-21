"""Tests for `lemma evidence import-sarif` (Refs #41)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.cli import app

_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [
                {
                    "ruleId": "py/sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/db.py"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                },
                {"ruleId": "py/weak-hash", "level": "warning", "message": {"text": "MD5"}},
            ],
        }
    ],
}


def _init_project(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()


def _write_sarif(tmp_path: Path, doc=_SARIF) -> Path:
    report = tmp_path / "scan.sarif"
    report.write_text(json.dumps(doc))
    return report


def test_import_sarif_appends_signed_findings(tmp_path, monkeypatch):
    from lemma.services.evidence_log import EvidenceLog

    _init_project(tmp_path, monkeypatch)
    report = _write_sarif(tmp_path)

    result = CliRunner().invoke(app, ["evidence", "import-sarif", str(report)])
    assert result.exit_code == 0, result.stdout
    assert "2 ingested" in result.stdout

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    envelopes = log.read_envelopes()
    assert len(envelopes) == 2
    assert all(env.signer_key_id.startswith("ed25519:") for env in envelopes)
    # Provenance records the SARIF source + the sarif→ocsf transform.
    stages = {rec.stage for env in envelopes for rec in env.provenance}
    assert {"source", "transform"} <= stages


def test_import_sarif_dedupes_on_reimport(tmp_path, monkeypatch):
    _init_project(tmp_path, monkeypatch)
    report = _write_sarif(tmp_path)

    runner = CliRunner()
    first = runner.invoke(app, ["evidence", "import-sarif", str(report)])
    assert "2 ingested" in first.stdout
    second = runner.invoke(app, ["evidence", "import-sarif", str(report)])
    # Same report, same UTC day → all duplicates, nothing new written.
    assert "0 ingested, 2 skipped" in second.stdout


def test_import_sarif_dry_run_writes_nothing(tmp_path, monkeypatch):
    from lemma.services.evidence_log import EvidenceLog

    _init_project(tmp_path, monkeypatch)
    report = _write_sarif(tmp_path)

    result = CliRunner().invoke(app, ["evidence", "import-sarif", str(report), "--dry-run"])
    assert result.exit_code == 0
    assert "dry run" in result.stdout.lower()
    assert EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence").read_envelopes() == []


def test_import_sarif_empty_report_is_a_clean_noop(tmp_path, monkeypatch):
    _init_project(tmp_path, monkeypatch)
    report = _write_sarif(tmp_path, {"version": "2.1.0", "runs": []})

    result = CliRunner().invoke(app, ["evidence", "import-sarif", str(report)])
    assert result.exit_code == 0
    assert "0 findings" in result.stdout


def test_import_sarif_invalid_json_exits_one(tmp_path, monkeypatch):
    _init_project(tmp_path, monkeypatch)
    bad = tmp_path / "bad.sarif"
    bad.write_text("{not json")

    result = CliRunner().invoke(app, ["evidence", "import-sarif", str(bad)])
    assert result.exit_code == 1
    assert "invalid json" in result.stdout.lower()


def test_import_sarif_missing_file_exits_one(tmp_path, monkeypatch):
    _init_project(tmp_path, monkeypatch)
    result = CliRunner().invoke(app, ["evidence", "import-sarif", str(tmp_path / "nope.sarif")])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_import_sarif_outside_project_exits_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no .lemma/
    report = _write_sarif(tmp_path)
    result = CliRunner().invoke(app, ["evidence", "import-sarif", str(report)])
    assert result.exit_code == 1
