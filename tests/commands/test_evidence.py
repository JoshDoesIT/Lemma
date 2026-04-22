"""Tests for the `lemma evidence` CLI commands."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _compliance_payload(uid: str = "evt-1") -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Lemma"},
            "uid": uid,
        },
    }


def _seed_signed_entries(project_dir: Path, count: int = 2) -> list[str]:
    """Append ``count`` signed entries and return their entry_hashes."""
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    for i in range(count):
        log.append(normalize(_compliance_payload(f"seed-{i}")))
    return [env.entry_hash for env in log.read_envelopes()]


def test_verify_reports_proven_for_untampered_entry(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    hashes = _seed_signed_entries(tmp_path)

    result = runner.invoke(app, ["evidence", "verify", hashes[0]])

    assert result.exit_code == 0, result.stdout
    assert "PROVEN" in result.stdout


def test_verify_reports_violated_when_entry_missing(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    result = runner.invoke(app, ["evidence", "verify", "f" * 64])
    assert result.exit_code == 1
    assert "VIOLATED" in result.stdout or "not found" in result.stdout.lower()


def test_verify_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["evidence", "verify", "a" * 64])
    assert result.exit_code == 1
    stdout = result.stdout.lower()
    assert "not a lemma project" in stdout or "lemma init" in stdout


def test_log_displays_timeline_with_integrity_states(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path, count=3)

    result = runner.invoke(app, ["evidence", "log"])
    assert result.exit_code == 0, result.stdout
    # Table or table-like output mentioning the integrity verdict per row
    assert "PROVEN" in result.stdout
    # Shows producer
    assert "Lemma" in result.stdout


def test_log_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["evidence", "log"])
    assert result.exit_code == 1
