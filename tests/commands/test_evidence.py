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


def test_rotate_key_command_retires_active_and_prints_new_id(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.crypto import read_lifecycle

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path, count=1)

    result = runner.invoke(app, ["evidence", "rotate-key", "--producer", "Lemma"])
    assert result.exit_code == 0, result.stdout
    assert "ed25519:" in result.stdout  # printed new key_id
    assert "RETIRED" in result.stdout or "rotated" in result.stdout.lower()

    lifecycle = read_lifecycle("Lemma", key_dir=tmp_path / ".lemma" / "keys")
    statuses = [r.status.value for r in lifecycle.keys]
    assert statuses.count("ACTIVE") == 1
    assert statuses.count("RETIRED") == 1


def test_rotate_key_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["evidence", "rotate-key", "--producer", "Lemma"])
    assert result.exit_code == 1


def test_revoke_key_requires_reason(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path, count=1)

    # Grab the active key_id.
    from lemma.services.crypto import read_lifecycle

    active_key_id = read_lifecycle("Lemma", key_dir=tmp_path / ".lemma" / "keys").active().key_id

    # Missing --reason should fail with a non-zero exit.
    result = runner.invoke(
        app, ["evidence", "revoke-key", "--producer", "Lemma", "--key-id", active_key_id]
    )
    assert result.exit_code != 0


def test_revoke_key_marks_record_and_prints_confirmation(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.crypto import read_lifecycle

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path, count=1)

    active_key_id = read_lifecycle("Lemma", key_dir=tmp_path / ".lemma" / "keys").active().key_id

    result = runner.invoke(
        app,
        [
            "evidence",
            "revoke-key",
            "--producer",
            "Lemma",
            "--key-id",
            active_key_id,
            "--reason",
            "test compromise",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "REVOKED" in result.stdout

    lifecycle = read_lifecycle("Lemma", key_dir=tmp_path / ".lemma" / "keys")
    assert lifecycle.find(active_key_id).status.value == "REVOKED"


def test_keys_command_lists_all_keys_with_lifecycle(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.crypto import rotate_key

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path, count=1)
    rotate_key(producer="Lemma", key_dir=tmp_path / ".lemma" / "keys")

    result = runner.invoke(app, ["evidence", "keys"])
    assert result.exit_code == 0, result.stdout
    # Both the retired and active key should surface.
    assert "ACTIVE" in result.stdout
    assert "RETIRED" in result.stdout
    assert "Lemma" in result.stdout
