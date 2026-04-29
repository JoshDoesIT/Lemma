"""Tests for `lemma agent` CLI scaffold (Refs #25 Slice C).

The agent surface in v1 is mostly placeholders — the binary,
federation protocol, and control plane are tracked separately under
#25. The exception is `lemma agent sync --offline`, which is fully
wired today: it's a thin wrapper over `lemma evidence bundle` so
operators can script against the long-lived `lemma agent sync` shape
even before the agent binary lands.
"""

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


def _seed_signed_entries(project_dir: Path) -> list[str]:
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("agent-1")))
    return [env.entry_hash for env in log.read_envelopes()]


def test_agent_help_lists_three_subcommands(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code == 0, result.stdout
    assert "install" in result.stdout
    assert "status" in result.stdout
    assert "sync" in result.stdout


def test_agent_install_exits_one_with_tracking_pointer(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(app, ["agent", "install"])
    assert result.exit_code == 1
    assert "not yet implemented" in result.stdout.lower()
    assert "#25" in result.stdout
    # Now that the Go scaffold lives at agent/, point operators at it.
    assert "agent/README.md" in result.stdout


def test_agent_status_exits_one_with_tracking_pointer(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(app, ["agent", "status"])
    assert result.exit_code == 1
    assert "not yet implemented" in result.stdout.lower()
    assert "#25" in result.stdout
    assert "agent/README.md" in result.stdout


def test_agent_sync_without_offline_exits_one_pointing_at_offline(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(app, ["agent", "sync"])
    assert result.exit_code == 1
    assert "--offline" in result.stdout
    # Online sync requires the binary + control plane, both tracked on #25.
    assert "#25" in result.stdout
    assert "agent/README.md" in result.stdout


def test_agent_sync_offline_without_output_exits_one(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)
    result = runner.invoke(app, ["agent", "sync", "--offline"])
    assert result.exit_code == 1
    assert "--output" in result.stdout


def test_agent_sync_offline_writes_audit_bundle(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    out = tmp_path / "bundle"
    result = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert (out / "manifest.json").is_file()
    assert (out / "manifest.sig").is_file()
    assert (out / "evidence").is_dir()


def test_agent_sync_offline_no_ai_skips_ai_dir(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    out = tmp_path / "bundle"
    result = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out), "--no-ai"])
    assert result.exit_code == 0, result.stdout
    assert not (out / "ai").exists()


def test_agent_sync_offline_force_overwrites_non_empty_dir(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    out = tmp_path / "bundle"
    out.mkdir()
    (out / "stray.txt").write_text("existing")

    first = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out)])
    assert first.exit_code == 1
    assert "force" in first.stdout.lower()

    second = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out), "--force"])
    assert second.exit_code == 0, second.stdout
    assert not (out / "stray.txt").exists()
