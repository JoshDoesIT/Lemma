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


def test_collect_runs_github_connector_and_appends_signed_evidence(tmp_path: Path, monkeypatch):
    """`lemma evidence collect github --repo owner/name` drives the connector end-to-end."""
    import httpx

    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/branches/main/protection" in url:
            return httpx.Response(200, json={})
        if "/contents/CODEOWNERS" in url:
            return httpx.Response(404, json={"message": "Not Found"})
        if "/dependabot/alerts" in url:
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    mock_client = httpx.Client(
        base_url="https://api.github.com", transport=httpx.MockTransport(_handler)
    )

    # Patch the connector's default client construction so the CLI picks up the mock.
    from lemma.sdk.connectors import github as gh_module

    original_init = gh_module.GitHubConnector.__init__

    def _patched_init(self, *, repo, client=None, token=None):
        original_init(self, repo=repo, client=client or mock_client, token=token)

    monkeypatch.setattr(gh_module.GitHubConnector, "__init__", _patched_init)

    result = runner.invoke(app, ["evidence", "collect", "github", "--repo", "JoshDoesIT/Lemma"])
    assert result.exit_code == 0, result.stdout
    assert "ingested" in result.stdout.lower()

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) >= 2  # branch protection + codeowners at minimum


def test_collect_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["evidence", "collect", "github", "--repo", "owner/name"])
    assert result.exit_code == 1


def test_collect_rejects_unknown_connector_name(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()

    result = runner.invoke(app, ["evidence", "collect", "not-a-real-connector", "--repo", "x/y"])
    assert result.exit_code == 1
    assert (
        "unknown" in result.stdout.lower()
        or "not a recognized" in result.stdout.lower()
        or "not recognized" in result.stdout.lower()
    )


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


# --- `lemma evidence ingest` ---


import json  # noqa: E402


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload))
    return path


def _write_jsonl(path: Path, payloads: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(p) for p in payloads) + "\n")
    return path


def test_ingest_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    file = _write_json(tmp_path / "evt.json", _compliance_payload("i-0"))

    result = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert result.exit_code == 1
    stdout = result.stdout.lower()
    assert "not a lemma project" in stdout or "lemma init" in stdout


def test_ingest_rejects_unknown_extension_and_names_file(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    bad = tmp_path / "evt.txt"
    bad.write_text(json.dumps(_compliance_payload("i-0")))

    result = runner.invoke(app, ["evidence", "ingest", str(bad)])
    assert result.exit_code != 0
    assert "evt.txt" in result.stdout
    # Accepted extensions should be named in the error.
    assert ".json" in result.stdout and ".jsonl" in result.stdout


def test_ingest_malformed_json_names_file(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    bad = _write_json(tmp_path / "bad.json", {"class_uid": 9999, "time": "bogus"})

    result = runner.invoke(app, ["evidence", "ingest", str(bad)])
    assert result.exit_code != 0
    assert "bad.json" in result.stdout


def test_ingest_malformed_jsonl_names_line(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    payloads_file = tmp_path / "mixed.jsonl"
    good = _compliance_payload("i-good-1")
    good2 = _compliance_payload("i-good-2")
    bad = {"class_uid": 9999, "time": "bogus"}
    payloads_file.write_text(
        json.dumps(good) + "\n" + json.dumps(good2) + "\n" + json.dumps(bad) + "\n"
    )

    result = runner.invoke(app, ["evidence", "ingest", str(payloads_file)])
    assert result.exit_code != 0
    assert "mixed.jsonl" in result.stdout
    # Line 3 is where the bad record lives.
    assert ":3" in result.stdout or "line 3" in result.stdout.lower()
    # Atomicity: nothing should have been written.
    from lemma.services.evidence_log import EvidenceLog

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert log.read_envelopes() == []


def test_ingest_single_json_appends_one_envelope(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    file = _write_json(tmp_path / "evt.json", _compliance_payload("single-1"))

    result = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert result.exit_code == 0, result.stdout
    assert "1 ingested" in result.stdout
    assert "0 skipped" in result.stdout

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) == 1


def test_ingest_jsonl_appends_every_record(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    file = _write_jsonl(
        tmp_path / "batch.jsonl",
        [_compliance_payload(f"batch-{i}") for i in range(3)],
    )

    result = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert result.exit_code == 0, result.stdout
    assert "3 ingested" in result.stdout
    assert "0 skipped" in result.stdout

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) == 3


def test_ingest_second_run_reports_dedupe(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    file = _write_jsonl(
        tmp_path / "batch.jsonl",
        [_compliance_payload(f"rep-{i}") for i in range(3)],
    )

    first = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert first.exit_code == 0

    second = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert second.exit_code == 0, second.stdout
    assert "0 ingested" in second.stdout
    assert "3 skipped" in second.stdout

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) == 3  # unchanged


def test_ingest_dry_run_writes_nothing(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    file = _write_jsonl(
        tmp_path / "preview.jsonl",
        [_compliance_payload(f"dr-{i}") for i in range(2)],
    )

    result = runner.invoke(app, ["evidence", "ingest", str(file), "--dry-run"])
    assert result.exit_code == 0, result.stdout
    assert "dry run" in result.stdout.lower()
    assert "2 valid" in result.stdout

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert log.read_envelopes() == []


def test_ingest_stdin_reads_jsonl(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    stdin_text = (
        json.dumps(_compliance_payload("stdin-0"))
        + "\n"
        + json.dumps(_compliance_payload("stdin-1"))
        + "\n"
    )

    result = runner.invoke(app, ["evidence", "ingest", "-"], input=stdin_text)
    assert result.exit_code == 0, result.stdout
    assert "2 ingested" in result.stdout

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) == 2
