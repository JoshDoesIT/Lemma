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


def test_collect_runs_okta_connector_and_appends_signed_evidence(tmp_path: Path, monkeypatch):
    """`lemma evidence collect okta --domain <x>.okta.com` drives the connector end-to-end."""
    import httpx

    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_OKTA_TOKEN", "test-token")

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v1/policies" in url:
            return httpx.Response(200, json=[{"id": "p1", "name": "MFA", "status": "ACTIVE"}])
        if "/api/v1/apps" in url:
            return httpx.Response(200, json=[{"id": "a1", "status": "ACTIVE"}])
        return httpx.Response(404)

    mock_client = httpx.Client(
        base_url="https://example.okta.com", transport=httpx.MockTransport(_handler)
    )

    # Patch the connector's default client so the CLI picks up the mock.
    from lemma.sdk.connectors import okta as okta_module

    original_init = okta_module.OktaConnector.__init__

    def _patched_init(self, *, domain, client=None, token=None):
        original_init(self, domain=domain, client=client or mock_client, token=token)

    monkeypatch.setattr(okta_module.OktaConnector, "__init__", _patched_init)

    result = runner.invoke(app, ["evidence", "collect", "okta", "--domain", "example.okta.com"])
    assert result.exit_code == 0, result.stdout
    assert "ingested" in result.stdout.lower()

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) == 2  # MFA policy + SSO apps


def test_collect_okta_without_domain_exits_nonzero(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_OKTA_TOKEN", "test-token")

    result = runner.invoke(app, ["evidence", "collect", "okta"])
    assert result.exit_code == 1
    assert "domain" in result.stdout.lower()


def test_collect_runs_aws_connector_and_appends_signed_evidence(tmp_path: Path, monkeypatch):
    """`lemma evidence collect aws --region <r>` drives the connector end-to-end."""
    from unittest.mock import MagicMock

    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()

    session = MagicMock()
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    iam.get_account_password_policy.return_value = {"PasswordPolicy": {"MinimumPasswordLength": 14}}
    trail = MagicMock()
    trail.describe_trails.return_value = {"trailList": [{"Name": "t1", "IsMultiRegionTrail": True}]}
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    session.client.side_effect = lambda svc, **_: {
        "iam": iam,
        "cloudtrail": trail,
        "sts": sts,
    }[svc]

    from lemma.sdk.connectors import aws as aws_module

    original_init = aws_module.AWSConnector.__init__

    def _patched_init(self, *, region="us-east-1", session=None):
        original_init(self, region=region, session=session or session_fixture)

    session_fixture = session
    monkeypatch.setattr(aws_module.AWSConnector, "__init__", _patched_init)

    result = runner.invoke(app, ["evidence", "collect", "aws", "--region", "us-east-1"])
    assert result.exit_code == 0, result.stdout
    assert "ingested" in result.stdout.lower()

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert len(log.read_envelopes()) == 3  # root MFA + password policy + CloudTrail


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


# --- Provenance chain (issue #99) ---


def test_ingest_lands_source_and_normalization_provenance(tmp_path: Path, monkeypatch):
    """An ingested envelope ends up with source, normalization, and storage."""
    import hashlib

    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    payload = _compliance_payload("prov-ingest-1")
    file = _write_jsonl(tmp_path / "batch.jsonl", [payload])
    raw_bytes = file.read_bytes()

    result = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert result.exit_code == 0, result.stdout

    env = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence").read_envelopes()[0]
    stages = [r.stage for r in env.provenance]
    assert stages == ["source", "normalization", "storage"]

    source = env.provenance[0]
    assert "batch.jsonl" in source.actor
    assert source.content_hash == hashlib.sha256(raw_bytes).hexdigest()

    norm = env.provenance[1]
    assert norm.actor == "lemma.ocsf_normalizer/1"


def test_verify_prints_full_provenance_chain(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    file = _write_jsonl(tmp_path / "batch.jsonl", [_compliance_payload("verify-prov")])

    ingest_result = runner.invoke(app, ["evidence", "ingest", str(file)])
    assert ingest_result.exit_code == 0

    entry_hash = (
        EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence").read_envelopes()[0].entry_hash
    )

    result = runner.invoke(app, ["evidence", "verify", entry_hash])
    assert result.exit_code == 0, result.stdout
    assert "source" in result.stdout
    assert "normalization" in result.stdout
    assert "storage" in result.stdout


# --- Evidence nodes in the compliance graph (Refs #76, #88) ---


def _compliance_payload_with_refs(uid: str, control_refs: list[str]) -> dict:
    p = _compliance_payload(uid)
    p["metadata"]["control_refs"] = control_refs
    return p


def _seed_graph_with_controls(project_dir: Path) -> None:
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-csf-2.0")
    g.add_control(
        framework="nist-csf-2.0",
        control_id="gv.oc-1",
        title="Org Context 1",
        family="GV.OC",
    )
    g.add_control(
        framework="nist-csf-2.0",
        control_id="pr.aa-1",
        title="Identities and credentials",
        family="PR.AA",
    )
    g.save(project_dir / ".lemma" / "graph.json")


class TestEvidenceLoad:
    def test_happy_path_creates_nodes_and_edges(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload_with_refs("e-1", ["nist-csf-2.0:gv.oc-1"])))
        log.append(normalize(_compliance_payload_with_refs("e-2", ["nist-csf-2.0:pr.aa-1"])))

        result = runner.invoke(app, ["evidence", "load"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        envs = log.read_envelopes()
        for env in envs:
            assert g.get_node(f"evidence:{env.entry_hash}") is not None

        # EVIDENCES edge from first envelope to gv.oc-1.
        edges = g.get_edges(f"evidence:{envs[0].entry_hash}", "control:nist-csf-2.0:gv.oc-1")
        assert any(e.get("relationship") == "EVIDENCES" for e in edges)

    def test_unresolved_refs_abort_the_batch(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload_with_refs("e-1", ["nist-csf-2.0:gv.oc-1"])))
        # Typo'd framework — must abort.
        log.append(normalize(_compliance_payload_with_refs("e-2", ["nist-csf-2.0:typo-xx"])))

        result = runner.invoke(app, ["evidence", "load"])
        assert result.exit_code == 1
        assert "typo-xx" in result.stdout

        # Graph stays clean — no evidence nodes added at all on failure.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        for env in log.read_envelopes():
            assert g.get_node(f"evidence:{env.entry_hash}") is None

    def test_empty_log_prints_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)

        result = runner.invoke(app, ["evidence", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no evidence" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["evidence", "load"])
        assert result.exit_code == 1

    def test_in_graph_column_reflects_load_state(self, tmp_path: Path, monkeypatch):
        """`lemma evidence log` shows ✓ after load, ✗ beforehand."""
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)
        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload_with_refs("e-1", ["nist-csf-2.0:gv.oc-1"])))

        before = runner.invoke(app, ["evidence", "log"])
        assert before.exit_code == 0
        assert "Graph" in before.stdout  # column header
        assert "✗" in before.stdout

        assert runner.invoke(app, ["evidence", "load"]).exit_code == 0

        after = runner.invoke(app, ["evidence", "log"])
        assert after.exit_code == 0
        assert "✓" in after.stdout


def _seed_indexed_framework(project_dir: Path) -> None:
    from lemma.services.indexer import ControlIndexer

    indexer = ControlIndexer(index_dir=project_dir / ".lemma" / "index")
    indexer.index_controls(
        "nist-csf-2.0",
        [
            {
                "id": "gv.oc-1",
                "title": "Organizational context 1",
                "prose": "Establish organizational context for cybersecurity decisions.",
                "family": "GV.OC",
            },
        ],
    )


class TestEvidenceInfer:
    """`lemma evidence infer` end-to-end (Refs #88)."""

    def test_happy_path_writes_edge_and_prints_summary(self, tmp_path: Path, monkeypatch):
        import json
        from unittest.mock import MagicMock, patch

        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)
        _seed_indexed_framework(tmp_path)

        # Configure auto-accept threshold via lemma.config.yaml.
        (tmp_path / "lemma.config.yaml").write_text(
            "ai:\n  automation:\n    thresholds:\n      evidence-mapping: 0.7\n"
        )

        # Load an event with NO control_refs so the Evidence node is orphaned.
        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload("e-1")))
        runner.invoke(app, ["evidence", "load"])

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.92, "rationale": "Direct match."}
        )

        with patch("lemma.commands.evidence.get_llm_client", return_value=mock_llm):
            result = runner.invoke(app, ["evidence", "infer"])

        assert result.exit_code == 0, result.stdout
        assert "newly linked" in result.stdout.lower()

        graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        envs = log.read_envelopes()
        edges = graph.get_edges(f"evidence:{envs[0].entry_hash}", "control:nist-csf-2.0:gv.oc-1")
        relevant = [e for e in edges if e.get("relationship") == "EVIDENCES"]
        assert len(relevant) == 1
        assert relevant[0]["confidence"] == 0.92

    def test_accept_all_overrides_missing_threshold(self, tmp_path: Path, monkeypatch):
        import json
        from unittest.mock import MagicMock, patch

        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)
        _seed_indexed_framework(tmp_path)
        # No lemma.config.yaml — no thresholds configured.

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload("e-1")))
        runner.invoke(app, ["evidence", "load"])

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps({"confidence": 0.3, "rationale": "Weak."})

        with patch("lemma.commands.evidence.get_llm_client", return_value=mock_llm):
            result = runner.invoke(app, ["evidence", "infer", "--accept-all"])

        assert result.exit_code == 0, result.stdout

        graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        envs = log.read_envelopes()
        edges = graph.get_edges(f"evidence:{envs[0].entry_hash}", "control:nist-csf-2.0:gv.oc-1")
        relevant = [e for e in edges if e.get("relationship") == "EVIDENCES"]
        assert len(relevant) == 1
        assert relevant[0]["confidence"] == 0.3

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["evidence", "infer"])
        assert result.exit_code == 1

    def test_no_orphans_prints_zero_summary(self, tmp_path: Path, monkeypatch):
        from unittest.mock import MagicMock, patch

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)
        _seed_indexed_framework(tmp_path)

        mock_llm = MagicMock()

        with patch("lemma.commands.evidence.get_llm_client", return_value=mock_llm):
            result = runner.invoke(app, ["evidence", "infer"])

        assert result.exit_code == 0, result.stdout
        assert "0" in result.stdout  # "0 orphaned" or similar
        mock_llm.generate.assert_not_called()
