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


class TestAssessmentResults:
    """`lemma evidence assessment-results` (Refs #25 Slice A)."""

    def _seed_graph_with_one_passed_control(self, project_dir: Path) -> None:
        """Persist a graph with one mapped control so AR has at least one finding."""
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph()
        g.add_framework("nist-800-53", title="NIST 800-53")
        g.add_control(
            framework="nist-800-53", control_id="ac-1", title="Access Control", family="AC"
        )
        g.add_policy("access-control.md", title="Access Control Policy")
        g.add_mapping(
            policy="access-control.md", framework="nist-800-53", control_id="ac-1", confidence=0.9
        )
        g.save(project_dir / ".lemma" / "graph.json")

    def test_stdout_mode_emits_valid_ar_json(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.oscal_ar import validate_assessment_results

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_passed_control(tmp_path)

        result = runner.invoke(app, ["evidence", "assessment-results"])
        assert result.exit_code == 0, result.stdout
        ar = json.loads(result.stdout)
        validate_assessment_results(ar)
        findings = ar["assessment-results"]["results"][0]["findings"]
        assert len(findings) == 1
        assert findings[0]["target"]["target-id"] == "control:nist-800-53:ac-1"

    def test_output_writes_signed_pair(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services import crypto

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_passed_control(tmp_path)

        out = tmp_path / "ar"
        result = runner.invoke(app, ["evidence", "assessment-results", "--output", str(out)])
        assert result.exit_code == 0, result.stdout
        json_path = out / "assessment-results.json"
        sig_path = out / "assessment-results.sig"
        assert json_path.is_file()
        assert sig_path.is_file()

        # Sig hex-decodes and verifies against the project's Lemma key.
        sig_bytes = bytes.fromhex(sig_path.read_text().strip())
        ok = crypto.verify(
            json_path.read_bytes(),
            sig_bytes,
            producer="Lemma",
            key_dir=tmp_path / ".lemma" / "keys",
        )
        assert ok is True

    def test_no_sign_flag_skips_sidecar(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_passed_control(tmp_path)

        out = tmp_path / "ar"
        result = runner.invoke(
            app, ["evidence", "assessment-results", "--output", str(out), "--no-sign"]
        )
        assert result.exit_code == 0, result.stdout
        assert (out / "assessment-results.json").is_file()
        assert not (out / "assessment-results.sig").exists()

    def test_existing_non_empty_output_requires_force(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_passed_control(tmp_path)

        out = tmp_path / "ar"
        out.mkdir()
        (out / "stray.txt").write_text("existing content")

        first = runner.invoke(app, ["evidence", "assessment-results", "--output", str(out)])
        assert first.exit_code == 1
        assert "force" in first.stdout.lower()

        second = runner.invoke(
            app, ["evidence", "assessment-results", "--output", str(out), "--force"]
        )
        assert second.exit_code == 0, second.stdout
        assert not (out / "stray.txt").exists()
        assert (out / "assessment-results.json").is_file()


class TestAssessmentPlan:
    """`lemma evidence assessment-plan` (Refs #25 Slice E)."""

    def _seed_graph_with_one_framework(self, project_dir: Path) -> None:
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph()
        g.add_framework("nist-800-53", title="NIST 800-53")
        g.add_control(
            framework="nist-800-53", control_id="ac-1", title="Access Policy", family="AC"
        )
        g.add_control(
            framework="nist-800-53",
            control_id="ac-2",
            title="Account Management",
            family="AC",
        )
        g.save(project_dir / ".lemma" / "graph.json")

    def test_stdout_mode_emits_valid_ap_json(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.oscal_ap import validate_assessment_plan

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_framework(tmp_path)

        result = runner.invoke(app, ["evidence", "assessment-plan"])
        assert result.exit_code == 0, result.stdout
        ap = json.loads(result.stdout)
        validate_assessment_plan(ap)
        selections = ap["assessment-plan"]["reviewed-controls"]["control-selections"]
        assert len(selections) == 1
        ids = [r["control-id"] for r in selections[0]["include-controls"]]
        assert ids == ["nist-800-53:ac-1", "nist-800-53:ac-2"]

    def test_output_writes_signed_pair(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services import crypto

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_framework(tmp_path)

        out = tmp_path / "ap"
        result = runner.invoke(app, ["evidence", "assessment-plan", "--output", str(out)])
        assert result.exit_code == 0, result.stdout
        json_path = out / "assessment-plan.json"
        sig_path = out / "assessment-plan.sig"
        assert json_path.is_file()
        assert sig_path.is_file()

        sig_bytes = bytes.fromhex(sig_path.read_text().strip())
        ok = crypto.verify(
            json_path.read_bytes(),
            sig_bytes,
            producer="Lemma",
            key_dir=tmp_path / ".lemma" / "keys",
        )
        assert ok is True

    def test_no_sign_flag_skips_sidecar(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_framework(tmp_path)

        out = tmp_path / "ap"
        result = runner.invoke(
            app,
            ["evidence", "assessment-plan", "--output", str(out), "--no-sign"],
        )
        assert result.exit_code == 0, result.stdout
        assert (out / "assessment-plan.json").is_file()
        assert not (out / "assessment-plan.sig").exists()

    def test_existing_non_empty_output_requires_force(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._seed_graph_with_one_framework(tmp_path)

        out = tmp_path / "ap"
        out.mkdir()
        (out / "stray.txt").write_text("existing content")

        first = runner.invoke(app, ["evidence", "assessment-plan", "--output", str(out)])
        assert first.exit_code == 1
        assert "force" in first.stdout.lower()

        second = runner.invoke(
            app, ["evidence", "assessment-plan", "--output", str(out), "--force"]
        )
        assert second.exit_code == 0, second.stdout
        assert not (out / "stray.txt").exists()
        assert (out / "assessment-plan.json").is_file()


class TestEvidenceBundle:
    """`lemma evidence bundle` and `verify --bundle` (Refs #175, #25)."""

    def test_bundle_creates_directory_and_prints_summary(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_signed_entries(tmp_path, count=2)

        out = tmp_path / "bundle"
        result = runner.invoke(app, ["evidence", "bundle", "--output", str(out)])
        assert result.exit_code == 0, result.stdout
        assert (out / "manifest.json").is_file()
        assert (out / "manifest.sig").is_file()
        # Default-on: AR + AP land in assessments/ alongside ai/.
        assert (out / "assessments" / "assessment-results.json").is_file()
        assert (out / "assessments" / "assessment-plan.json").is_file()
        assert "audit bundle" in result.stdout.lower()

    def test_bundle_no_assessments_flag_omits_assessments_directory(
        self, tmp_path: Path, monkeypatch
    ):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_signed_entries(tmp_path, count=1)

        out = tmp_path / "bundle"
        result = runner.invoke(
            app, ["evidence", "bundle", "--output", str(out), "--no-assessments"]
        )
        assert result.exit_code == 0, result.stdout
        assert not (out / "assessments").exists()

    def test_bundle_into_existing_non_empty_directory_requires_force(
        self, tmp_path: Path, monkeypatch
    ):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_signed_entries(tmp_path, count=1)

        out = tmp_path / "bundle"
        out.mkdir()
        (out / "stray.txt").write_text("not from a bundle")

        first = runner.invoke(app, ["evidence", "bundle", "--output", str(out)])
        assert first.exit_code == 1
        assert "force" in first.stdout.lower()

        second = runner.invoke(app, ["evidence", "bundle", "--output", str(out), "--force"])
        assert second.exit_code == 0
        assert not (out / "stray.txt").exists()

    def test_verify_with_bundle_works_on_fresh_install(self, tmp_path: Path, monkeypatch):
        """End-to-end: export bundle, blow away `.lemma/`, verify with --bundle."""
        import shutil

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        hashes = _seed_signed_entries(tmp_path, count=2)
        target_hash = hashes[0]

        bundle_dir = tmp_path / "bundle"
        export_result = runner.invoke(app, ["evidence", "bundle", "--output", str(bundle_dir)])
        assert export_result.exit_code == 0, export_result.stdout

        # Simulate fresh install: nuke .lemma/ entirely. The bundle must
        # carry everything verify needs.
        shutil.rmtree(tmp_path / ".lemma")
        # Re-init so verify_command's `--bundle` branch (which does NOT call
        # `_require_lemma_project`) is exercised cleanly. Without a `.lemma/`
        # directory, the runner's CWD is fine.
        result = runner.invoke(
            app, ["evidence", "verify", target_hash, "--bundle", str(bundle_dir)]
        )
        assert result.exit_code == 0, result.stdout
        assert "PROVEN" in result.stdout

    def test_verify_rejects_both_crl_and_bundle(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        hashes = _seed_signed_entries(tmp_path, count=1)

        # We don't actually need a real bundle or CRL on disk — argument parsing
        # short-circuits before either is opened.
        result = runner.invoke(
            app,
            [
                "evidence",
                "verify",
                hashes[0],
                "--crl",
                "/nope/crl.json",
                "--bundle",
                "/nope/bundle",
            ],
        )
        assert result.exit_code == 1
        assert "OR" in result.stdout or "both" in result.stdout.lower()


class TestExportAndVerifyCrl:
    """`lemma evidence export-crl` and `verify --crl` (Refs #101)."""

    def _project_with_revocation(self, project_dir: Path):
        from lemma.services import crypto

        # Seed an entry signed by the current ACTIVE key.
        hashes = _seed_signed_entries(project_dir, count=1)

        key_dir = project_dir / ".lemma" / "evidence" / ".." / "keys"  # not real; use the actual:
        key_dir = project_dir / ".lemma" / "keys"
        active = crypto.public_key_id(producer="Lemma", key_dir=key_dir)

        # Rotate so we have a new ACTIVE key, then revoke the old one.
        new_active = crypto.rotate_key(producer="Lemma", key_dir=key_dir)
        crypto.revoke_key(
            producer="Lemma",
            key_id=active,
            reason="test: simulated leak",
            key_dir=key_dir,
        )
        return hashes, active, new_active

    def test_export_crl_writes_signed_document_to_stdout(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.models.signed_evidence import RevocationList

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._project_with_revocation(tmp_path)

        result = runner.invoke(app, ["evidence", "export-crl", "--producer", "Lemma"])
        assert result.exit_code == 0, result.stdout

        crl = RevocationList.model_validate_json(result.stdout)
        assert crl.producer == "Lemma"
        assert len(crl.revocations) == 1

    def test_export_crl_with_output_writes_file_round_trip(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.models.signed_evidence import RevocationList

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._project_with_revocation(tmp_path)

        out = tmp_path / "crl.json"
        result = runner.invoke(
            app,
            ["evidence", "export-crl", "--producer", "Lemma", "--output", str(out)],
        )
        assert result.exit_code == 0, result.stdout
        assert out.exists()
        crl = RevocationList.model_validate_json(out.read_text())
        assert crl.producer == "Lemma"
        assert len(crl.revocations) == 1

    def test_export_crl_no_active_key_exits_one(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        result = runner.invoke(app, ["evidence", "export-crl", "--producer", "ghost"])
        assert result.exit_code == 1

    def test_verify_with_crl_flag_returns_violated_for_post_revocation_entry(
        self, tmp_path: Path, monkeypatch
    ):
        from lemma.cli import app
        from lemma.models.signed_evidence import (
            ProvenanceRecord,
            RevocationEntry,
            RevocationList,
            SignedEvidence,
        )
        from lemma.services import crypto
        from lemma.services.evidence_log import EvidenceLog, _compute_entry_hash
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        key_dir = tmp_path / ".lemma" / "keys"
        log.append(normalize(_compliance_payload("pre")))
        pre = log.read_envelopes()[0]
        active = pre.signer_key_id

        # Forge a post-revocation entry signed with the same private key,
        # but the CRL we'll supply lists that key as revoked BEFORE the
        # forged signed_at. Local lifecycle has no revocation here — we
        # want to prove the CRL alone is enough to flip the verdict.
        forged_event = normalize(_compliance_payload("post"))
        forged_hash = _compute_entry_hash(pre.entry_hash, forged_event, [])
        priv = crypto._load_private_by_key_id("Lemma", active, key_dir)
        sig = priv.sign(bytes.fromhex(forged_hash)).hex()
        from datetime import UTC, datetime, timedelta

        signed_at = datetime.now(UTC)
        forged = SignedEvidence(
            event=forged_event,
            prev_hash=pre.entry_hash,
            entry_hash=forged_hash,
            signature=sig,
            signer_key_id=active,
            signed_at=signed_at,
            provenance=[
                ProvenanceRecord(
                    stage="storage",
                    actor="lemma.services.evidence_log",
                    content_hash=forged_hash,
                )
            ],
        )
        log_file = next((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
        with log_file.open("a") as f:
            f.write(forged.model_dump_json() + "\n")

        # Build a CRL using the existing ACTIVE key as issuer (only one key
        # ever generated for this producer, so issuer == revoked key — odd
        # but valid; Lemma can self-attest a revocation when no rotation
        # has happened, and it tests the same code path).
        rotated = crypto.rotate_key(producer="Lemma", key_dir=key_dir)
        # Now the original `active` is RETIRED; revoke it locally so we
        # can also exercise a real export. But the test uses a hand-built
        # CRL so we don't depend on local lifecycle here.
        crl = crypto.export_crl(producer="Lemma", key_dir=key_dir)
        # Augment the CRL with a revocation pre-dating signed_at, signed
        # by the new ACTIVE key.
        augmented = RevocationList(
            producer="Lemma",
            issued_at=crl.issued_at,
            revocations=[
                *crl.revocations,
                RevocationEntry(
                    key_id=active,
                    revoked_at=signed_at - timedelta(seconds=10),
                    reason="forged",
                ),
            ],
            issuer_key_id=rotated,
            signature="00",  # placeholder; we re-sign below
        )
        # Re-sign with the new ACTIVE key.
        from lemma.services.crypto import _crl_canonical_bytes

        payload = _crl_canonical_bytes(
            augmented.producer,
            augmented.issued_at,
            augmented.revocations,
            augmented.issuer_key_id,
        )
        new_priv = crypto._load_private_by_key_id("Lemma", rotated, key_dir)
        augmented = augmented.model_copy(update={"signature": new_priv.sign(payload).hex()})

        crl_path = tmp_path / "crl.json"
        crl_path.write_text(augmented.model_dump_json(indent=2))

        # `lemma evidence verify <pre-hash>` is PROVEN; <forged-hash>
        # without CRL is also PROVEN (signature is valid, no local
        # revocation). With --crl, the forged entry flips to VIOLATED.
        result = runner.invoke(app, ["evidence", "verify", forged_hash, "--crl", str(crl_path)])
        assert result.exit_code == 1, result.stdout
        assert "VIOLATED" in result.stdout

    def test_verify_without_crl_prints_missing_crl_note(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        hashes = _seed_signed_entries(tmp_path, count=1)

        result = runner.invoke(app, ["evidence", "verify", hashes[0]])
        assert result.exit_code == 0, result.stdout
        assert "No CRL supplied" in result.stdout

    def test_verify_with_invalid_crl_signature_exits_one_and_does_not_merge(
        self, tmp_path: Path, monkeypatch
    ):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        hashes = _seed_signed_entries(tmp_path, count=1)
        self._project_with_revocation(tmp_path)  # sets up keys

        # Build a valid CRL, then tamper with its signature so verify_crl rejects it.
        from lemma.services.crypto import export_crl

        crl = export_crl(producer="Lemma", key_dir=tmp_path / ".lemma" / "keys")
        bad = crl.model_copy(update={"signature": "00" * (len(crl.signature) // 2)})
        crl_path = tmp_path / "crl.json"
        crl_path.write_text(bad.model_dump_json(indent=2))

        result = runner.invoke(app, ["evidence", "verify", hashes[0], "--crl", str(crl_path)])
        assert result.exit_code == 1
        assert "CRL signature invalid" in result.stdout

    def test_verify_with_crl_for_unknown_producer_exits_one(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        hashes = _seed_signed_entries(tmp_path, count=1)

        # Hand-craft a CRL claiming to be from a producer with no public key on file.
        from datetime import UTC, datetime

        from lemma.models.signed_evidence import RevocationList

        crl = RevocationList(
            producer="UnknownVendor",
            issued_at=datetime.now(UTC),
            revocations=[],
            issuer_key_id="ed25519:nonexistent",
            signature="00" * 64,
        )
        crl_path = tmp_path / "crl.json"
        crl_path.write_text(crl.model_dump_json(indent=2))

        result = runner.invoke(app, ["evidence", "verify", hashes[0], "--crl", str(crl_path)])
        assert result.exit_code == 1
        assert "no public key" in result.stdout.lower() or "unknownvendor" in result.stdout.lower()

    def test_export_crl_round_trips_through_verify_on_fresh_install(
        self, tmp_path: Path, monkeypatch
    ):
        """AC-1: a CRL exported on one machine verifies on a fresh install
        that has only the public PEM."""
        from lemma.cli import app
        from lemma.services import crypto

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        self._project_with_revocation(tmp_path)

        # Export the CRL on the operator side.
        out = tmp_path / "crl.json"
        export_result = runner.invoke(
            app,
            ["evidence", "export-crl", "--producer", "Lemma", "--output", str(out)],
        )
        assert export_result.exit_code == 0, export_result.stdout

        # Now: simulate a fresh install. Capture the producer's CURRENT
        # ACTIVE public PEM (which signed the CRL), drop everything else.
        key_dir = tmp_path / ".lemma" / "keys"
        active = crypto.public_key_id(producer="Lemma", key_dir=key_dir)
        active_pem = (key_dir / "Lemma" / f"{active}.public.pem").read_bytes()

        # Verify the CRL signature with only that public key bytes —
        # mirrors what an external verifier with just the PEM would do.
        from lemma.models.signed_evidence import RevocationList
        from lemma.services.crypto import verify_crl

        crl = RevocationList.model_validate_json(out.read_text())
        assert verify_crl(crl, active_pem) is True


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

    def test_load_populates_severity_name_and_class_uid_from_event(
        self, tmp_path: Path, monkeypatch
    ):
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_controls(tmp_path)

        # severity_id=4 → HIGH per OCSF
        payload = _compliance_payload_with_refs("e-sev", ["nist-csf-2.0:gv.oc-1"])
        payload["severity_id"] = 4
        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(payload))

        result = runner.invoke(app, ["evidence", "load"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        env = log.read_envelopes()[0]
        node = g.get_node(f"evidence:{env.entry_hash}")
        assert node is not None
        assert node["severity"] == "HIGH"
        assert node["class_uid"] == 2003

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


def _seed_graph_with_harmonized_controls(project_dir: Path) -> None:
    """Two frameworks, two controls, one HARMONIZED_WITH edge between them."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-csf-2.0")
    g.add_framework("pci-dss-4.0")
    g.add_control(
        framework="nist-csf-2.0", control_id="gv.oc-1", title="Org Context 1", family="GV.OC"
    )
    g.add_control(
        framework="pci-dss-4.0",
        control_id="12.1",
        title="Information Security Policy",
        family="12",
    )
    g.add_harmonization(
        framework_a="nist-csf-2.0",
        control_a="gv.oc-1",
        framework_b="pci-dss-4.0",
        control_b="12.1",
        similarity=0.85,
    )
    g.save(project_dir / ".lemma" / "graph.json")


class TestEvidenceLoadAutoRebuild:
    """`lemma evidence load` should rebuild IMPLICITLY_EVIDENCES edges
    after the direct EVIDENCES walk so cross-scope reuse is current
    without a separate command (Cross-Scope Evidence Reuse).
    """

    def test_load_writes_implicit_edges_via_harmonization(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_harmonized_controls(tmp_path)

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload_with_refs("e-1", ["nist-csf-2.0:gv.oc-1"])))

        result = runner.invoke(app, ["evidence", "load"])
        assert result.exit_code == 0, result.stdout
        assert "implicit reuse edge" in result.stdout.lower()

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        env = log.read_envelopes()[0]
        edges = g.get_edges(f"evidence:{env.entry_hash}", "control:pci-dss-4.0:12.1")
        implicit = [e for e in edges if e.get("relationship") == "IMPLICITLY_EVIDENCES"]
        assert len(implicit) == 1
        assert implicit[0]["via_control"] == "control:nist-csf-2.0:gv.oc-1"
        assert implicit[0]["similarity"] == 0.85


class TestEvidenceRebuildReuse:
    """`lemma evidence rebuild-reuse [--min-similarity N]` recomputes
    IMPLICITLY_EVIDENCES on demand without re-running discover/load.
    """

    def test_rebuilds_implicit_with_default_threshold(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_harmonized_controls(tmp_path)

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload_with_refs("e-1", ["nist-csf-2.0:gv.oc-1"])))
        # Load direct EVIDENCES; the auto-rebuild already wrote an implicit edge.
        runner.invoke(app, ["evidence", "load"])

        result = runner.invoke(app, ["evidence", "rebuild-reuse"])
        assert result.exit_code == 0, result.stdout
        # 1 implicit edge expected at default threshold (0.7 ≤ 0.85).
        assert "1" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        env = log.read_envelopes()[0]
        edges = g.get_edges(f"evidence:{env.entry_hash}", "control:pci-dss-4.0:12.1")
        assert any(e.get("relationship") == "IMPLICITLY_EVIDENCES" for e in edges)

    def test_min_similarity_override_drops_implicit_edges(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.evidence_log import EvidenceLog
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.ocsf_normalizer import normalize

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _seed_graph_with_harmonized_controls(tmp_path)

        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        log.append(normalize(_compliance_payload_with_refs("e-1", ["nist-csf-2.0:gv.oc-1"])))
        runner.invoke(app, ["evidence", "load"])

        # Tighten the threshold above the harmonization similarity (0.85).
        result = runner.invoke(app, ["evidence", "rebuild-reuse", "--min-similarity", "0.9"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        env = log.read_envelopes()[0]
        edges = g.get_edges(f"evidence:{env.entry_hash}", "control:pci-dss-4.0:12.1")
        assert all(e.get("relationship") != "IMPLICITLY_EVIDENCES" for e in edges)

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["evidence", "rebuild-reuse"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------
# `lemma evidence collect --config` (Refs #116)
# ---------------------------------------------------------------------


class TestCollectFromConfigFile:
    def test_collect_loads_config_file_and_runs_connector(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Pointing `--config` at a `lemma_connector_config.yaml` runs
        the connector with the values from the file. No CLI flags."""
        from typer.testing import CliRunner

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        cfg = tmp_path / "lemma_connector_config.yaml"
        cfg.write_text("connector: github\nconfig:\n  repo: octocat/Hello-World\n")

        result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
        assert result.exit_code == 0, result.stdout
        # GitHub stub connector emits at least one event.
        assert "ingested" in result.stdout

    def test_collect_config_overrides_can_use_env_vars(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        monkeypatch.setenv("AGENT_REPO", "envvar/repo")

        cfg = tmp_path / "lemma_connector_config.yaml"
        cfg.write_text("connector: github\nconfig:\n  repo: ${AGENT_REPO}\n")

        result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
        assert result.exit_code == 0, result.stdout

    def test_collect_config_disabled_exits_zero_without_running(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """`enabled: false` skips the run cleanly — useful when an
        operator wants to disable a connector temporarily without
        deleting its config."""
        from typer.testing import CliRunner

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        cfg = tmp_path / "lemma_connector_config.yaml"
        cfg.write_text("connector: github\nenabled: false\nconfig:\n  repo: foo/bar\n")

        result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "disabled" in result.stdout.lower()

    def test_collect_config_file_missing_exits_one(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        result = CliRunner().invoke(
            app, ["evidence", "collect", "--config", str(tmp_path / "missing.yaml")]
        )
        assert result.exit_code == 1

    def test_collect_legacy_positional_flag_form_still_works(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Backward compat: passing the connector name + per-connector
        flags (no --config) keeps working unchanged."""
        from typer.testing import CliRunner

        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        result = CliRunner().invoke(
            app, ["evidence", "collect", "github", "--repo", "octocat/Hello-World"]
        )
        assert result.exit_code == 0, result.stdout
