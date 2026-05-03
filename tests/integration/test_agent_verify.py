"""End-to-end parity test for the Go `lemma-agent verify` subcommand.

Builds the Go binary, asks Python's `EvidenceLog` to write a multi-entry
signed JSONL, then invokes the agent against that file. PROVEN means the
canonical-JSON, chain-hash, and Ed25519 layers all agree across the two
language implementations. Drift surfaces as a VIOLATED entry-hash
mismatch — exactly what the parity oracle is here to catch.

Skipped on hosts without Go on PATH so a contributor without a Go
toolchain doesn't see red.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = REPO_ROOT / "agent"

requires_go = pytest.mark.skipif(
    shutil.which("go") is None,
    reason="Go toolchain not on PATH; the agent-build CI job covers this case",
)


@pytest.fixture(scope="module")
def agent_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the agent once per test module."""
    if shutil.which("go") is None:
        pytest.skip("Go toolchain not available")
    out = tmp_path_factory.mktemp("agent-bin") / "lemma-agent"
    subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=AGENT_DIR,
        check=True,
    )
    return out


def _compliance_event(uid: str) -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {"version": "1.3.0", "product": {"name": "Lemma"}, "uid": uid},
    }


def _seed_signed_log(project_dir: Path, count: int = 2) -> Path:
    """Append `count` envelopes via the production EvidenceLog API."""
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    for i in range(count):
        log.append(normalize(_compliance_event(f"agent-parity-{i}")))

    files = sorted((project_dir / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files) == 1, f"expected one evidence file, got {files}"
    return files[0]


@requires_go
def test_pristine_multi_entry_log_verifies_proven(agent_binary: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=3)
    keys_dir = project / ".lemma" / "keys"

    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"expected exit 0\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "PROVEN" in result.stdout
    assert "0 VIOLATED" in result.stdout
    # Three entries → three PROVEN lines plus the summary line.
    assert result.stdout.count("PROVEN") >= 3


@requires_go
def test_tampered_event_payload_flips_to_violated(agent_binary: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=2)

    # Mangle the first envelope's event payload — entry_hash recomputation
    # will not match the claimed value.
    text = log_path.read_text()
    tampered = text.replace("agent-parity-0", "AGENT-PARITY-0", 1)
    assert tampered != text, "uid substring not found in JSONL"
    log_path.write_text(tampered)

    keys_dir = project / ".lemma" / "keys"
    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"expected exit 1, got {result.returncode}\nstdout:\n{result.stdout}"
    )
    assert "VIOLATED" in result.stdout
    assert "hash mismatch" in result.stdout.lower()


@requires_go
def test_tampered_signature_flips_to_violated(agent_binary: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=1)

    # Flip a hex char in the signature — the Ed25519 check fails.
    text = log_path.read_text()
    sig_marker = '"signature":"'
    idx = text.index(sig_marker) + len(sig_marker)
    flipped = "0" if text[idx] != "0" else "1"
    tampered = text[:idx] + flipped + text[idx + 1 :]
    log_path.write_text(tampered)

    keys_dir = project / ".lemma" / "keys"
    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "VIOLATED" in result.stdout


@requires_go
def test_missing_keys_dir_marks_entry_violated(agent_binary: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=1)

    empty_keys = tmp_path / "empty-keys"
    empty_keys.mkdir()

    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path), "--keys-dir", str(empty_keys)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "public key not found" in result.stdout.lower()


@requires_go
def test_missing_required_flag_exits_two(agent_binary: Path, tmp_path: Path) -> None:
    log_path = tmp_path / "stub.jsonl"
    log_path.write_text("")
    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "--keys-dir" in result.stderr or "usage" in result.stderr.lower()


@requires_go
def test_no_args_prints_version_line(agent_binary: Path) -> None:
    result = subprocess.run(
        [str(agent_binary)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "lemma-agent v" in result.stdout
    assert "verify" in result.stdout
    assert "sign" in result.stdout


# CRL parity tests ------------------------------------------------------


def _export_crl(project_dir: Path, producer: str) -> Path:
    """Run `lemma evidence export-crl` end-to-end and return the file path."""
    out = project_dir / f"crl-{producer}.json"
    result = subprocess.run(
        [
            "uv",
            "run",
            "lemma",
            "evidence",
            "export-crl",
            "--producer",
            producer,
            "--output",
            str(out),
        ],
        cwd=project_dir,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"export-crl failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert out.is_file()
    return out


def _retroactively_revoke_signing_key(project_dir: Path, producer: str, revoked_at_iso: str) -> str:
    """Rotate then revoke the producer's first ACTIVE key, pinning the
    revocation timestamp to ``revoked_at_iso``.

    The agent's CRL flip rule is ``signed_at >= revoked_at`` → VIOLATED. To
    observe a flip, ``revoked_at`` has to be earlier than the envelope's
    ``signed_at``; the production ``revoke_key`` API stamps ``now()``, which
    is always *after* the envelope was signed during a single test run.
    Workaround: rotate (so the producer still has a current ACTIVE key for
    signing the CRL), revoke as usual, then rewrite the lifecycle on disk
    with the desired ``revoked_at``.
    """
    from datetime import datetime

    from lemma.services import crypto as lemma_crypto

    keys_dir = project_dir / ".lemma" / "keys"
    lifecycle = lemma_crypto._read_lifecycle(producer, keys_dir)
    old_active = lifecycle.active()
    assert old_active is not None

    lemma_crypto.rotate_key(producer=producer, key_dir=keys_dir)
    lemma_crypto.revoke_key(
        producer=producer,
        key_id=old_active.key_id,
        reason="test-retroactive",
        key_dir=keys_dir,
    )

    # Pin revoked_at to the requested moment.
    lifecycle = lemma_crypto._read_lifecycle(producer, keys_dir)
    record = lifecycle.find(old_active.key_id)
    assert record is not None
    record.revoked_at = datetime.fromisoformat(revoked_at_iso)
    lemma_crypto._write_lifecycle(producer, keys_dir, lifecycle)
    return old_active.key_id


@requires_go
def test_verify_with_crl_flips_revoked_entry_to_violated(
    agent_binary: Path, tmp_path: Path
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=1)

    # Pin revoked_at to a moment well before the envelope's signed_at so
    # the CRL flip rule (signed_at >= revoked_at → VIOLATED) fires.
    _retroactively_revoke_signing_key(project, "Lemma", "2020-01-01T00:00:00+00:00")
    crl_path = _export_crl(project, "Lemma")
    keys_dir = project / ".lemma" / "keys"

    result = subprocess.run(
        [
            str(agent_binary),
            "verify",
            str(log_path),
            "--keys-dir",
            str(keys_dir),
            "--crl",
            str(crl_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"expected exit 1\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "VIOLATED" in result.stdout
    # Python's export_crl derives the CRL from the local lifecycle, so once
    # Slice I (#193) reads the local lifecycle the merge's "earlier wins"
    # tie-break may name either source — what matters is the flip fired.
    assert "revoked at" in result.stdout
    assert "source: CRL" in result.stdout or "source: local lifecycle" in result.stdout
    # The advisory must NOT appear when --crl was supplied.
    assert "No CRL supplied" not in result.stdout


@requires_go
def test_verify_with_crl_does_not_affect_unrelated_producer(
    agent_binary: Path, tmp_path: Path
) -> None:
    """A CRL for a different producer must not flip a Lemma-signed entry.

    Stand up a second producer ("Okta") with its own active key, revoke that
    key, export the Okta CRL, then run the agent against the Lemma-signed
    evidence log. The Lemma envelope must still verify PROVEN.
    """
    from lemma.services import crypto as lemma_crypto

    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=1)
    keys_dir = project / ".lemma" / "keys"

    # Mint a key for "Okta", rotate+revoke (with retroactive revoked_at
    # so the CRL would flip a matching producer's envelope), then export
    # Okta's CRL.
    lemma_crypto.generate_keypair(producer="Okta", key_dir=keys_dir)
    _retroactively_revoke_signing_key(project, "Okta", "2020-01-01T00:00:00+00:00")
    okta_crl = _export_crl(project, "Okta")

    result = subprocess.run(
        [
            str(agent_binary),
            "verify",
            str(log_path),
            "--keys-dir",
            str(keys_dir),
            "--crl",
            str(okta_crl),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"cross-producer CRL must be ignored — exit 0 expected\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "PROVEN" in result.stdout


@requires_go
def test_verify_emits_no_crl_advisory_without_crl_flag(agent_binary: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=1)
    keys_dir = project / ".lemma" / "keys"

    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "No CRL supplied" in result.stdout


# Sign parity oracle (Go signs, Python verifies) -----------------------


def _normalized_event_json(uid: str) -> str:
    """Run a raw OCSF event through Python's normalizer and return its
    canonical JSON form. Operators must hand the agent a normalized event
    so the resulting envelope round-trips through Pydantic's verify path."""
    from lemma.services.ocsf_normalizer import normalize

    event = normalize(_compliance_event(uid))
    return event.model_dump_json()


def _seed_keys_only(project_dir: Path) -> Path:
    """Mint a Lemma producer ACTIVE key without writing any envelopes."""
    from lemma.services import crypto as lemma_crypto

    keys_dir = project_dir / ".lemma" / "keys"
    keys_dir.mkdir(parents=True)
    lemma_crypto.generate_keypair(producer="Lemma", key_dir=keys_dir)
    return keys_dir


@requires_go
def test_agent_sign_produces_python_verifiable_envelope(agent_binary: Path, tmp_path: Path) -> None:
    """Round-trip: Go signs, Python verifies via EvidenceLog.verify_entry."""
    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = _seed_keys_only(project)

    event_json = _normalized_event_json("go-sign-1")
    result = subprocess.run(
        [str(agent_binary), "sign", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        input=event_json,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"sign failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    line = result.stdout.strip()
    assert line, "sign produced empty output"

    # Drop the line into Lemma's evidence directory and ask EvidenceLog
    # to verify it.
    evidence_dir = project / ".lemma" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "today.jsonl").write_text(line + "\n")

    import json as _json

    env_dict = _json.loads(line)
    log = EvidenceLog(log_dir=evidence_dir)
    verdict = log.verify_entry(env_dict["entry_hash"])
    assert verdict.state == EvidenceIntegrityState.PROVEN, (
        f"expected PROVEN, got {verdict.state} ({verdict.detail})\nenvelope: {line}"
    )


@requires_go
def test_agent_sign_chain_links_via_prev_hash_flag(agent_binary: Path, tmp_path: Path) -> None:
    """Two signs in sequence, with the second's --prev-hash set to the first's
    entry_hash, must form a valid chain that verifies end-to-end."""
    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = _seed_keys_only(project)

    import json as _json

    first = subprocess.run(
        [str(agent_binary), "sign", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        input=_normalized_event_json("chain-0"),
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    first_line = first.stdout.strip()
    first_hash = _json.loads(first_line)["entry_hash"]

    second = subprocess.run(
        [
            str(agent_binary),
            "sign",
            "--keys-dir",
            str(keys_dir),
            "--producer",
            "Lemma",
            "--prev-hash",
            first_hash,
        ],
        input=_normalized_event_json("chain-1"),
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0, second.stderr
    second_line = second.stdout.strip()
    second_hash = _json.loads(second_line)["entry_hash"]

    evidence_dir = project / ".lemma" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "chain.jsonl").write_text(first_line + "\n" + second_line + "\n")

    log = EvidenceLog(log_dir=evidence_dir)
    for h in (first_hash, second_hash):
        verdict = log.verify_entry(h)
        assert verdict.state == EvidenceIntegrityState.PROVEN, (
            f"{h}: {verdict.state} ({verdict.detail})"
        )


@requires_go
def test_agent_sign_default_prev_hash_is_genesis(agent_binary: Path, tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = _seed_keys_only(project)

    result = subprocess.run(
        [str(agent_binary), "sign", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        input=_normalized_event_json("genesis"),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    import json as _json

    env = _json.loads(result.stdout.strip())
    assert env["prev_hash"] == "0" * 64


# Local lifecycle parity test (no CRL exported) ------------------------


@requires_go
def test_verify_with_local_lifecycle_revocation_flips_to_violated(
    agent_binary: Path, tmp_path: Path
) -> None:
    """Local meta.json says REVOKED with revoked_at < signed_at — agent must
    flip to VIOLATED with source: local lifecycle, even without --crl."""
    project = tmp_path / "proj"
    project.mkdir()
    log_path = _seed_signed_log(project, count=1)

    # Retroactively revoke the signing key in the local lifecycle (no CRL
    # export — only the meta.json source is in play).
    _retroactively_revoke_signing_key(project, "Lemma", "2020-01-01T00:00:00+00:00")
    keys_dir = project / ".lemma" / "keys"

    result = subprocess.run(
        [str(agent_binary), "verify", str(log_path), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"expected exit 1\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "VIOLATED" in result.stdout
    assert "source: local lifecycle" in result.stdout


# Ingest parity tests --------------------------------------------------


@requires_go
def test_agent_ingest_round_trips_through_verify(agent_binary: Path, tmp_path: Path) -> None:
    """End-to-end: Go ingest → Go verify on the same binary."""
    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = _seed_keys_only(project)
    evidence_dir = project / ".lemma" / "evidence"

    # Pre-normalize 3 events via Python so Pydantic defaults are baked in
    # (the agent's ingest doesn't do OCSF Pydantic-grade validation).
    jsonl_path = tmp_path / "events.jsonl"
    lines = [_normalized_event_json(f"ingest-rt-{i}") for i in range(3)]
    jsonl_path.write_text("\n".join(lines) + "\n")

    ingest = subprocess.run(
        [
            str(agent_binary),
            "ingest",
            str(jsonl_path),
            "--keys-dir",
            str(keys_dir),
            "--evidence-dir",
            str(evidence_dir),
            "--producer",
            "Lemma",
        ],
        capture_output=True,
        text=True,
    )
    assert ingest.returncode == 0, (
        f"ingest failed\nstdout:\n{ingest.stdout}\nstderr:\n{ingest.stderr}"
    )
    assert "3 ingested" in ingest.stdout

    # Find the day file the agent wrote.
    day_files = list(evidence_dir.glob("*.jsonl"))
    assert len(day_files) == 1, f"expected 1 day file, got {day_files}"

    verify = subprocess.run(
        [str(agent_binary), "verify", str(day_files[0]), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, (
        f"verify failed\nstdout:\n{verify.stdout}\nstderr:\n{verify.stderr}"
    )
    assert "3 PROVEN, 0 VIOLATED" in verify.stdout


@requires_go
def test_agent_ingest_output_python_verifies_proven(agent_binary: Path, tmp_path: Path) -> None:
    """Cross-language: Go ingest → Python's EvidenceLog.verify_entry."""
    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = _seed_keys_only(project)
    evidence_dir = project / ".lemma" / "evidence"

    jsonl_path = tmp_path / "events.jsonl"
    lines = [_normalized_event_json(f"ingest-cross-{i}") for i in range(2)]
    jsonl_path.write_text("\n".join(lines) + "\n")

    ingest = subprocess.run(
        [
            str(agent_binary),
            "ingest",
            str(jsonl_path),
            "--keys-dir",
            str(keys_dir),
            "--evidence-dir",
            str(evidence_dir),
            "--producer",
            "Lemma",
        ],
        capture_output=True,
        text=True,
    )
    assert ingest.returncode == 0, ingest.stderr

    log = EvidenceLog(log_dir=evidence_dir)
    envelopes = log.read_envelopes()
    assert len(envelopes) == 2
    for env in envelopes:
        verdict = log.verify_entry(env.entry_hash)
        assert verdict.state == EvidenceIntegrityState.PROVEN, (
            f"{env.entry_hash}: {verdict.state} ({verdict.detail})"
        )


# Keygen parity test ---------------------------------------------------


@requires_go
def test_agent_keygen_produces_python_loadable_keypair(agent_binary: Path, tmp_path: Path) -> None:
    """Cross-language: Go mints keys, Python loads them via crypto.read_lifecycle
    and signs an envelope, then Go verifies the resulting log entry."""
    from datetime import UTC
    from datetime import datetime as _datetime

    from lemma.services import crypto as lemma_crypto
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = project / ".lemma" / "keys"
    keys_dir.mkdir(parents=True)

    # 1. Go mints the keypair.
    keygen = subprocess.run(
        [str(agent_binary), "keygen", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        capture_output=True,
        text=True,
    )
    assert keygen.returncode == 0, (
        f"keygen failed\nstdout:\n{keygen.stdout}\nstderr:\n{keygen.stderr}"
    )
    assert "Generated ed25519:" in keygen.stdout

    # 2. Python loads the lifecycle and finds the ACTIVE key.
    lifecycle = lemma_crypto._read_lifecycle("Lemma", keys_dir)
    active = lifecycle.active()
    assert active is not None, "Python could not find ACTIVE key in Go-minted lifecycle"
    assert active.key_id.startswith("ed25519:")

    # 3. Python signs an envelope using that key.
    evidence_dir = project / ".lemma" / "evidence"
    log = EvidenceLog(log_dir=evidence_dir, key_dir=keys_dir)
    log.append(
        normalize(
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "category_uid": 2000,
                "category_name": "Findings",
                "type_uid": 200301,
                "activity_id": 1,
                "time": _datetime.now(UTC).isoformat(),
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Lemma"},
                    "uid": "keygen-cross-lang",
                },
            }
        )
    )

    # 4. Go verifies the Python-signed envelope.
    log_files = list(evidence_dir.glob("*.jsonl"))
    assert len(log_files) == 1, f"expected 1 log file, got {log_files}"
    verify = subprocess.run(
        [
            str(agent_binary),
            "verify",
            str(log_files[0]),
            "--keys-dir",
            str(keys_dir),
        ],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, (
        f"verify failed\nstdout:\n{verify.stdout}\nstderr:\n{verify.stderr}"
    )
    assert "1 PROVEN, 0 VIOLATED" in verify.stdout


@requires_go
def test_agent_keygen_idempotent_does_not_clobber_existing_key(
    agent_binary: Path, tmp_path: Path
) -> None:
    """Second keygen call returns the same key_id without rewriting files."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()

    first = subprocess.run(
        [str(agent_binary), "keygen", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0
    # Capture the meta.json bytes so we can confirm idempotent calls don't touch them.
    meta_path = keys_dir / "Lemma" / "meta.json"
    meta_before = meta_path.read_bytes()

    second = subprocess.run(
        [str(agent_binary), "keygen", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0
    assert "already has ACTIVE key" in second.stdout
    assert meta_path.read_bytes() == meta_before, "idempotent call mutated meta.json"


# Forward parity tests --------------------------------------------------


@requires_go
def test_agent_forward_posts_envelopes_to_python_http_server(
    agent_binary: Path, tmp_path: Path
) -> None:
    """End-to-end: Go signs N envelopes, forwards them to a Python HTTP
    server, server captures bodies, asserts the agent delivered them
    intact in order."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = _seed_keys_only(project)
    evidence_dir = project / ".lemma" / "evidence"

    # Use the agent's ingest to produce a real signed JSONL.
    jsonl_input = tmp_path / "events.jsonl"
    jsonl_input.write_text("\n".join(_normalized_event_json(f"fwd-{i}") for i in range(3)) + "\n")
    ingest = subprocess.run(
        [
            str(agent_binary),
            "ingest",
            str(jsonl_input),
            "--keys-dir",
            str(keys_dir),
            "--evidence-dir",
            str(evidence_dir),
            "--producer",
            "Lemma",
        ],
        capture_output=True,
        text=True,
    )
    assert ingest.returncode == 0, ingest.stderr

    day_files = list(evidence_dir.glob("*.jsonl"))
    assert len(day_files) == 1
    log_path = day_files[0]

    # Stand up a Python HTTP server that records POST bodies.
    received: list[bytes] = []
    received_headers: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            received.append(body)
            received_headers.append(dict(self.headers))
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args, **kwargs):
            pass  # silence the default per-request log

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        result = subprocess.run(
            [
                str(agent_binary),
                "forward",
                str(log_path),
                "--to",
                f"http://127.0.0.1:{port}/",
                "--header",
                "X-Lemma-Producer=Lemma",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0, (
        f"forward exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "3 forwarded, 0 failed." in result.stdout
    assert len(received) == 3, f"server received {len(received)} POSTs, expected 3"

    # Bodies should be the JSONL lines in order.
    expected_lines = log_path.read_text().strip().split("\n")
    for i, want in enumerate(expected_lines):
        assert received[i].decode() == want, f"POST {i} body differs from on-disk envelope"

    # Custom header propagated.
    assert received_headers[0].get("X-Lemma-Producer") == "Lemma"
    assert received_headers[0].get("Content-Type") == "application/json"


@requires_go
def test_agent_forward_5xx_response_exits_one(agent_binary: Path, tmp_path: Path) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args, **kwargs):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        jsonl = tmp_path / "envelopes.jsonl"
        jsonl.write_text('{"entry_hash":"a"}\n')
        result = subprocess.run(
            [
                str(agent_binary),
                "forward",
                str(jsonl),
                "--to",
                f"http://127.0.0.1:{port}/",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 1, f"exit {result.returncode}, want 1"
    assert "0 forwarded, 1 failed." in result.stdout


# Keyrotate / keyrevoke parity tests -----------------------------------


@requires_go
def test_agent_keyrotate_python_sees_retired_and_new_active(
    agent_binary: Path, tmp_path: Path
) -> None:
    """Cross-language: Go rotates the producer's ACTIVE key, Python's
    crypto.read_lifecycle reads back the retired→new ACTIVE chain
    (status flip, retired_at populated, successor_key_id populated),
    and the new ACTIVE key signs an envelope that Go verifies."""
    from datetime import UTC
    from datetime import datetime as _datetime

    from lemma.services import crypto as lemma_crypto
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = project / ".lemma" / "keys"
    keys_dir.mkdir(parents=True)

    # 1. Go bootstraps the keypair.
    keygen = subprocess.run(
        [str(agent_binary), "keygen", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        capture_output=True,
        text=True,
    )
    assert keygen.returncode == 0, keygen.stderr
    old_key_id = (
        keygen.stdout.strip().removeprefix("Generated ").removesuffix(" for producer Lemma.")
    )

    # 2. Go rotates.
    rotate = subprocess.run(
        [str(agent_binary), "keyrotate", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        capture_output=True,
        text=True,
    )
    assert rotate.returncode == 0, f"keyrotate failed:\n{rotate.stderr}"
    assert "Rotated Lemma:" in rotate.stdout

    # 3. Python reads the lifecycle and sees both records.
    lifecycle = lemma_crypto._read_lifecycle("Lemma", keys_dir)
    assert len(lifecycle.keys) == 2, (
        f"expected 2 lifecycle records after rotate, got {len(lifecycle.keys)}"
    )
    old = next(r for r in lifecycle.keys if r.key_id == old_key_id)
    new = next(r for r in lifecycle.keys if r.key_id != old_key_id)
    assert old.status.value == "RETIRED"
    assert old.retired_at is not None
    assert old.successor_key_id == new.key_id
    assert new.status.value == "ACTIVE"
    assert lifecycle.active() is not None
    assert lifecycle.active().key_id == new.key_id

    # 4. Python signs with the rotated ACTIVE key.
    log = EvidenceLog(
        log_dir=project / ".lemma" / "evidence",
        key_dir=keys_dir,
    )
    log.append(
        normalize(
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "category_uid": 2000,
                "category_name": "Findings",
                "type_uid": 200301,
                "activity_id": 1,
                "time": _datetime.now(UTC).isoformat(),
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Lemma"},
                    "uid": "rotate-cross-lang",
                },
            }
        )
    )

    # 5. Go verifies the Python-signed envelope.
    log_files = list((project / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(log_files) == 1
    verify = subprocess.run(
        [str(agent_binary), "verify", str(log_files[0]), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert "1 PROVEN, 0 VIOLATED" in verify.stdout


@requires_go
def test_agent_keyrevoke_python_sees_revoked_status_and_reason(
    agent_binary: Path, tmp_path: Path
) -> None:
    """Cross-language: Go revokes a key, Python reads back the REVOKED
    status, revoked_at timestamp, and revoked_reason. Then Go's
    `verify --keys-dir` flips a freshly-signed envelope to VIOLATED via
    the local lifecycle merge (#193 path)."""
    from datetime import UTC
    from datetime import datetime as _datetime

    from lemma.services import crypto as lemma_crypto
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    project = tmp_path / "proj"
    project.mkdir()
    keys_dir = project / ".lemma" / "keys"
    keys_dir.mkdir(parents=True)

    # 1. Bootstrap.
    keygen = subprocess.run(
        [str(agent_binary), "keygen", "--keys-dir", str(keys_dir), "--producer", "Lemma"],
        capture_output=True,
        text=True,
    )
    assert keygen.returncode == 0
    key_id = keygen.stdout.strip().removeprefix("Generated ").removesuffix(" for producer Lemma.")

    # 2. Sign one envelope BEFORE revocation.
    evidence_dir = project / ".lemma" / "evidence"
    log = EvidenceLog(log_dir=evidence_dir, key_dir=keys_dir)
    log.append(
        normalize(
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "category_uid": 2000,
                "category_name": "Findings",
                "type_uid": 200301,
                "activity_id": 1,
                "time": _datetime.now(UTC).isoformat(),
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Lemma"},
                    "uid": "revoke-cross-lang",
                },
            }
        )
    )
    log_file = next(evidence_dir.glob("*.jsonl"))

    # 3. Go revokes.
    revoke = subprocess.run(
        [
            str(agent_binary),
            "keyrevoke",
            "--keys-dir",
            str(keys_dir),
            "--producer",
            "Lemma",
            "--key-id",
            key_id,
            "--reason",
            "key compromise",
        ],
        capture_output=True,
        text=True,
    )
    assert revoke.returncode == 0, f"keyrevoke failed:\n{revoke.stderr}"
    assert f"Revoked {key_id}" in revoke.stdout

    # 4. Python reads back the REVOKED record.
    lifecycle = lemma_crypto._read_lifecycle("Lemma", keys_dir)
    rec = next(r for r in lifecycle.keys if r.key_id == key_id)
    assert rec.status.value == "REVOKED"
    assert rec.revoked_at is not None
    assert rec.revoked_reason == "key compromise"

    # 5. Backdate the local lifecycle revoked_at so it precedes the
    #    pre-revocation envelope's signed_at — exercises the local
    #    lifecycle merge in the verifier (#193): signed_at >= revoked_at
    #    flips PROVEN → VIOLATED.
    meta_path = keys_dir / "Lemma" / "meta.json"
    import json

    meta = json.loads(meta_path.read_text())
    for r in meta["keys"]:
        if r["key_id"] == key_id:
            r["revoked_at"] = "2020-01-01T00:00:00Z"
    meta_path.write_text(json.dumps(meta, indent=2))

    verify = subprocess.run(
        [str(agent_binary), "verify", str(log_file), "--keys-dir", str(keys_dir)],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 1, (
        f"verify after backdated revoke should exit 1\nstdout:\n{verify.stdout}"
    )
    assert "VIOLATED" in verify.stdout
