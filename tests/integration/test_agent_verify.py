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
