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
