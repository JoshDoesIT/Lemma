"""Tests for the Lemma Control Plane receiver (Refs #25).

The Control Plane is the receiving side of `lemma-agent forward`: it
accepts signed evidence envelopes via HTTP, verifies them against the
producer's public key, persists them to a per-producer day file, and
reports the verification verdict in the response.

These tests spin up the handler in-process via `http.server.HTTPServer`
on a free port, then exercise it with stdlib `urllib.request`.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.server import HTTPServer
from pathlib import Path

from lemma.services.control_plane import make_handler_class
from lemma.services.evidence_log import EvidenceLog
from lemma.services.ocsf_normalizer import normalize


def _compliance_event(uid: str = "evt-1") -> dict:
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


def _produce_signed_envelope(project_dir: Path, uid: str = "evt-1") -> dict:
    """Sign one envelope locally and return its dict shape — what an
    agent would POST to the Control Plane."""
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    appended = log.append(normalize(_compliance_event(uid)))
    assert appended, "EvidenceLog.append returned False (deduped?)"
    envelopes = log.read_envelopes()
    return json.loads(envelopes[-1].model_dump_json())


def _start_server(handler_cls) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def _post_json(url: str, body: dict, timeout: float = 5.0) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_post_evidence_persists_to_per_producer_day_file(tmp_path: Path) -> None:
    """Agent posts a signed envelope; receiver writes it to
    <evidence-dir>/<producer>/<date>.jsonl."""
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"  # producer key already on disk

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, body = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
    finally:
        server.shutdown()
        server.server_close()

    assert status == 200, f"status={status} body={body}"
    assert body["verdict"] == "PROVEN"
    assert body["entry_hash"] == envelope["entry_hash"]

    producer_dir = cp_evidence / "Lemma"
    written_files = list(producer_dir.glob("*.jsonl"))
    assert len(written_files) == 1, f"expected 1 day file, got {written_files}"
    written = json.loads(written_files[0].read_text().strip())
    assert written["entry_hash"] == envelope["entry_hash"]


def test_post_evidence_rejects_malformed_json(tmp_path: Path) -> None:
    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/evidence",
            data=b"not json",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected HTTPError")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, f"expected 400, got {exc.code}"
    finally:
        server.shutdown()
        server.server_close()


def test_post_evidence_rejects_envelope_without_known_producer_key(tmp_path: Path) -> None:
    """An envelope signed by a producer whose public key is not in
    `--keys-dir` must be rejected (we can't verify the signature)."""
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)

    cp_evidence = tmp_path / "cp-evidence"
    # Empty keys-dir — Control Plane has no public key for "Lemma".
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, body = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
    finally:
        server.shutdown()
        server.server_close()

    assert status == 422, f"status={status} body={body}"
    assert body["verdict"] in {"VIOLATED", "DEGRADED"}


def test_post_evidence_detects_tampered_signature(tmp_path: Path) -> None:
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)
    # Flip a hex char in the signature.
    sig = envelope["signature"]
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    envelope["signature"] = flipped

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, body = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
    finally:
        server.shutdown()
        server.server_close()

    assert status == 422
    assert body["verdict"] in {"VIOLATED", "DEGRADED"}


def test_post_evidence_unknown_path_returns_404(tmp_path: Path) -> None:
    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/wrong", timeout=5)
            raise AssertionError("expected HTTPError")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_health_endpoint_returns_basic_status(tmp_path: Path) -> None:
    """Control Plane mirrors the agent's /health convention so operators
    have a uniform observability probe."""
    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
    finally:
        server.shutdown()
        server.server_close()

    for key in ("evidence_count", "producer_count", "started_at", "uptime_seconds"):
        assert key in body, f"missing key {key} in /health"


def test_two_envelopes_from_same_producer_form_a_chain(tmp_path: Path) -> None:
    """Receiver appends in arrival order; the per-producer evidence log
    must be chain-consistent across two envelopes."""
    project = tmp_path / "agent-side"
    project.mkdir()
    e1 = _produce_signed_envelope(project, "evt-cp-1")
    e2 = _produce_signed_envelope(project, "evt-cp-2")
    assert e2["prev_hash"] == e1["entry_hash"]

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        s1, _ = _post_json(f"http://127.0.0.1:{port}/v1/evidence", e1)
        s2, b2 = _post_json(f"http://127.0.0.1:{port}/v1/evidence", e2)
    finally:
        server.shutdown()
        server.server_close()

    assert s1 == 200
    assert s2 == 200, f"second envelope failed: {b2}"
    written = list((cp_evidence / "Lemma").glob("*.jsonl"))
    # All envelopes for the same UTC date land in one file; both
    # envelopes were signed in the same test run so this is stable.
    text = "".join(f.read_text() for f in written)
    assert e1["entry_hash"] in text
    assert e2["entry_hash"] in text


def test_two_producers_get_separate_directories(tmp_path: Path) -> None:
    """Cross-producer isolation: a Lemma envelope and an Okta envelope
    write to different per-producer directories."""
    from lemma.services import crypto as lemma_crypto

    # Bootstrap two producers in the same keys-dir.
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    lemma_crypto.generate_keypair(producer="Lemma", key_dir=keys_dir)
    lemma_crypto.generate_keypair(producer="Okta", key_dir=keys_dir)

    # Each producer gets its own log dir + chain on the agent side so
    # the receiver can verify them independently — chain isolation per
    # producer is the correct receiver-side semantic.
    lemma_log = EvidenceLog(log_dir=tmp_path / "agent-lemma", key_dir=keys_dir)
    lemma_log.append(normalize(_compliance_event("lemma-evt")))
    e_lemma = lemma_log.read_envelopes()[-1]

    okta_event = _compliance_event("okta-evt")
    okta_event["metadata"]["product"]["name"] = "Okta"
    okta_log = EvidenceLog(log_dir=tmp_path / "agent-okta", key_dir=keys_dir)
    okta_log.append(normalize(okta_event))
    e_okta = okta_log.read_envelopes()[-1]

    cp_evidence = tmp_path / "cp-evidence"
    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=keys_dir)
    server, port = _start_server(handler)
    try:
        s1, _ = _post_json(
            f"http://127.0.0.1:{port}/v1/evidence",
            json.loads(e_lemma.model_dump_json()),
        )
        s2, _ = _post_json(
            f"http://127.0.0.1:{port}/v1/evidence",
            json.loads(e_okta.model_dump_json()),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert s1 == 200 and s2 == 200
    assert (cp_evidence / "Lemma").is_dir()
    assert (cp_evidence / "Okta").is_dir()
    assert list((cp_evidence / "Lemma").glob("*.jsonl"))
    assert list((cp_evidence / "Okta").glob("*.jsonl"))
