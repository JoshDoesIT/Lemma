"""Tests for the append-only EvidenceLog."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path


def _compliance_payload(uid: str = "evt-1", when: datetime | None = None) -> dict:
    when = when or datetime.now(UTC)
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": when.isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Lemma"},
            "uid": uid,
        },
    }


def _auth_payload(uid: str = "auth-1", when: datetime | None = None) -> dict:
    when = when or datetime.now(UTC)
    return {
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3000,
        "category_name": "IAM",
        "type_uid": 300201,
        "activity_id": 1,
        "time": when.isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Okta"},
            "uid": uid,
        },
    }


def test_append_writes_one_line_and_read_all_round_trips(tmp_path: Path):
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    event = normalize(_compliance_payload())

    wrote = log.append(event)

    assert wrote is True
    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files) == 1
    assert len(files[0].read_text().strip().splitlines()) == 1

    out = log.read_all()
    assert len(out) == 1
    assert isinstance(out[0], ComplianceFinding)
    assert out[0].metadata["uid"] == "evt-1"


def test_evidence_log_is_append_only(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert not hasattr(log, "update")
    assert not hasattr(log, "delete")
    assert not hasattr(log, "clear")


def test_read_all_returns_events_across_files_in_chronological_order(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    yesterday = datetime.now(UTC) - timedelta(days=1)
    today = datetime.now(UTC)

    event_yesterday = normalize(_compliance_payload("y-1", when=yesterday))
    event_today = normalize(_compliance_payload("t-1", when=today))

    # Append out-of-order to prove sort is by file name, not insertion order
    log.append(event_today)
    log.append(event_yesterday)

    files = sorted((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files) == 2  # one file per UTC date

    out = log.read_all()
    assert [e.metadata["uid"] for e in out] == ["y-1", "t-1"]


def test_append_dedupes_by_metadata_uid(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    event = normalize(_compliance_payload("dup-1"))

    assert log.append(event) is True
    assert log.append(event) is False  # second call is a no-op

    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files[0].read_text().strip().splitlines()) == 1


def test_append_content_hash_dedupe_when_uid_absent(tmp_path: Path):
    """Producers that don't set metadata.uid fall back to content-hash dedupe."""
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    payload = _compliance_payload()
    del payload["metadata"]["uid"]

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    event = normalize(payload)

    assert log.append(event) is True
    assert log.append(event) is False

    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files[0].read_text().strip().splitlines()) == 1


def test_append_writes_signed_chained_envelope(tmp_path: Path):
    """Every appended entry is wrapped in a SignedEvidence envelope with chain + signature."""
    import json

    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("e-1")))
    log.append(normalize(_compliance_payload("e-2")))

    # Inspect the raw JSONL — confirm every line is an envelope shape
    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    lines = [line for f in files for line in f.read_text().strip().splitlines()]

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    # Envelope fields
    for payload in (first, second):
        assert "event" in payload
        assert "entry_hash" in payload
        assert "signature" in payload
        assert "signer_key_id" in payload
        assert payload["signer_key_id"].startswith("ed25519:")

    # Genesis entry has zeroed prev_hash; second chains to first's entry_hash
    assert first["prev_hash"] == "0" * 64
    assert second["prev_hash"] == first["entry_hash"]


def test_read_all_still_returns_unwrapped_ocsf_events(tmp_path: Path):
    """Signing is transparent to callers using read_all()."""
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("e-1")))

    events = log.read_all()
    assert len(events) == 1
    assert isinstance(events[0], ComplianceFinding)
    assert events[0].metadata["uid"] == "e-1"


def test_verify_entry_returns_proven_for_untampered_chain(tmp_path: Path):
    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("e-1")))
    log.append(normalize(_compliance_payload("e-2")))

    envelopes = log.read_envelopes()
    for env in envelopes:
        result = log.verify_entry(env.entry_hash)
        assert result.state == EvidenceIntegrityState.PROVEN


def test_verify_entry_returns_violated_when_content_modified(tmp_path: Path):
    import json

    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("e-1")))

    # Tamper: rewrite the entry's event message in-place on disk
    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    payload = json.loads(files[0].read_text().strip())
    payload["event"]["message"] = "tampered message"
    files[0].write_text(json.dumps(payload) + "\n")

    envelope = log.read_envelopes()[0]
    result = log.verify_entry(envelope.entry_hash)
    assert result.state == EvidenceIntegrityState.VIOLATED
    assert "hash" in result.detail.lower() or "content" in result.detail.lower()


def test_verify_entry_returns_violated_when_chain_broken(tmp_path: Path):
    import json

    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("e-1")))
    log.append(normalize(_compliance_payload("e-2")))

    # Tamper: rewrite the second entry's prev_hash so the chain breaks
    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    lines = files[0].read_text().strip().splitlines()
    second = json.loads(lines[1])
    second["prev_hash"] = "f" * 64
    lines[1] = json.dumps(second)
    files[0].write_text("\n".join(lines) + "\n")

    envelopes = log.read_envelopes()
    result = log.verify_entry(envelopes[1].entry_hash)
    assert result.state == EvidenceIntegrityState.VIOLATED
    assert "chain" in result.detail.lower() or "prev" in result.detail.lower()


def test_verify_entry_returns_degraded_when_signer_key_unknown(tmp_path: Path):
    import shutil

    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("e-1")))

    # Simulate a lost key: delete the keystore after signing
    shutil.rmtree(tmp_path / ".lemma" / "keys")

    envelope = log.read_envelopes()[0]
    result = log.verify_entry(envelope.entry_hash)
    assert result.state == EvidenceIntegrityState.DEGRADED
    assert "key" in result.detail.lower()


def test_rotation_leaves_prior_entries_proven(tmp_path: Path):
    """Pre-rotation entries stay PROVEN after the signing key is rotated."""
    from lemma.models.signed_evidence import EvidenceIntegrityState
    from lemma.services.crypto import rotate_key
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("rot-before")))

    rotate_key(producer="Lemma", key_dir=tmp_path / ".lemma" / "keys")
    log.append(normalize(_compliance_payload("rot-after")))

    envelopes = log.read_envelopes()
    for env in envelopes:
        result = log.verify_entry(env.entry_hash)
        assert result.state == EvidenceIntegrityState.PROVEN, (
            f"expected PROVEN, got {result.state}: {result.detail}"
        )


def test_revocation_violates_entries_signed_at_or_after_revoked_at(tmp_path: Path):
    """REVOKED signer → VIOLATED for entries signed at/after revoked_at, PROVEN before.

    Models the adversarial scenario the revocation check exists to catch: an
    attacker with a stolen-but-now-revoked key signs new entries after the
    revocation timestamp. The honest verifier must refuse those entries even
    though the signature itself is cryptographically valid.
    """
    from datetime import timedelta

    from lemma.models.signed_evidence import (
        EvidenceIntegrityState,
        ProvenanceRecord,
        SignedEvidence,
    )
    from lemma.services import crypto
    from lemma.services.evidence_log import (
        EvidenceLog,
        _compute_entry_hash,
    )
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    key_dir = tmp_path / ".lemma" / "keys"

    # A legitimate pre-revoke entry signed by the currently-active key.
    log.append(normalize(_compliance_payload("pre-revoke")))
    pre_envelope = log.read_envelopes()[0]
    active_key_id = pre_envelope.signer_key_id

    # Revoke the signing key.
    crypto.revoke_key(
        producer="Lemma",
        key_id=active_key_id,
        reason="test: simulated compromise",
        key_dir=key_dir,
    )

    # Manually craft a "malicious" post-revocation entry that still uses the
    # revoked key. This is the whole point of the revocation check — the
    # signature is cryptographically valid, but policy says ignore it.
    malicious_event = normalize(_compliance_payload("post-revoke"))
    prev_hash = pre_envelope.entry_hash
    # Match the new-algorithm shape: empty pre-storage prefix → storage-only envelope.
    entry_hash = _compute_entry_hash(prev_hash, malicious_event, [])
    # Use the signing primitive directly with the revoked key's private material.
    private_key = crypto._load_private_by_key_id("Lemma", active_key_id, key_dir)  # type: ignore[attr-defined]
    signature = private_key.sign(bytes.fromhex(entry_hash)).hex()

    revoked_record = crypto.read_lifecycle("Lemma", key_dir=key_dir).find(active_key_id)
    malicious_envelope = SignedEvidence(
        event=malicious_event,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        signature=signature,
        signer_key_id=active_key_id,
        signed_at=revoked_record.revoked_at + timedelta(milliseconds=1),
        provenance=[
            ProvenanceRecord(
                stage="storage",
                actor="lemma.services.evidence_log",
                content_hash=entry_hash,
            )
        ],
    )
    log_file = next((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    with log_file.open("a") as f:
        f.write(malicious_envelope.model_dump_json() + "\n")

    pre_result = log.verify_entry(pre_envelope.entry_hash)
    post_result = log.verify_entry(malicious_envelope.entry_hash)

    assert pre_result.state == EvidenceIntegrityState.PROVEN, (
        f"pre-revoke entry should be PROVEN, got {pre_result.state}: {pre_result.detail}"
    )
    assert post_result.state == EvidenceIntegrityState.VIOLATED, (
        f"post-revoke entry should be VIOLATED, got {post_result.state}: {post_result.detail}"
    )
    assert "revoked" in post_result.detail.lower()


def test_filter_by_class_and_time_range(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    t_early = datetime(2026, 4, 20, 12, 0, 0, tzinfo=UTC)
    t_mid = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    t_late = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)

    log.append(normalize(_compliance_payload("c-early", when=t_early)))
    log.append(normalize(_compliance_payload("c-late", when=t_late)))
    log.append(normalize(_auth_payload("a-mid", when=t_mid)))

    # filter_by_class
    compliance = log.filter_by_class(2003)
    assert {e.metadata["uid"] for e in compliance} == {"c-early", "c-late"}
    auth = log.filter_by_class(3002)
    assert {e.metadata["uid"] for e in auth} == {"a-mid"}
    assert log.filter_by_class(9999) == []

    # filter_by_time_range — half-open [start, end)
    window = log.filter_by_time_range(t_early, t_late)
    assert {e.metadata["uid"] for e in window} == {"c-early", "a-mid"}


# --- Provenance chain (issue #99) ---


def test_append_accepts_incoming_provenance_and_appends_storage_last(tmp_path: Path):
    from lemma.models.signed_evidence import ProvenanceRecord
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / "evidence")
    event = normalize(_compliance_payload("prov-1"))
    source = ProvenanceRecord(
        stage="source",
        actor="ingest-cli:sandbox.jsonl",
        content_hash="a" * 64,
    )
    normalization = ProvenanceRecord(
        stage="normalization",
        actor="lemma.ocsf_normalizer/1",
        content_hash="b" * 64,
    )

    assert log.append(event, provenance=[source, normalization]) is True

    envelopes = log.read_envelopes()
    assert len(envelopes) == 1
    env = envelopes[0]
    stages = [r.stage for r in env.provenance]
    assert stages == ["source", "normalization", "storage"]
    assert env.provenance[0].actor == "ingest-cli:sandbox.jsonl"
    assert env.provenance[-1].content_hash == env.entry_hash


def test_append_without_provenance_kwarg_still_works(tmp_path: Path):
    """Back-compat: callers that don't pass provenance get a storage-only envelope."""
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / "evidence")
    event = normalize(_compliance_payload("no-prov"))
    assert log.append(event) is True

    env = log.read_envelopes()[0]
    assert [r.stage for r in env.provenance] == ["storage"]


def test_entry_hash_changes_when_provenance_changes(tmp_path: Path):
    """Same event, different pre-storage provenance → different entry_hash."""
    from lemma.models.signed_evidence import ProvenanceRecord
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    event = normalize(_compliance_payload("hash-sensitive"))

    log_a = EvidenceLog(log_dir=tmp_path / "log_a")
    log_a.append(
        event, provenance=[ProvenanceRecord(stage="source", actor="A", content_hash="a" * 64)]
    )
    hash_a = log_a.read_envelopes()[0].entry_hash

    # Different provenance → different content bytes → different hash.
    log_b = EvidenceLog(log_dir=tmp_path / "log_b")
    log_b.append(
        event, provenance=[ProvenanceRecord(stage="source", actor="B", content_hash="b" * 64)]
    )
    hash_b = log_b.read_envelopes()[0].entry_hash

    assert hash_a != hash_b


def test_verify_returns_proven_for_untouched_envelope_with_provenance(tmp_path: Path):
    """Happy-path regression under the new algorithm."""
    from lemma.models.signed_evidence import EvidenceIntegrityState, ProvenanceRecord
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / "evidence")
    event = normalize(_compliance_payload("happy-prov"))
    log.append(
        event,
        provenance=[
            ProvenanceRecord(stage="source", actor="src", content_hash="a" * 64),
            ProvenanceRecord(stage="normalization", actor="norm", content_hash="b" * 64),
        ],
    )
    env = log.read_envelopes()[0]

    result = log.verify_entry(env.entry_hash)
    assert result.state == EvidenceIntegrityState.PROVEN, result.detail


def test_verify_detects_tampered_source_provenance(tmp_path: Path):
    """Mutating a pre-storage provenance record on disk must break verify."""
    import json

    from lemma.models.signed_evidence import EvidenceIntegrityState, ProvenanceRecord
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / "evidence")
    event = normalize(_compliance_payload("tamper-me"))
    log.append(
        event,
        provenance=[
            ProvenanceRecord(stage="source", actor="src", content_hash="a" * 64),
            ProvenanceRecord(stage="normalization", actor="norm", content_hash="b" * 64),
        ],
    )
    env = log.read_envelopes()[0]
    target_hash = env.entry_hash

    # Rewrite the on-disk line with source.content_hash flipped.
    log_file = next((tmp_path / "evidence").glob("*.jsonl"))
    lines = log_file.read_text().strip().splitlines()
    tampered = json.loads(lines[0])
    tampered["provenance"][0]["content_hash"] = "f" * 64
    log_file.write_text(json.dumps(tampered) + "\n")

    result = log.verify_entry(target_hash)
    assert result.state == EvidenceIntegrityState.VIOLATED


def test_get_envelope_returns_matching_envelope(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload(uid="a")))
    log.append(normalize(_compliance_payload(uid="b")))

    envelopes = log.read_envelopes()
    assert len(envelopes) == 2
    target = envelopes[1]

    result = log.get_envelope(target.entry_hash)
    assert result is not None
    assert result.entry_hash == target.entry_hash
    assert result.event.metadata["uid"] == "b"


def test_get_envelope_returns_none_for_unknown_hash(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload(uid="only")))

    assert log.get_envelope("0" * 64) is None
