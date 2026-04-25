"""Append-only evidence log — signed, hash-chained OCSF events on disk.

Every appended event is wrapped in a ``SignedEvidence`` envelope and
written to ``.lemma/evidence/YYYY-MM-DD.jsonl``. The envelope carries:

- ``prev_hash`` — the entry hash of the previous line in the full log,
  or 64 zeros for the genesis entry.
- ``entry_hash`` — SHA-256 over ``prev_hash || canonical_json(event)``.
- ``signature`` — Ed25519 signature over the entry hash bytes, produced
  by the signing key for the producer named in
  ``event.metadata.product.name``.
- ``signer_key_id`` — stable public-key identifier from
  ``lemma.services.crypto``.
- ``provenance`` — transformation chain for the entry; this PR
  populates the ``storage`` stage, and connector PRs will fill in the
  earlier stages.

Dedupe happens at append time against today's log file (see the
``_dedupe_key`` helper). Verification walks the full log in order,
confirming each entry's content hash, chain linkage, and signature.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter

from lemma.models.key_metadata import KeyStatus
from lemma.models.ocsf import OcsfBaseEvent
from lemma.models.signed_evidence import (
    EvidenceIntegrityState,
    ProvenanceRecord,
    SignedEvidence,
)
from lemma.services import crypto

_GENESIS_HASH = "0" * 64
_envelope_adapter: TypeAdapter[SignedEvidence] = TypeAdapter(SignedEvidence)


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a single evidence entry.

    Attributes:
        state: PROVEN / DEGRADED / VIOLATED.
        detail: Human-readable explanation of which check succeeded or
            which one failed. Always non-empty.
    """

    state: EvidenceIntegrityState
    detail: str


def _producer_of(event: OcsfBaseEvent) -> str:
    product = event.metadata.get("product") if isinstance(event.metadata, dict) else None
    if isinstance(product, dict):
        name = product.get("name")
        if isinstance(name, str) and name:
            return name
    return "unknown"


def _canonical_signed_bytes(
    event: OcsfBaseEvent, provenance_prefix: list[ProvenanceRecord]
) -> bytes:
    """Canonical JSON of the event + pre-storage provenance for hashing.

    Sorted keys, no whitespace. The storage record is excluded by design —
    it carries the entry hash as its ``content_hash`` and can only be
    constructed after the hash is computed.
    """
    combined = {
        "event": json.loads(event.model_dump_json()),
        "provenance": [json.loads(r.model_dump_json()) for r in provenance_prefix],
    }
    return json.dumps(combined, sort_keys=True, separators=(",", ":")).encode()


def _compute_entry_hash(
    prev_hash: str, event: OcsfBaseEvent, provenance_prefix: list[ProvenanceRecord]
) -> str:
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode())
    hasher.update(_canonical_signed_bytes(event, provenance_prefix))
    return hasher.hexdigest()


def _dedupe_key(event: OcsfBaseEvent) -> str:
    """Stable idempotency key: producer-supplied ``metadata.uid``, else content hash."""
    uid = event.metadata.get("uid")
    if isinstance(uid, str) and uid:
        return f"uid:{uid}"
    digest = hashlib.sha256(event.model_dump_json().encode()).hexdigest()
    return f"hash:{digest}"


class EvidenceLog:
    """Append-only, signed, hash-chained log of OCSF evidence events."""

    def __init__(self, log_dir: Path, *, key_dir: Path | None = None) -> None:
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._key_dir = key_dir or (log_dir.parent / "keys")

    def _log_file(self, dt: datetime | None = None) -> Path:
        if dt is None:
            dt = datetime.now(UTC)
        return self._log_dir / f"{dt.strftime('%Y-%m-%d')}.jsonl"

    # --- internal helpers ---

    def _read_envelopes_from(self, log_file: Path) -> list[SignedEvidence]:
        if not log_file.exists():
            return []
        envelopes: list[SignedEvidence] = []
        for line in log_file.read_text().strip().splitlines():
            if line.strip():
                envelopes.append(_envelope_adapter.validate_json(line))
        return envelopes

    def _latest_entry_hash(self) -> str:
        """Walk all log files newest-to-oldest, return the most recent entry_hash."""
        for log_file in sorted(self._log_dir.glob("*.jsonl"), reverse=True):
            envelopes = self._read_envelopes_from(log_file)
            if envelopes:
                return envelopes[-1].entry_hash
        return _GENESIS_HASH

    def _seen_keys_today(self, log_file: Path) -> set[str]:
        if not log_file.exists():
            return set()
        keys: set[str] = set()
        for envelope in self._read_envelopes_from(log_file):
            keys.add(_dedupe_key(envelope.event))
        return keys

    # --- public API ---

    def append(
        self,
        event: OcsfBaseEvent,
        *,
        provenance: list[ProvenanceRecord] | None = None,
    ) -> bool:
        """Sign, chain, and append an event to the log.

        Args:
            event: The normalized OCSF event to store.
            provenance: Optional transformation records (``source``,
                ``normalization``) that preceded storage. They are
                folded into the signed hash — tampering with any of
                them breaks verification. This log always appends a
                final ``storage`` record carrying the entry hash.

        Returns ``True`` when a new envelope was written, ``False`` if
        the event was skipped by the dedupe guard on today's file.
        """
        log_file = self._log_file(event.time)
        if _dedupe_key(event) in self._seen_keys_today(log_file):
            return False

        producer = _producer_of(event)
        crypto.generate_keypair(producer=producer, key_dir=self._key_dir)
        signer_key_id = crypto.public_key_id(producer=producer, key_dir=self._key_dir)

        prefix = list(provenance) if provenance else []
        prev_hash = self._latest_entry_hash()
        entry_hash = _compute_entry_hash(prev_hash, event, prefix)
        signature = crypto.sign(
            bytes.fromhex(entry_hash), producer=producer, key_dir=self._key_dir
        ).hex()

        storage_record = ProvenanceRecord(
            stage="storage",
            actor="lemma.services.evidence_log",
            content_hash=entry_hash,
        )
        envelope = SignedEvidence(
            event=event,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            signature=signature,
            signer_key_id=signer_key_id,
            provenance=[*prefix, storage_record],
        )

        with log_file.open("a") as f:
            f.write(envelope.model_dump_json() + "\n")
        return True

    def read_envelopes(self) -> list[SignedEvidence]:
        """Return all envelopes in chronological (file, line) order."""
        envelopes: list[SignedEvidence] = []
        for log_file in sorted(self._log_dir.glob("*.jsonl")):
            envelopes.extend(self._read_envelopes_from(log_file))
        return envelopes

    def read_all(self) -> list[OcsfBaseEvent]:
        """Return all enveloped events in chronological order (envelopes unwrapped)."""
        return [env.event for env in self.read_envelopes()]

    def get_envelope(self, entry_hash: str) -> SignedEvidence | None:
        """Return the envelope whose entry_hash matches, or None if not found."""
        for env in self.read_envelopes():
            if env.entry_hash == entry_hash:
                return env
        return None

    def filter_by_class(self, class_uid: int) -> list[OcsfBaseEvent]:
        return [e for e in self.read_all() if e.class_uid == class_uid]

    def filter_by_time_range(self, start: datetime, end: datetime) -> list[OcsfBaseEvent]:
        return [e for e in self.read_all() if start <= e.time < end]

    def verify_entry(self, entry_hash: str) -> VerificationResult:
        """Check that a single entry is hash-consistent, chain-linked, and signed.

        Walks the full log in order until it reaches the target entry,
        verifying each step. Verdict:

        - VIOLATED if any earlier entry's content hash is wrong, any
          chain link is broken, or the target entry itself fails.
        - DEGRADED if the chain is intact but the signature can't be
          verified (most commonly because the signer's public key is no
          longer on file).
        - PROVEN otherwise.
        """
        expected_prev = _GENESIS_HASH
        for envelope in self.read_envelopes():
            # Chain linkage first: a bad prev_hash points at outright tampering.
            if envelope.prev_hash != expected_prev:
                if envelope.entry_hash == entry_hash:
                    return VerificationResult(
                        EvidenceIntegrityState.VIOLATED,
                        f"Chain broken at this entry: prev_hash "
                        f"{envelope.prev_hash[:12]} does not match prior entry_hash "
                        f"{expected_prev[:12]}.",
                    )
                return VerificationResult(
                    EvidenceIntegrityState.VIOLATED,
                    f"Chain broken at entry {envelope.entry_hash[:12]}.",
                )

            # Content hash: the envelope.entry_hash must match
            # SHA-256(prev || canonical(event + non-storage provenance)).
            # Storage is always last and carries the hash, so it's excluded
            # from the recomputation.
            prefix = [r for r in envelope.provenance if r.stage != "storage"]
            recomputed = _compute_entry_hash(envelope.prev_hash, envelope.event, prefix)
            if recomputed != envelope.entry_hash:
                if envelope.entry_hash == entry_hash:
                    return VerificationResult(
                        EvidenceIntegrityState.VIOLATED,
                        "Content hash does not match stored entry_hash "
                        "(event has been modified since signing).",
                    )
                return VerificationResult(
                    EvidenceIntegrityState.VIOLATED,
                    f"Earlier entry {envelope.entry_hash[:12]} has corrupt content hash.",
                )

            expected_prev = envelope.entry_hash

            if envelope.entry_hash == entry_hash:
                producer = _producer_of(envelope.event)
                signature_bytes = bytes.fromhex(envelope.signature)
                signed_payload = bytes.fromhex(envelope.entry_hash)
                ok = crypto.verify(
                    signed_payload,
                    signature_bytes,
                    producer=producer,
                    key_dir=self._key_dir,
                    key_id=envelope.signer_key_id,
                )
                if not ok:
                    return VerificationResult(
                        EvidenceIntegrityState.DEGRADED,
                        f"Hash and chain valid, but signer's key "
                        f"{envelope.signer_key_id} for producer "
                        f"'{producer}' is unavailable or the signature doesn't verify.",
                    )

                # Signature verifies. Now check the key's lifecycle for
                # revocation — a signature made before the key was
                # revoked is still PROVEN; one made at or after the
                # revocation timestamp is VIOLATED.
                lifecycle = crypto.read_lifecycle(producer, key_dir=self._key_dir)
                record = lifecycle.find(envelope.signer_key_id)
                if (
                    record is not None
                    and record.status == KeyStatus.REVOKED
                    and record.revoked_at is not None
                    and envelope.signed_at >= record.revoked_at
                ):
                    return VerificationResult(
                        EvidenceIntegrityState.VIOLATED,
                        f"Signer key {envelope.signer_key_id} was revoked at "
                        f"{record.revoked_at.isoformat()} "
                        f"({record.revoked_reason or 'no reason given'}); "
                        f"this entry was signed at or after revocation.",
                    )
                return VerificationResult(
                    EvidenceIntegrityState.PROVEN,
                    f"Hash, chain, and signature all valid for producer '{producer}'.",
                )

        return VerificationResult(
            EvidenceIntegrityState.VIOLATED,
            f"No entry found with entry_hash {entry_hash[:12]}.",
        )
