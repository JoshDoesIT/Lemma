"""Append-only evidence log — normalized OCSF events on disk.

Stores OCSF events as newline-delimited JSON (JSONL) files partitioned
by UTC date under ``.lemma/evidence/YYYY-MM-DD.jsonl``. Polymorphic
reads are driven by the same discriminated-union ``TypeAdapter`` used
by the normalizer, so every event returned from ``read_all`` is a
concrete OCSF model (``ComplianceFinding``, ``DetectionFinding``, or
``AuthenticationEvent``).

The log is strictly append-only: no update, delete, or clear methods.
Dedupe is performed at append time against today's log file so every
stored line is unique by construction.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from lemma.models.ocsf import OcsfBaseEvent
from lemma.services.ocsf_normalizer import ocsf_adapter


def _dedupe_key(event: OcsfBaseEvent) -> str:
    """Return a stable idempotency key for ``event``.

    Prefers the producer-supplied ``metadata.uid`` (OCSF's canonical
    idempotency hint). Falls back to a SHA-256 hash over the full model
    dump when ``metadata.uid`` is absent, so retries of the same event
    still collapse without losing genuine same-second distinct events
    that carry different content.
    """
    uid = event.metadata.get("uid")
    if isinstance(uid, str) and uid:
        return f"uid:{uid}"
    digest = hashlib.sha256(event.model_dump_json().encode()).hexdigest()
    return f"hash:{digest}"


class EvidenceLog:
    """Append-only log of normalized OCSF evidence events."""

    def __init__(self, log_dir: Path) -> None:
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def _log_file(self, dt: datetime | None = None) -> Path:
        if dt is None:
            dt = datetime.now(UTC)
        return self._log_dir / f"{dt.strftime('%Y-%m-%d')}.jsonl"

    def _seen_keys_today(self, log_file: Path) -> set[str]:
        if not log_file.exists():
            return set()
        keys: set[str] = set()
        for line in log_file.read_text().strip().splitlines():
            if not line.strip():
                continue
            prior = ocsf_adapter.validate_json(line)
            keys.add(_dedupe_key(prior))
        return keys

    def append(self, event: OcsfBaseEvent) -> bool:
        """Append an event to the log.

        Returns ``True`` when a new line was written, ``False`` if the
        event was skipped by the dedupe guard (see module docstring).
        Dedupe scope is the day-partitioned file for ``event.time``.
        """
        log_file = self._log_file(event.time)
        if _dedupe_key(event) in self._seen_keys_today(log_file):
            return False
        with log_file.open("a") as f:
            f.write(event.model_dump_json() + "\n")
        return True

    def read_all(self) -> list[OcsfBaseEvent]:
        """Return every event in chronological (file, line) order."""
        events: list[OcsfBaseEvent] = []
        for log_file in sorted(self._log_dir.glob("*.jsonl")):
            for line in log_file.read_text().strip().splitlines():
                if line.strip():
                    events.append(ocsf_adapter.validate_json(line))
        return events

    def filter_by_class(self, class_uid: int) -> list[OcsfBaseEvent]:
        """Return every event with the given ``class_uid``."""
        return [e for e in self.read_all() if e.class_uid == class_uid]

    def filter_by_time_range(self, start: datetime, end: datetime) -> list[OcsfBaseEvent]:
        """Return events whose ``time`` falls in ``[start, end)`` (half-open)."""
        return [e for e in self.read_all() if start <= e.time < end]
