"""Append-only policy event log — tamper-evident record of config changes.

Mirrors the shape of the AI trace log: strictly append-only JSONL files
partitioned by UTC date. Stored at ``.lemma/policy-events/YYYY-MM-DD.jsonl``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from lemma.models.policy import PolicyEvent


class PolicyEventLog:
    """Append-only log of policy configuration events."""

    def __init__(self, log_dir: Path) -> None:
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def _log_file(self, dt: datetime | None = None) -> Path:
        if dt is None:
            dt = datetime.now(UTC)
        return self._log_dir / f"{dt.strftime('%Y-%m-%d')}.jsonl"

    def append(self, event: PolicyEvent) -> None:
        """Append a policy event to the log."""
        log_file = self._log_file(event.timestamp)
        with log_file.open("a") as f:
            f.write(event.model_dump_json() + "\n")

    def read_all(self) -> list[PolicyEvent]:
        """Return every event in chronological (file, line) order."""
        events: list[PolicyEvent] = []
        for log_file in sorted(self._log_dir.glob("*.jsonl")):
            for line in log_file.read_text().strip().splitlines():
                if line.strip():
                    events.append(PolicyEvent.model_validate_json(line))
        return events

    def latest_threshold(self, operation: str) -> float | None:
        """Return the most recently recorded threshold for ``operation``.

        Scans events newest-to-oldest and returns the ``new_value`` of the
        first matching entry (which may be ``None`` if the threshold was
        most recently removed). If the operation has no recorded events,
        returns ``None``.
        """
        for event in reversed(self.read_all()):
            if event.operation == operation:
                return event.new_value
        return None
