"""Append-only AI trace log — tamper-evident audit trail.

Stores AITrace records as newline-delimited JSON (JSONL) files,
organized by date. The log is strictly append-only: there are no
update, delete, or clear operations.

File layout:
    .lemma/traces/
        2026-04-21.jsonl
        2026-04-22.jsonl
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from lemma.models.trace import AITrace, TraceStatus


class TraceLog:
    """Append-only trace log for AI decision audit trail.

    Args:
        log_dir: Directory where JSONL trace files are stored.
    """

    def __init__(self, log_dir: Path) -> None:
        """Initialize the trace log.

        Args:
            log_dir: Path to the trace log directory.
        """
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def _log_file(self, dt: datetime | None = None) -> Path:
        """Get the log file path for a given date.

        Args:
            dt: Datetime to determine the file. Defaults to now (UTC).

        Returns:
            Path to the JSONL log file.
        """
        if dt is None:
            dt = datetime.now(UTC)
        return self._log_dir / f"{dt.strftime('%Y-%m-%d')}.jsonl"

    def append(self, trace: AITrace) -> None:
        """Append a trace entry to the log.

        Args:
            trace: The AITrace record to persist.
        """
        log_file = self._log_file(trace.timestamp)
        with log_file.open("a") as f:
            f.write(trace.model_dump_json() + "\n")

    def read_all(self) -> list[AITrace]:
        """Read all trace entries from all log files.

        Returns:
            List of AITrace records, ordered by file then line.
        """
        traces: list[AITrace] = []
        for log_file in sorted(self._log_dir.glob("*.jsonl")):
            for line in log_file.read_text().strip().splitlines():
                if line.strip():
                    traces.append(AITrace.model_validate_json(line))
        return traces

    def filter_by_model(self, model_id: str) -> list[AITrace]:
        """Return traces produced by a specific model.

        Args:
            model_id: Model identifier to filter by.

        Returns:
            List of matching AITrace records.
        """
        return [t for t in self.read_all() if t.model_id == model_id]

    def filter_by_operation(self, operation: str) -> list[AITrace]:
        """Return traces of a specific operation type.

        Args:
            operation: Operation type to filter by (e.g., 'map').

        Returns:
            List of matching AITrace records.
        """
        return [t for t in self.read_all() if t.operation == operation]

    def review(
        self,
        trace_id: str,
        *,
        status: TraceStatus,
        rationale: str = "",
    ) -> None:
        """Record a human review decision for a trace.

        Creates a new trace entry linked to the original via parent_trace_id.
        This preserves the append-only property - the original is never modified.

        Args:
            trace_id: The trace_id of the entry being reviewed.
            status: The new review status (ACCEPTED or REJECTED).
            rationale: Required rationale for REJECTED status.

        Raises:
            ValueError: If rejecting without a rationale.
            ValueError: If the trace_id is not found.
        """
        if status == TraceStatus.REJECTED and not rationale:
            msg = "Rationale is required when rejecting an AI determination."
            raise ValueError(msg)

        # Find the original trace
        original = None
        for trace in self.read_all():
            if trace.trace_id == trace_id:
                original = trace
                break

        if original is None:
            msg = f"Trace ID '{trace_id}' not found in log."
            raise ValueError(msg)

        # Create a review entry linked to the original
        review_entry = AITrace(
            operation=original.operation,
            input_text=original.input_text,
            prompt=original.prompt,
            model_id=original.model_id,
            model_version=original.model_version,
            raw_output=original.raw_output,
            confidence=original.confidence,
            determination=original.determination,
            control_id=original.control_id,
            framework=original.framework,
            status=status,
            review_rationale=rationale,
            parent_trace_id=trace_id,
        )

        self.append(review_entry)

    def auto_accept(self, original: AITrace, *, threshold: float) -> AITrace:
        """Append an ACCEPTED review entry produced by confidence gating.

        Used by confidence-gated automation: when an AI output's confidence
        is at or above a configured threshold, the mapper calls this to
        promote the original PROPOSED trace to ACCEPTED without human review.
        The review entry records the threshold that was applied and carries
        ``auto_accepted=True`` so it is auditable as policy-driven rather
        than human-driven.

        Args:
            original: The PROPOSED trace being auto-accepted.
            threshold: The configured threshold that was met.

        Returns:
            The appended review entry.
        """
        rationale = (
            f"Auto-accepted by confidence gate: "
            f"confidence {original.confidence:.3f} >= threshold {threshold:.3f} "
            f"for operation '{original.operation}'."
        )
        review_entry = AITrace(
            operation=original.operation,
            input_text=original.input_text,
            prompt=original.prompt,
            model_id=original.model_id,
            model_version=original.model_version,
            raw_output=original.raw_output,
            confidence=original.confidence,
            determination=original.determination,
            control_id=original.control_id,
            framework=original.framework,
            status=TraceStatus.ACCEPTED,
            review_rationale=rationale,
            parent_trace_id=original.trace_id,
            auto_accepted=True,
        )
        self.append(review_entry)
        return review_entry
