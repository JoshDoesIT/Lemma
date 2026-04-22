"""Lemma project configuration loader and schema.

Parses ``lemma.config.yaml`` and exposes validated config objects
for use by the CLI commands and services.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from lemma.models.policy import PolicyEvent, PolicyEventType
from lemma.services.policy_log import PolicyEventLog


class AutomationConfig(BaseModel):
    """Confidence-gated automation configuration.

    Per-operation confidence thresholds. When an AI operation emits a
    trace with confidence greater than or equal to the configured
    threshold, the mapper auto-accepts it (status promoted to ACCEPTED
    with ``auto_accepted=True``). Operations without a threshold entry
    are never auto-accepted and remain PROPOSED for human review.

    Attributes:
        thresholds: Mapping of operation name (e.g., ``"map"``) to the
            confidence threshold in the range 0.0-1.0.
    """

    thresholds: dict[str, float] = Field(default_factory=dict)

    @field_validator("thresholds")
    @classmethod
    def _validate_thresholds(cls, value: dict[str, float]) -> dict[str, float]:
        for operation, threshold in value.items():
            if not 0.0 <= threshold <= 1.0:
                msg = (
                    f"Automation threshold for operation '{operation}' must be "
                    f"between 0.0 and 1.0 (got {threshold})."
                )
                raise ValueError(msg)
        return value

    def threshold_for(self, operation: str) -> float | None:
        """Return the configured threshold for an operation, or None if unset."""
        return self.thresholds.get(operation)


def load_automation_config(config_file: Path) -> AutomationConfig:
    """Load and validate the automation config block from ``lemma.config.yaml``.

    Returns an empty ``AutomationConfig`` (no auto-accept) if the file
    does not exist or if the ``ai.automation`` block is absent.

    Args:
        config_file: Path to ``lemma.config.yaml``.

    Returns:
        A validated ``AutomationConfig``.

    Raises:
        ValueError: If any threshold is outside the 0.0-1.0 range.
    """
    if not config_file.exists():
        return AutomationConfig()

    raw = yaml.safe_load(config_file.read_text()) or {}
    automation_block = raw.get("ai", {}).get("automation", {}) or {}
    return AutomationConfig(**automation_block)


def record_threshold_changes(
    config: AutomationConfig,
    policy_log: PolicyEventLog,
    source: str = "",
) -> list[PolicyEvent]:
    """Diff ``config`` against the most recent recorded thresholds and append events.

    For each operation currently configured, emits ``THRESHOLD_SET`` if there
    is no prior recorded value or ``THRESHOLD_CHANGED`` if the value differs.
    For each operation with a prior non-None recorded value that is no longer
    configured, emits ``THRESHOLD_REMOVED``. Operations whose current and prior
    values match produce no event.

    Args:
        config: The currently-loaded automation configuration.
        policy_log: Append-only log to write change events to.
        source: Optional provenance string (e.g. the config file path) recorded
            on every emitted event.

    Returns:
        The list of events appended this call, in the order they were written.
    """
    emitted: list[PolicyEvent] = []
    current = config.thresholds

    # Operations previously recorded but absent now, so we can flag removals.
    prior_ops = {event.operation for event in policy_log.read_all()}
    for operation in sorted(set(current) | prior_ops):
        previous = policy_log.latest_threshold(operation)
        new = current.get(operation)

        if previous == new:
            continue

        if previous is None:
            event_type = PolicyEventType.THRESHOLD_SET
        elif new is None:
            event_type = PolicyEventType.THRESHOLD_REMOVED
        else:
            event_type = PolicyEventType.THRESHOLD_CHANGED

        event = PolicyEvent(
            event_type=event_type,
            operation=operation,
            previous_value=previous,
            new_value=new,
            source=source,
        )
        policy_log.append(event)
        emitted.append(event)

    return emitted
