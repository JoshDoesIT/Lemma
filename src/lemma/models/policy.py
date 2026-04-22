"""Policy event model — auditable record of policy configuration changes.

Policy events capture changes to governance-relevant configuration (e.g.,
confidence-gated automation thresholds) so that changes in automation
behavior are independently reviewable, separate from individual AI
decision traces.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class PolicyEventType(StrEnum):
    """Discriminator for the kind of policy change recorded."""

    THRESHOLD_SET = "threshold_set"
    THRESHOLD_CHANGED = "threshold_changed"
    THRESHOLD_REMOVED = "threshold_removed"


class PolicyEvent(BaseModel):
    """A single auditable policy configuration change.

    Attributes:
        event_id: Unique identifier.
        timestamp: UTC timestamp of when the change was recorded.
        event_type: The kind of change (set, changed, removed).
        operation: The operation whose policy changed (e.g., ``"map"``).
        previous_value: Prior threshold, or None if newly set.
        new_value: New threshold, or None if removed.
        source: Free-form origin indicator (e.g., config file path).
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: PolicyEventType
    operation: str
    previous_value: float | None = None
    new_value: float | None = None
    source: str = ""
