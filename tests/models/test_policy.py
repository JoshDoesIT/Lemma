"""Tests for the PolicyEvent model — auditable record of policy config changes."""

from __future__ import annotations

import json


def test_policy_event_requires_event_type_and_operation():
    from lemma.models.policy import PolicyEvent, PolicyEventType

    event = PolicyEvent(
        event_type=PolicyEventType.THRESHOLD_SET,
        operation="map",
        previous_value=None,
        new_value=0.85,
    )

    assert event.event_type == PolicyEventType.THRESHOLD_SET
    assert event.operation == "map"
    assert event.previous_value is None
    assert event.new_value == 0.85
    assert event.event_id
    assert event.timestamp is not None


def test_policy_event_serializes_to_json():
    from lemma.models.policy import PolicyEvent, PolicyEventType

    event = PolicyEvent(
        event_type=PolicyEventType.THRESHOLD_CHANGED,
        operation="map",
        previous_value=0.80,
        new_value=0.95,
    )
    data = json.loads(event.model_dump_json())

    assert data["event_type"] == "threshold_changed"
    assert data["operation"] == "map"
    assert data["previous_value"] == 0.80
    assert data["new_value"] == 0.95
    assert "event_id" in data
    assert "timestamp" in data


def test_policy_event_type_enum_has_three_transitions():
    from lemma.models.policy import PolicyEventType

    assert PolicyEventType.THRESHOLD_SET.value == "threshold_set"
    assert PolicyEventType.THRESHOLD_CHANGED.value == "threshold_changed"
    assert PolicyEventType.THRESHOLD_REMOVED.value == "threshold_removed"
