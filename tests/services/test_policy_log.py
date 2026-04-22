"""Tests for the append-only PolicyEventLog."""

from __future__ import annotations

import json
from pathlib import Path


def test_append_writes_event_to_file(tmp_path: Path):
    from lemma.models.policy import PolicyEvent, PolicyEventType
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
    event = PolicyEvent(
        event_type=PolicyEventType.THRESHOLD_SET,
        operation="map",
        new_value=0.85,
    )
    log.append(event)

    files = list((tmp_path / ".lemma" / "policy-events").glob("*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["operation"] == "map"
    assert entry["event_type"] == "threshold_set"


def test_read_all_returns_events_in_order(tmp_path: Path):
    from lemma.models.policy import PolicyEvent, PolicyEventType
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")

    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_SET,
            operation="map",
            new_value=0.80,
        )
    )
    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_CHANGED,
            operation="map",
            previous_value=0.80,
            new_value=0.95,
        )
    )

    events = log.read_all()
    assert len(events) == 2
    assert events[0].event_type.value == "threshold_set"
    assert events[1].event_type.value == "threshold_changed"


def test_policy_log_is_append_only(tmp_path: Path):
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
    assert not hasattr(log, "update")
    assert not hasattr(log, "delete")
    assert not hasattr(log, "clear")


def test_latest_threshold_returns_none_when_no_events(tmp_path: Path):
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
    assert log.latest_threshold("map") is None


def test_latest_threshold_returns_new_value_of_most_recent_event(tmp_path: Path):
    from lemma.models.policy import PolicyEvent, PolicyEventType
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")

    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_SET,
            operation="map",
            new_value=0.80,
        )
    )
    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_CHANGED,
            operation="map",
            previous_value=0.80,
            new_value=0.95,
        )
    )

    assert log.latest_threshold("map") == 0.95


def test_latest_threshold_after_removal_is_none(tmp_path: Path):
    from lemma.models.policy import PolicyEvent, PolicyEventType
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")

    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_SET,
            operation="map",
            new_value=0.80,
        )
    )
    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_REMOVED,
            operation="map",
            previous_value=0.80,
            new_value=None,
        )
    )

    assert log.latest_threshold("map") is None


def test_latest_threshold_isolated_by_operation(tmp_path: Path):
    from lemma.models.policy import PolicyEvent, PolicyEventType
    from lemma.services.policy_log import PolicyEventLog

    log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")

    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_SET,
            operation="map",
            new_value=0.80,
        )
    )
    log.append(
        PolicyEvent(
            event_type=PolicyEventType.THRESHOLD_SET,
            operation="harmonize",
            new_value=0.90,
        )
    )

    assert log.latest_threshold("map") == 0.80
    assert log.latest_threshold("harmonize") == 0.90
    assert log.latest_threshold("nonexistent") is None
