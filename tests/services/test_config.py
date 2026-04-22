"""Tests for the project config loader and automation schema."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lemma.services.config import AutomationConfig, load_automation_config


class TestAutomationConfig:
    """Tests for the AutomationConfig Pydantic model."""

    def test_empty_config_has_no_thresholds(self):
        config = AutomationConfig()
        assert config.thresholds == {}
        assert config.threshold_for("map") is None

    def test_threshold_for_returns_configured_value(self):
        config = AutomationConfig(thresholds={"map": 0.8, "harmonize": 0.9})
        assert config.threshold_for("map") == 0.8
        assert config.threshold_for("harmonize") == 0.9
        assert config.threshold_for("unknown") is None

    def test_threshold_boundaries_are_inclusive(self):
        AutomationConfig(thresholds={"map": 0.0})
        AutomationConfig(thresholds={"map": 1.0})

    def test_threshold_above_one_rejected(self):
        with pytest.raises(ValueError, match=r"between 0\.0 and 1\.0"):
            AutomationConfig(thresholds={"map": 1.5})

    def test_threshold_below_zero_rejected(self):
        with pytest.raises(ValueError, match=r"between 0\.0 and 1\.0"):
            AutomationConfig(thresholds={"map": -0.1})

    def test_operation_name_is_preserved_in_error(self):
        with pytest.raises(ValueError, match="harmonize"):
            AutomationConfig(thresholds={"harmonize": 2.0})


class TestLoadAutomationConfig:
    """Tests for loading automation config from lemma.config.yaml."""

    def test_missing_file_returns_empty_config(self, tmp_path: Path):
        config = load_automation_config(tmp_path / "missing.yaml")
        assert config.thresholds == {}

    def test_missing_automation_block_returns_empty_config(self, tmp_path: Path):
        config_file = tmp_path / "lemma.config.yaml"
        config_file.write_text(yaml.dump({"ai": {"provider": "ollama"}}))

        config = load_automation_config(config_file)
        assert config.thresholds == {}

    def test_loads_per_operation_thresholds(self, tmp_path: Path):
        config_file = tmp_path / "lemma.config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "ai": {
                        "automation": {
                            "thresholds": {"map": 0.85, "harmonize": 0.95},
                        }
                    }
                }
            )
        )

        config = load_automation_config(config_file)
        assert config.threshold_for("map") == 0.85
        assert config.threshold_for("harmonize") == 0.95

    def test_invalid_threshold_raises_on_load(self, tmp_path: Path):
        config_file = tmp_path / "lemma.config.yaml"
        config_file.write_text(yaml.dump({"ai": {"automation": {"thresholds": {"map": 1.7}}}}))

        with pytest.raises(ValueError, match=r"between 0\.0 and 1\.0"):
            load_automation_config(config_file)


class TestRecordThresholdChanges:
    """Tests for the automation-config → policy-event diff function."""

    def test_first_configured_threshold_emits_threshold_set(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig, record_threshold_changes
        from lemma.services.policy_log import PolicyEventLog

        log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
        emitted = record_threshold_changes(AutomationConfig(thresholds={"map": 0.85}), log)

        assert len(emitted) == 1
        event = emitted[0]
        assert event.event_type.value == "threshold_set"
        assert event.operation == "map"
        assert event.previous_value is None
        assert event.new_value == 0.85
        assert log.latest_threshold("map") == 0.85

    def test_unchanged_threshold_emits_nothing(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig, record_threshold_changes
        from lemma.services.policy_log import PolicyEventLog

        log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
        record_threshold_changes(AutomationConfig(thresholds={"map": 0.85}), log)
        emitted = record_threshold_changes(AutomationConfig(thresholds={"map": 0.85}), log)

        assert emitted == []
        assert len(log.read_all()) == 1

    def test_changed_threshold_emits_threshold_changed(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig, record_threshold_changes
        from lemma.services.policy_log import PolicyEventLog

        log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
        record_threshold_changes(AutomationConfig(thresholds={"map": 0.85}), log)
        emitted = record_threshold_changes(AutomationConfig(thresholds={"map": 0.95}), log)

        assert len(emitted) == 1
        event = emitted[0]
        assert event.event_type.value == "threshold_changed"
        assert event.operation == "map"
        assert event.previous_value == 0.85
        assert event.new_value == 0.95

    def test_removed_threshold_emits_threshold_removed(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig, record_threshold_changes
        from lemma.services.policy_log import PolicyEventLog

        log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
        record_threshold_changes(AutomationConfig(thresholds={"map": 0.85}), log)
        emitted = record_threshold_changes(AutomationConfig(), log)

        assert len(emitted) == 1
        event = emitted[0]
        assert event.event_type.value == "threshold_removed"
        assert event.operation == "map"
        assert event.previous_value == 0.85
        assert event.new_value is None

    def test_source_is_recorded_on_emitted_events(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig, record_threshold_changes
        from lemma.services.policy_log import PolicyEventLog

        log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
        emitted = record_threshold_changes(
            AutomationConfig(thresholds={"map": 0.85}),
            log,
            source="lemma.config.yaml",
        )
        assert emitted[0].source == "lemma.config.yaml"

    def test_multiple_ops_diffed_independently(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig, record_threshold_changes
        from lemma.services.policy_log import PolicyEventLog

        log = PolicyEventLog(log_dir=tmp_path / ".lemma" / "policy-events")
        record_threshold_changes(
            AutomationConfig(thresholds={"map": 0.80, "harmonize": 0.90}),
            log,
        )
        emitted = record_threshold_changes(
            AutomationConfig(thresholds={"map": 0.85, "harmonize": 0.90}),
            log,
        )

        assert len(emitted) == 1
        assert emitted[0].operation == "map"
        assert emitted[0].event_type.value == "threshold_changed"
