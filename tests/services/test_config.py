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
