"""Tests for the connector configuration loader (Refs #116).

A `lemma_connector_config.yaml` file lives next to a connector project
and captures connector configuration distinctly from code, so operators
can reconfigure a connector without editing Python.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_load_connector_config_minimal_yaml(tmp_path: Path) -> None:
    """A minimal config with just `connector` and `config` loads."""
    from lemma.services.connector_config import load_connector_config

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text("connector: github\nconfig:\n  repo: octocat/Hello-World\n")
    cfg = load_connector_config(cfg_path)
    assert cfg.connector == "github"
    assert cfg.config == {"repo": "octocat/Hello-World"}
    assert cfg.enabled is True  # default
    assert cfg.producer == ""  # default empty (caller substitutes project producer)
    assert cfg.schedule == ""  # default


def test_load_connector_config_full_shape(tmp_path: Path) -> None:
    from lemma.services.connector_config import load_connector_config

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text(
        "producer: Lemma\n"
        "enabled: true\n"
        "schedule: '0 */6 * * *'\n"
        "connector: okta\n"
        "config:\n"
        "  domain: acme.okta.com\n"
        "  page_size: 100\n"
    )
    cfg = load_connector_config(cfg_path)
    assert cfg.producer == "Lemma"
    assert cfg.schedule == "0 */6 * * *"
    assert cfg.connector == "okta"
    assert cfg.config == {"domain": "acme.okta.com", "page_size": 100}


def test_load_connector_config_interpolates_env_vars(tmp_path: Path, monkeypatch) -> None:
    """`${ENV_VAR}` in string values is replaced by the environment
    variable's value at load time. Sensitive fields (tokens) live in
    env vars, not in the YAML."""
    from lemma.services.connector_config import load_connector_config

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_xyz")
    monkeypatch.setenv("GITHUB_REPO", "octocat/Hello-World")

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text(
        "connector: github\nconfig:\n  repo: ${GITHUB_REPO}\n  token: ${GITHUB_TOKEN}\n"
    )
    cfg = load_connector_config(cfg_path)
    assert cfg.config == {
        "repo": "octocat/Hello-World",
        "token": "ghp_secret_xyz",
    }


def test_load_connector_config_unknown_env_var_raises(tmp_path: Path, monkeypatch) -> None:
    """Referencing an env var that isn't set is a load-time error
    (better to fail loudly than silently substitute empty string)."""
    from lemma.services.connector_config import load_connector_config

    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text("connector: github\nconfig:\n  token: ${DOES_NOT_EXIST}\n")
    with pytest.raises(ValueError, match="DOES_NOT_EXIST"):
        load_connector_config(cfg_path)


def test_load_connector_config_interpolates_nested_strings(tmp_path: Path, monkeypatch) -> None:
    """Env-var interpolation walks nested dicts and lists, not just the
    top level of `config`."""
    from lemma.services.connector_config import load_connector_config

    monkeypatch.setenv("AWS_REGION", "us-west-2")

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text(
        "connector: aws\n"
        "config:\n"
        "  primary:\n"
        "    region: ${AWS_REGION}\n"
        "  regions:\n"
        "    - ${AWS_REGION}\n"
        "    - us-east-1\n"
    )
    cfg = load_connector_config(cfg_path)
    assert cfg.config["primary"]["region"] == "us-west-2"
    assert cfg.config["regions"] == ["us-west-2", "us-east-1"]


def test_load_connector_config_rejects_missing_connector(tmp_path: Path) -> None:
    from lemma.services.connector_config import load_connector_config

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text("config:\n  repo: foo/bar\n")
    with pytest.raises(ValueError, match="connector"):
        load_connector_config(cfg_path)


def test_load_connector_config_rejects_missing_file(tmp_path: Path) -> None:
    from lemma.services.connector_config import load_connector_config

    with pytest.raises(FileNotFoundError):
        load_connector_config(tmp_path / "missing.yaml")


def test_load_connector_config_rejects_extra_top_level_keys(tmp_path: Path) -> None:
    """Strict schema — typo'd top-level keys surface immediately."""
    from lemma.services.connector_config import load_connector_config

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text(
        "connector: github\n"
        "config:\n"
        "  repo: foo/bar\n"
        "schedules: '0 0 * * *'\n"  # typo: should be `schedule`
    )
    with pytest.raises(ValueError, match="schedules"):
        load_connector_config(cfg_path)


def test_load_connector_config_rejects_invalid_yaml(tmp_path: Path) -> None:
    from lemma.services.connector_config import load_connector_config

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text("this is: : not valid: yaml\n")
    with pytest.raises(ValueError):
        load_connector_config(cfg_path)


def test_load_connector_config_disabled_skips_loading_into_run(tmp_path: Path) -> None:
    """`enabled: false` is preserved in the loaded config; consumers
    decide what to do with it. The test guards round-trip preservation."""
    from lemma.services.connector_config import load_connector_config

    cfg_path = tmp_path / "lemma_connector_config.yaml"
    cfg_path.write_text("connector: github\nenabled: false\nconfig:\n  repo: foo/bar\n")
    cfg = load_connector_config(cfg_path)
    assert cfg.enabled is False
