"""Tests for `lemma connector validate` (Refs #34, #109)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.cli import app

_VALID = {
    "name": "acme-okta",
    "version": "1.2.0",
    "producer": "Acme",
    "description": "Acme Okta posture.",
    "capabilities": ["mfa-policy", "sso-apps"],
}


def _write(tmp_path: Path, data, name="manifest.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data) if isinstance(data, dict) else data)
    return path


def test_valid_manifest_exits_zero(tmp_path):
    manifest = _write(tmp_path, _VALID)
    result = CliRunner().invoke(app, ["connector", "validate", str(manifest)])
    assert result.exit_code == 0, result.stdout
    assert "valid" in result.stdout.lower()


def test_invalid_version_exits_one_and_lists_error(tmp_path):
    manifest = _write(tmp_path, {**_VALID, "version": "v1.2"})
    result = CliRunner().invoke(app, ["connector", "validate", str(manifest)])
    assert result.exit_code == 1
    assert "version" in result.stdout.lower()


def test_missing_file_exits_one(tmp_path):
    result = CliRunner().invoke(app, ["connector", "validate", str(tmp_path / "nope.json")])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_malformed_manifest_exits_one(tmp_path):
    bad = _write(tmp_path, "name: [unterminated\n", name="bad.yaml")
    result = CliRunner().invoke(app, ["connector", "validate", str(bad)])
    assert result.exit_code == 1


def test_yaml_manifest_is_accepted(tmp_path):
    yaml_text = "name: acme-okta\nversion: 1.2.0\nproducer: Acme\ncapabilities:\n  - mfa-policy\n"
    manifest = _write(tmp_path, yaml_text, name="manifest.yaml")
    result = CliRunner().invoke(app, ["connector", "validate", str(manifest)])
    assert result.exit_code == 0, result.stdout
