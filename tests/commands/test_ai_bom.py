"""Tests for `lemma ai bom` CLI command."""

from __future__ import annotations

import json

from typer.testing import CliRunner

runner = CliRunner()


def test_ai_bom_runs_outside_a_lemma_project(tmp_path):
    """The AIBOM is built from hardcoded System Card data — should run anywhere.

    Required by release CI: `lemma ai bom` is invoked at tag time without
    a project checkout, so demanding `.lemma/` would force an awkward
    `lemma init` dance for output that reads no project state.
    """
    from lemma.cli import app

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(app, ["ai", "bom"])
        assert result.exit_code == 0, result.stdout
        bom = json.loads(result.stdout)
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"


def test_ai_bom_emits_valid_cyclonedx_json(tmp_path):
    from lemma.cli import app

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(app, ["ai", "bom"])

    assert result.exit_code == 0, result.stdout
    bom = json.loads(result.stdout)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert len(bom["components"]) >= 1
    assert bom["components"][0]["type"] == "machine-learning-model"


def test_ai_bom_output_passes_validator(tmp_path):
    from lemma.cli import app
    from lemma.services.aibom import validate_aibom

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(app, ["ai", "bom"])

    assert result.exit_code == 0
    validate_aibom(json.loads(result.stdout))
