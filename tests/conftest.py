"""Shared pytest fixtures for Lemma's test suite."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture
def lemma_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An initialized Lemma project with nist-csf-2.0 indexed.

    Runs `lemma init` in a fresh tmp_path and indexes the smallest
    bundled OSCAL catalog so tests get a realistic starting state
    without the 10 MB nist-800-53 catalog's overhead. The working
    directory is set to ``tmp_path`` for the duration of the test.

    Returns the project root (same as ``tmp_path``).
    """
    from lemma.cli import app
    from lemma.services.framework import add_bundled_framework

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.stdout

    # Remove the default policies/README so tests can decide whether
    # any policies exist without accidentally mapping against scaffolding.
    readme = tmp_path / "policies" / "README.md"
    if readme.exists():
        readme.unlink()

    add_bundled_framework(name="nist-csf-2.0", project_dir=tmp_path)

    return tmp_path
