"""Tests for harmonization CLI commands.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def test_harmonize_persists_oscal_profile_to_disk(lemma_project: Path, monkeypatch):
    """`lemma harmonize` writes an OSCAL Profile to .lemma/harmonization.oscal.json."""
    from lemma.cli import app
    from lemma.models.oscal import Profile
    from lemma.services.framework import add_bundled_framework

    monkeypatch.chdir(lemma_project)
    # lemma_project indexes nist-csf-2.0; add nist-800-171 to get two frameworks
    add_bundled_framework(name="nist-800-171", project_dir=lemma_project)

    result = runner.invoke(app, ["harmonize", "--threshold", "0.5"])
    assert result.exit_code == 0, result.stdout

    profile_path = lemma_project / ".lemma" / "harmonization.oscal.json"
    assert profile_path.is_file(), "Profile was not written"

    payload = json.loads(profile_path.read_text())
    # OSCAL kebab-case on the wire
    assert "back-matter" in payload
    # Round-trips as a valid Profile
    profile = Profile.model_validate_json(profile_path.read_text())
    assert len(profile.imports) == 2


class TestHarmonizeCommand:
    """Tests for `lemma harmonize`."""

    def test_harmonize_not_initialized(self, tmp_path):
        """Harmonizing in a non-Lemma directory fails."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["harmonize"])
            assert result.exit_code == 1
            assert (
                "not a lemma project" in result.stdout.lower()
                or "lemma init" in result.stdout.lower()
            )

    def test_harmonize_no_frameworks(self, tmp_path):
        """Harmonizing without indexed frameworks fails."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(app, ["init"])
            result = runner.invoke(app, ["harmonize"])
            assert result.exit_code == 1
            stdout = result.stdout.lower()
            assert "no" in stdout and "framework" in stdout

    def test_harmonize_success(self, tmp_path, monkeypatch):
        """Successful harmonization produces JSON output."""
        from lemma.cli import app
        from lemma.services.indexer import ControlIndexer

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])

        index_dir = (tmp_path / ".lemma" / "index").resolve()
        indexer = ControlIndexer(index_dir=index_dir)
        indexer.index_controls(
            "fw-a",
            [{"id": "a-1", "title": "Access Control", "prose": "Control access.", "family": "AC"}],
        )
        indexer.index_controls(
            "fw-b",
            [
                {
                    "id": "b-1",
                    "title": "Access Management",
                    "prose": "Manage access.",
                    "family": "AC",
                }
            ],
        )
        del indexer

        result = runner.invoke(app, ["harmonize"])
        assert result.exit_code == 0
        assert "cluster" in result.stdout.lower() or "harmoniz" in result.stdout.lower()


class TestCoverageCommand:
    """Tests for `lemma coverage`."""

    def test_coverage_success(self, tmp_path, monkeypatch):
        """Coverage command produces per-framework statistics."""
        from lemma.cli import app
        from lemma.services.indexer import ControlIndexer

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])

        index_dir = (tmp_path / ".lemma" / "index").resolve()
        indexer = ControlIndexer(index_dir=index_dir)
        indexer.index_controls(
            "fw-a",
            [{"id": "a-1", "title": "Access Control", "prose": "Control access.", "family": "AC"}],
        )
        indexer.index_controls(
            "fw-b",
            [{"id": "b-1", "title": "Audit Logging", "prose": "Log events.", "family": "AU"}],
        )
        del indexer

        result = runner.invoke(app, ["coverage"])
        assert result.exit_code == 0
        stdout = result.stdout.lower()
        assert "fw-a" in stdout or "coverage" in stdout


class TestGapsCommand:
    """Tests for `lemma gaps`."""

    def test_gaps_success(self, tmp_path, monkeypatch):
        """Gaps command lists unmapped controls."""
        from lemma.cli import app
        from lemma.services.indexer import ControlIndexer

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])

        index_dir = (tmp_path / ".lemma" / "index").resolve()
        indexer = ControlIndexer(index_dir=index_dir)
        indexer.index_controls(
            "fw-a",
            [
                {
                    "id": "a-1",
                    "title": "Access Control",
                    "prose": "Control access.",
                    "family": "AC",
                },
                {"id": "a-2", "title": "Audit Logging", "prose": "Log events.", "family": "AU"},
            ],
        )
        indexer.index_controls(
            "fw-b",
            [
                {
                    "id": "b-1",
                    "title": "Access Management",
                    "prose": "Manage access.",
                    "family": "AC",
                }
            ],
        )
        del indexer

        result = runner.invoke(app, ["gaps", "--framework", "fw-a"])
        assert result.exit_code == 0


class TestDiffCommand:
    """Tests for `lemma diff`."""

    def test_diff_success(self, tmp_path, monkeypatch):
        """Diff command shows changes between framework versions."""
        from lemma.cli import app
        from lemma.services.indexer import ControlIndexer

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])

        index_dir = (tmp_path / ".lemma" / "index").resolve()
        indexer = ControlIndexer(index_dir=index_dir)
        indexer.index_controls(
            "fw-v1",
            [{"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"}],
        )
        indexer.index_controls(
            "fw-v2",
            [
                {"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"},
                {"id": "ac-22", "title": "New Control", "prose": "New.", "family": "AC"},
            ],
        )
        del indexer

        result = runner.invoke(app, ["diff", "--from", "fw-v1", "--to", "fw-v2"])
        assert result.exit_code == 0
        assert "ac-22" in result.stdout.lower() or "added" in result.stdout.lower()
