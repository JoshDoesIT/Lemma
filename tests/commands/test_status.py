"""Tests for the `lemma status` command.

TDD RED phase: these tests define the expected behavior before implementation.
"""

from typer.testing import CliRunner

runner = CliRunner()


class TestLemmaStatus:
    """Tests for the `lemma status` command."""

    def test_status_in_initialized_project(self, tmp_path, monkeypatch):
        """Status in an initialized project outputs a compliance summary."""
        monkeypatch.chdir(tmp_path)
        from lemma.cli import app

        # First init
        runner.invoke(app, ["init"])
        # Then status
        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "framework" in result.stdout.lower()

    def test_status_in_non_initialized_directory(self, tmp_path, monkeypatch):
        """Status in a non-initialized directory gives a clear error."""
        monkeypatch.chdir(tmp_path)
        from lemma.cli import app

        result = runner.invoke(app, ["status"])

        assert result.exit_code != 0
        stdout = result.stdout.lower()
        assert "not a lemma project" in stdout or "lemma init" in stdout
