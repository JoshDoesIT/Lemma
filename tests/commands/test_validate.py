"""Tests for the `lemma validate` command.

TDD RED phase: these tests define the expected behavior before implementation.
"""

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestLemmaValidate:
    """Tests for the `lemma validate` command."""

    def test_validate_valid_catalog(self):
        """Valid OSCAL catalog file returns exit code 0."""
        from lemma.cli import app

        result = runner.invoke(app, ["validate", str(FIXTURES_DIR / "valid_catalog.json")])
        assert result.exit_code == 0
        assert "valid" in result.stdout.lower()

    def test_validate_invalid_catalog(self):
        """Invalid OSCAL file returns exit code 1 with descriptive errors."""
        from lemma.cli import app

        result = runner.invoke(app, ["validate", str(FIXTURES_DIR / "invalid_catalog.json")])
        assert result.exit_code != 0
        assert "error" in result.stdout.lower() or "invalid" in result.stdout.lower()

    def test_validate_nonexistent_file(self):
        """Validating a nonexistent file returns exit code 1."""
        from lemma.cli import app

        result = runner.invoke(app, ["validate", "/tmp/does_not_exist.json"])
        assert result.exit_code != 0
