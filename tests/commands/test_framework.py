"""Tests for the `lemma framework` CLI commands.

Follows TDD: tests written BEFORE the implementation.
Validates CLI routing, output formatting, and error handling.
"""

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


class TestFrameworkAddCommand:
    """Tests for `lemma framework add <name>`."""

    def test_framework_add_success(self, tmp_path):
        """Successfully adding a framework reports the control count."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            # Initialize first
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0

            # Add framework
            result = runner.invoke(app, ["framework", "add", "nist-800-53"])
            assert result.exit_code == 0
            assert "nist-800-53" in result.stdout
            assert "controls" in result.stdout.lower() or "indexed" in result.stdout.lower()

    def test_framework_add_not_initialized(self, tmp_path):
        """Adding a framework in a non-Lemma directory fails with error."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["framework", "add", "nist-800-53"])
            assert result.exit_code == 1
            stdout = result.stdout.lower()
            assert "not a lemma project" in stdout or "lemma init" in stdout

    def test_framework_add_unknown(self, tmp_path):
        """Adding an unknown framework name fails with error."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0

            result = runner.invoke(app, ["framework", "add", "unknown-fw"])
            assert result.exit_code == 1
            assert "unknown" in result.stdout.lower()


class TestFrameworkListCommand:
    """Tests for `lemma framework list`."""

    def test_framework_list_empty(self, tmp_path):
        """Listing frameworks with no indexed returns empty message."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0

            result = runner.invoke(app, ["framework", "list"])
            assert result.exit_code == 0
            assert "no frameworks" in result.stdout.lower() or "none" in result.stdout.lower()

    def test_framework_list_with_data(self, tmp_path):
        """Listing frameworks after indexing shows framework details."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0

            runner.invoke(app, ["framework", "add", "nist-800-53"])

            result = runner.invoke(app, ["framework", "list"])
            assert result.exit_code == 0
            assert "nist-800-53" in result.stdout


class TestFrameworkImportCommand:
    """Tests for `lemma framework import <file>`."""

    def test_framework_import_json(self, tmp_path):
        """Importing a JSON file is accepted and indexed."""
        import json

        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0

            # Create a minimal OSCAL catalog
            catalog = {
                "catalog": {
                    "uuid": "12345678-1234-1234-1234-123456789abc",
                    "metadata": {
                        "title": "My Custom FW",
                        "last-modified": "2026-01-01T00:00:00Z",
                    },
                    "groups": [
                        {
                            "id": "ac",
                            "title": "Access Control",
                            "controls": [
                                {
                                    "id": "ac-1",
                                    "title": "Policy",
                                    "parts": [
                                        {
                                            "id": "ac-1_smt",
                                            "name": "statement",
                                            "prose": "Test policy.",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
            Path("custom.json").write_text(json.dumps(catalog))

            result = runner.invoke(app, ["framework", "import", "custom.json"])
            assert result.exit_code == 0
            assert "indexed" in result.stdout.lower() or "imported" in result.stdout.lower()

    def test_framework_import_unsupported(self, tmp_path):
        """Importing an unsupported file type fails with error."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0

            Path("framework.txt").write_text("not a framework")
            result = runner.invoke(app, ["framework", "import", "framework.txt"])
            assert result.exit_code == 1
            assert "unsupported" in result.stdout.lower()

    def test_framework_import_not_initialized(self, tmp_path):
        """Importing in a non-Lemma directory fails with error."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            Path("custom.json").write_text("{}")
            result = runner.invoke(app, ["framework", "import", "custom.json"])
            assert result.exit_code == 1
