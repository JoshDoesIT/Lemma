"""Tests for the `lemma map` CLI command.

Follows TDD: tests written BEFORE the implementation.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

runner = CliRunner()


class TestMapCommand:
    """Tests for `lemma map`."""

    def test_map_not_initialized(self, tmp_path):
        """Mapping in a non-Lemma directory fails with error."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["map", "--framework", "nist-800-53"])
            assert result.exit_code == 1
            stdout = result.stdout.lower()
            assert "not a lemma project" in stdout or "lemma init" in stdout

    def test_map_no_framework_indexed(self, tmp_path):
        """Mapping without indexed framework fails with error."""
        from lemma.cli import app

        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(app, ["init"])
            Path("policies/test.md").write_text("# Test\n\nPolicy text.\n")

            result = runner.invoke(app, ["map", "--framework", "nist-800-53"])
            assert result.exit_code == 1
            assert "not indexed" in result.stdout.lower()

    def test_map_no_policies(self, tmp_path):
        """Mapping without policy files fails with error."""
        from lemma.cli import app
        from lemma.services.indexer import ControlIndexer

        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(app, ["init"])

            # Remove template README.md created by init
            readme = Path("policies") / "README.md"
            if readme.exists():
                readme.unlink()

            # Index a framework so the "not indexed" check passes
            indexer = ControlIndexer(index_dir=Path(".lemma") / "index")
            indexer.index_controls(
                "nist-800-53",
                [
                    {
                        "id": "ac-1",
                        "title": "Policy",
                        "prose": "Test.",
                        "family": "AC",
                    },
                ],
            )

            result = runner.invoke(app, ["map", "--framework", "nist-800-53"])
            assert result.exit_code == 1
            stdout = result.stdout.lower()
            assert "no polic" in stdout or "policies" in stdout

    def test_map_command_success(self, tmp_path, monkeypatch):
        """Successful mapping produces output with mocked LLM."""
        from lemma.cli import app
        from lemma.services.indexer import ControlIndexer

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {
                "confidence": 0.85,
                "rationale": "Policy maps to account management.",
            }
        )

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])

        # Write a real policy file
        Path("policies/access.md").write_text(
            "# Access Control\n\nAll users must authenticate via SSO.\n"
        )

        # Index a framework — use absolute path to prevent ChromaDB
        # PersistentClient path resolution issues across invocations
        index_dir = (tmp_path / ".lemma" / "index").resolve()
        indexer = ControlIndexer(index_dir=index_dir)
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-2",
                    "title": "Account Management",
                    "prose": "Manage system accounts.",
                    "family": "AC",
                },
            ],
        )
        del indexer

        with patch(
            "lemma.commands.map.get_llm_client",
            return_value=mock_llm,
        ):
            result = runner.invoke(
                app,
                [
                    "map",
                    "--framework",
                    "nist-800-53",
                    "--output",
                    "json",
                ],
            )
        assert result.exit_code == 0
        assert "ac-2" in result.stdout or "nist-800-53" in result.stdout
