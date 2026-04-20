"""Tests for the `lemma init` command.

TDD RED phase: these tests define the expected behavior before implementation.
"""

import yaml
from typer.testing import CliRunner

runner = CliRunner()


class TestLemmaInit:
    """Tests for the `lemma init` command."""

    def test_init_creates_directory_structure(self, tmp_path, monkeypatch):
        """Running `lemma init` creates the expected directory tree."""
        monkeypatch.chdir(tmp_path)
        from lemma.cli import app

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert (tmp_path / ".lemma").is_dir()
        assert (tmp_path / "policies").is_dir()
        assert (tmp_path / "controls").is_dir()
        assert (tmp_path / "evidence").is_dir()
        assert (tmp_path / "scopes").is_dir()
        assert (tmp_path / "lemma.config.yaml").is_file()

    def test_init_creates_valid_config_yaml(self, tmp_path, monkeypatch):
        """The generated config file is valid YAML with expected sections."""
        monkeypatch.chdir(tmp_path)
        from lemma.cli import app

        runner.invoke(app, ["init"])

        config = yaml.safe_load((tmp_path / "lemma.config.yaml").read_text())
        assert "frameworks" in config
        assert "ai" in config
        assert "connectors" in config

    def test_init_creates_policies_readme(self, tmp_path, monkeypatch):
        """The policies/ directory contains a template README."""
        monkeypatch.chdir(tmp_path)
        from lemma.cli import app

        runner.invoke(app, ["init"])

        readme = tmp_path / "policies" / "README.md"
        assert readme.is_file()
        assert len(readme.read_text()) > 0

    def test_init_fails_on_existing_lemma_dir(self, tmp_path, monkeypatch):
        """Running `lemma init` in a directory with `.lemma/` exits with error."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        from lemma.cli import app

        result = runner.invoke(app, ["init"])

        assert result.exit_code != 0
        assert "already" in result.stdout.lower() or "already" in result.output.lower()

    def test_init_creates_gitignore_entries(self, tmp_path, monkeypatch):
        """The generated .gitignore includes Lemma-specific exclusions."""
        monkeypatch.chdir(tmp_path)
        from lemma.cli import app

        runner.invoke(app, ["init"])

        gitignore = tmp_path / ".gitignore"
        if gitignore.is_file():
            content = gitignore.read_text()
            assert ".lemma/cache/" in content
