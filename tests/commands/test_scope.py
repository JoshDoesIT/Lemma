"""Tests for the `lemma scope` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_yaml(name: str = "prod-us-east") -> str:
    return (
        f"name: {name}\n"
        "frameworks:\n"
        "  - nist-800-53\n"
        'justification: "Prod."\n'
        "match_rules:\n"
        "  - source: aws.tags.Environment\n"
        "    operator: equals\n"
        "    value: prod\n"
    )


class TestScopeInit:
    def test_creates_default_yaml(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 0, result.stdout
        target = tmp_path / "scopes" / "default.yaml"
        assert target.exists()
        # Starter content must be a valid scope that parses.
        from lemma.services.scope import load_scope

        scope = load_scope(target)
        assert scope.name  # non-empty
        assert scope.frameworks  # at least one framework in the template

    def test_custom_name_writes_that_file(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init", "--name", "prod"])

        assert result.exit_code == 0, result.stdout
        assert (tmp_path / "scopes" / "prod.yaml").exists()

    def test_refuses_to_overwrite_existing(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        existing = scopes_dir / "default.yaml"
        existing.write_text("hand-authored: true\n")

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 1
        assert "exists" in result.stdout.lower() or "overwrite" in result.stdout.lower()
        # Untouched.
        assert existing.read_text() == "hand-authored: true\n"

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "init"])
        assert result.exit_code == 1


class TestScopeStatus:
    def test_empty_state_exits_zero_with_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "lemma scope init" in result.stdout.lower() or "no scopes" in result.stdout.lower()

    def test_renders_table_for_valid_scopes(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))
        (scopes_dir / "dev.yaml").write_text(_valid_yaml("dev-us-east"))

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout
        assert "dev-us-east" in result.stdout
        assert "nist-800-53" in result.stdout

    def test_exits_nonzero_when_any_scope_has_parse_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "ok.yaml").write_text(_valid_yaml("ok"))
        (scopes_dir / "broken.yaml").write_text(
            "name: broken\nframeworks:\n  - nist-800-53\nmatch_rule:\n  []\n"
        )

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 1
        assert "broken.yaml" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "status"])
        assert result.exit_code == 1
