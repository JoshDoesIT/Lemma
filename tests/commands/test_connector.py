"""Tests for the ``lemma connector`` CLI subcommands."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_payload(uid: str) -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {"version": "1.3.0", "product": {"name": "Sample"}, "uid": uid},
    }


class TestConnectorInit:
    def test_init_scaffolds_project_files(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["connector", "init", "myconn"])

        assert result.exit_code == 0, result.stdout
        project = tmp_path / "myconn"
        assert project.is_dir()
        assert (project / "connector.py").is_file()
        assert (project / "manifest.json").is_file()
        assert (project / "README.md").is_file()
        assert (project / "fixtures").is_dir()

        # Scaffolded manifest.json parses as a valid ConnectorManifest.
        from lemma.models.connector_manifest import ConnectorManifest

        manifest = ConnectorManifest.model_validate_json((project / "manifest.json").read_text())
        assert manifest.name == "myconn"

    def test_init_refuses_to_overwrite_existing_directory(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / "existing").mkdir()
        (tmp_path / "existing" / "some-file.txt").write_text("important")

        result = runner.invoke(app, ["connector", "init", "existing"])

        assert result.exit_code == 1
        stdout = result.stdout.lower()
        assert "exists" in stdout or "already" in stdout
        # Existing file is untouched.
        assert (tmp_path / "existing" / "some-file.txt").read_text() == "important"


class TestConnectorTest:
    def test_test_command_reports_event_count_for_scaffolded_connector(
        self, tmp_path: Path, monkeypatch
    ):
        """Scaffold a project and exercise `lemma connector test` against it."""
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["connector", "init", "demo"])

        # Seed the default fixture with two valid events so collect() yields them.
        fixture = tmp_path / "demo" / "fixtures" / "events.jsonl"
        fixture.write_text(
            json.dumps(_valid_payload("e-1")) + "\n" + json.dumps(_valid_payload("e-2")) + "\n"
        )

        result = runner.invoke(app, ["connector", "test", str(tmp_path / "demo")])

        assert result.exit_code == 0, result.stdout
        assert "2" in result.stdout  # event count surfaces in summary

    def test_test_command_reports_missing_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["connector", "test", str(tmp_path / "does-not-exist")])

        assert result.exit_code == 1
        assert "not found" in result.stdout.lower() or "does not exist" in result.stdout.lower()

    def test_test_command_reports_malformed_fixture(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["connector", "init", "broken"])

        (tmp_path / "broken" / "fixtures" / "events.jsonl").write_text("this is not json\n")

        result = runner.invoke(app, ["connector", "test", str(tmp_path / "broken")])

        assert result.exit_code == 1
        assert "line 1" in result.stdout.lower() or "json" in result.stdout.lower()
