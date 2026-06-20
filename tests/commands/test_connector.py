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


class TestConnectorSecrets:
    def _init_project(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        monkeypatch.setenv("LEMMA_SECRET_PASSPHRASE", "unit-pass")

    def test_set_secret_via_env_value_then_list(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        monkeypatch.setenv("LEMMA_SECRET_VALUE", "ghp_abc123")

        result = runner.invoke(app, ["connector", "set-secret", "GITHUB_TOKEN"])
        assert result.exit_code == 0, result.stdout
        assert "Stored" in result.stdout

        listed = runner.invoke(app, ["connector", "list-secrets"])
        assert listed.exit_code == 0
        assert "GITHUB_TOKEN" in listed.stdout
        # The value is never printed.
        assert "ghp_abc123" not in listed.stdout

    def test_set_secret_rotates_existing(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.secret_store import SecretStore

        self._init_project(tmp_path, monkeypatch)

        monkeypatch.setenv("LEMMA_SECRET_VALUE", "v1")
        runner.invoke(app, ["connector", "set-secret", "TOK"])
        monkeypatch.setenv("LEMMA_SECRET_VALUE", "v2")
        result = runner.invoke(app, ["connector", "set-secret", "TOK"])

        assert "Rotated" in result.stdout
        store = SecretStore(tmp_path / ".lemma" / "secrets.json", passphrase="unit-pass")
        assert store.get("TOK") == "v2"

    def test_set_secret_requires_passphrase(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        monkeypatch.delenv("LEMMA_SECRET_PASSPHRASE", raising=False)
        monkeypatch.setenv("LEMMA_SECRET_VALUE", "x")

        result = runner.invoke(app, ["connector", "set-secret", "TOK"])
        assert result.exit_code == 1
        assert "LEMMA_SECRET_PASSPHRASE" in result.stdout

    def test_rm_secret(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        monkeypatch.setenv("LEMMA_SECRET_VALUE", "v")
        runner.invoke(app, ["connector", "set-secret", "TOK"])

        result = runner.invoke(app, ["connector", "rm-secret", "TOK"])
        assert result.exit_code == 0
        assert "Removed" in result.stdout
        assert "TOK" not in runner.invoke(app, ["connector", "list-secrets"]).stdout

    def test_rotated_secret_picked_up_without_restart(self, tmp_path: Path, monkeypatch):
        """A connector resolves the *current* stored value each run — rotating
        the secret is picked up by the next `evidence collect` with no restart."""
        from lemma.services.connector_config import load_connector_config
        from lemma.services.secret_store import SecretStore

        self._init_project(tmp_path, monkeypatch)
        store = SecretStore(tmp_path / ".lemma" / "secrets.json", passphrase="unit-pass")
        store.set("TOK", "old")

        cfg_path = tmp_path / "c.yaml"
        cfg_path.write_text("connector: jira\nconfig:\n  token: ${secret:TOK}\n")

        first = load_connector_config(cfg_path, secret_store=store)
        assert first.config["token"] == "old"

        # Rotate the secret; a fresh load (== next run) sees the new value.
        store.set("TOK", "new")
        second = load_connector_config(
            cfg_path,
            secret_store=SecretStore(tmp_path / ".lemma" / "secrets.json", passphrase="unit-pass"),
        )
        assert second.config["token"] == "new"


class TestConnectorRun:
    def _init_project(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

    def _stub_connector(self, counter: list):
        """A connector whose collect() emits one finding and counts calls."""
        from datetime import UTC, datetime

        from lemma.models.connector_manifest import ConnectorManifest
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connector import Connector

        class _Stub(Connector):
            def __init__(self) -> None:
                self.manifest = ConnectorManifest(
                    name="stub", version="0.1.0", producer="Stub", description="x"
                )

            def collect(self):
                counter.append(1)
                yield ComplianceFinding(
                    class_name="Compliance Finding",
                    category_uid=2000,
                    category_name="Findings",
                    type_uid=200301,
                    activity_id=1,
                    time=datetime.now(UTC),
                    message="stub",
                    status_id=1,
                    metadata={
                        "version": "1.3.0",
                        "product": {"name": "Stub"},
                        "uid": f"stub:{len(counter)}",
                    },
                )

        return _Stub()

    def test_run_once_collects_and_exits(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        calls: list = []
        stub = self._stub_connector(calls)
        monkeypatch.setattr(
            "lemma.commands.evidence._connector_from_config_dict", lambda *a, **k: stub
        )

        cfg = tmp_path / "c.yaml"
        cfg.write_text("connector: stub\nconfig: {}\n")

        result = runner.invoke(app, ["connector", "run", "--config", str(cfg), "--once"])
        assert result.exit_code == 0, result.stdout
        assert len(calls) == 1
        assert "Collected" in result.stdout

    def test_watch_runs_max_runs_times(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        calls: list = []
        stub = self._stub_connector(calls)
        monkeypatch.setattr(
            "lemma.commands.evidence._connector_from_config_dict", lambda *a, **k: stub
        )
        # Don't actually sleep between scheduled runs.
        monkeypatch.setattr("lemma.commands.connector._sleep_until", lambda _t: None)

        cfg = tmp_path / "c.yaml"
        cfg.write_text("connector: stub\nconfig: {}\nschedule: '* * * * *'\n")

        result = runner.invoke(app, ["connector", "run", "--config", str(cfg), "--max-runs", "3"])
        assert result.exit_code == 0, result.stdout
        assert len(calls) == 3

    def test_watch_without_schedule_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "lemma.commands.evidence._connector_from_config_dict",
            lambda *a, **k: self._stub_connector([]),
        )

        cfg = tmp_path / "c.yaml"
        cfg.write_text("connector: stub\nconfig: {}\n")  # no schedule

        result = runner.invoke(app, ["connector", "run", "--config", str(cfg)])
        assert result.exit_code == 1
        assert "schedule" in result.stdout.lower()

    def test_invalid_schedule_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "lemma.commands.evidence._connector_from_config_dict",
            lambda *a, **k: self._stub_connector([]),
        )

        cfg = tmp_path / "c.yaml"
        cfg.write_text("connector: stub\nconfig: {}\nschedule: 'not a cron'\n")

        result = runner.invoke(app, ["connector", "run", "--config", str(cfg), "--max-runs", "1"])
        assert result.exit_code == 1
        assert "schedule" in result.stdout.lower()

    def test_disabled_config_skips(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        self._init_project(tmp_path, monkeypatch)
        calls: list = []
        monkeypatch.setattr(
            "lemma.commands.evidence._connector_from_config_dict",
            lambda *a, **k: self._stub_connector(calls),
        )

        cfg = tmp_path / "c.yaml"
        cfg.write_text("connector: stub\nconfig: {}\nenabled: false\n")

        result = runner.invoke(app, ["connector", "run", "--config", str(cfg), "--once"])
        assert result.exit_code == 0
        assert "disabled" in result.stdout.lower()
        assert calls == []
