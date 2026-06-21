"""Tests for `lemma control-plane install` (Refs #42)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def test_install_systemd(tmp_path: Path):
    from lemma.cli import app

    out = tmp_path / "deploy"
    result = runner.invoke(
        app,
        ["control-plane", "install", "--shape", "systemd", "--output", str(out), "--port", "9443"],
    )
    assert result.exit_code == 0, result.stdout
    unit = out / "lemma-control-plane.service"
    assert unit.is_file()
    body = unit.read_text()
    assert "[Service]" in body
    assert "control-plane serve --port 9443" in body
    assert "{{" not in body  # all placeholders substituted


def test_install_docker_compose(tmp_path: Path):
    from lemma.cli import app

    out = tmp_path / "deploy"
    result = runner.invoke(
        app,
        [
            "control-plane",
            "install",
            "--shape",
            "docker-compose",
            "--output",
            str(out),
            "--image",
            "myreg/lemma:1.0",
        ],
    )
    assert result.exit_code == 0, result.stdout
    compose = out / "docker-compose.yml"
    assert compose.is_file()
    body = compose.read_text()
    assert "myreg/lemma:1.0" in body
    assert "lemma-control-plane:" in body
    assert "{{" not in body


def test_install_unknown_shape_errors(tmp_path: Path):
    from lemma.cli import app

    result = runner.invoke(
        app, ["control-plane", "install", "--shape", "k8s", "--output", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "systemd" in result.stdout and "docker-compose" in result.stdout


def test_install_refuses_overwrite_without_force(tmp_path: Path):
    from lemma.cli import app

    out = tmp_path / "deploy"
    args = ["control-plane", "install", "--shape", "systemd", "--output", str(out)]
    assert runner.invoke(app, args).exit_code == 0
    second = runner.invoke(app, args)
    assert second.exit_code == 1
    assert "force" in second.stdout.lower()
    assert runner.invoke(app, [*args, "--force"]).exit_code == 0
