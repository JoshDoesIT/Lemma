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


def test_install_helm_writes_a_renderable_chart(tmp_path: Path):
    from lemma.cli import app

    out = tmp_path / "deploy"
    result = runner.invoke(
        app,
        [
            "control-plane",
            "install",
            "--shape",
            "helm",
            "--output",
            str(out),
            "--port",
            "9443",
            "--image",
            "myreg/lemma:2.0",
        ],
    )
    assert result.exit_code == 0, result.stdout

    chart = out / "lemma-control-plane"
    assert (chart / "Chart.yaml").is_file()

    values = (chart / "values.yaml").read_text()
    assert "myreg/lemma:2.0" in values
    assert "9443" in values
    # The command's {{KEY}} placeholders are fully substituted in values.yaml.
    for placeholder in ("{{IMAGE}}", "{{PORT}}", "{{EVIDENCE_DIR}}", "{{KEYS_DIR}}"):
        assert placeholder not in values

    deployment = (chart / "templates" / "deployment.yaml").read_text()
    assert "kind: Deployment" in deployment
    assert "control-plane" in deployment and "serve" in deployment
    # Helm's own templating is preserved (not clobbered by {{KEY}} substitution).
    assert "{{ .Values.service.port }}" in deployment
    assert (chart / "templates" / "service.yaml").read_text().startswith("apiVersion")


def test_install_helm_refuses_overwrite_without_force(tmp_path: Path):
    from lemma.cli import app

    out = tmp_path / "deploy"
    args = ["control-plane", "install", "--shape", "helm", "--output", str(out)]
    assert runner.invoke(app, args).exit_code == 0
    second = runner.invoke(app, args)
    assert second.exit_code == 1
    assert "force" in second.stdout.lower()
    assert runner.invoke(app, [*args, "--force"]).exit_code == 0


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


def test_install_terraform_writes_a_parseable_module(tmp_path: Path):
    import hcl2

    from lemma.cli import app

    out = tmp_path / "deploy"
    result = runner.invoke(
        app,
        [
            "control-plane",
            "install",
            "--shape",
            "terraform",
            "--output",
            str(out),
            "--port",
            "9443",
            "--image",
            "myreg/lemma:2.0",
        ],
    )
    assert result.exit_code == 0, result.stdout

    module = out / "terraform"
    tf_files = ["versions.tf", "variables.tf", "main.tf", "outputs.tf"]
    for name in tf_files:
        assert (module / name).is_file()

    variables = (module / "variables.tf").read_text()
    assert "myreg/lemma:2.0" in variables
    assert "9443" in variables
    # The command's {{KEY}} placeholders are fully substituted in variables.tf.
    for placeholder in ("{{IMAGE}}", "{{PORT}}", "{{EVIDENCE_DIR}}", "{{KEYS_DIR}}"):
        assert placeholder not in variables

    # Every .tf file parses as valid HCL2 (raises on malformed HCL).
    for name in tf_files:
        hcl2.loads((module / name).read_text())

    main = (module / "main.tf").read_text()
    assert "aws_instance" in main
    assert "aws_security_group" in main


def test_install_terraform_refuses_overwrite_without_force(tmp_path: Path):
    from lemma.cli import app

    out = tmp_path / "deploy"
    args = ["control-plane", "install", "--shape", "terraform", "--output", str(out)]
    assert runner.invoke(app, args).exit_code == 0
    second = runner.invoke(app, args)
    assert second.exit_code == 1
    assert "force" in second.stdout.lower()
    assert runner.invoke(app, [*args, "--force"]).exit_code == 0
