"""Tests for `lemma agent` CLI scaffold (Refs #25 Slice C).

The agent surface in v1 is mostly placeholders — the binary,
federation protocol, and control plane are tracked separately under
#25. The exception is `lemma agent sync --offline`, which is fully
wired today: it's a thin wrapper over `lemma evidence bundle` so
operators can script against the long-lived `lemma agent sync` shape
even before the agent binary lands.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _compliance_payload(uid: str = "evt-1") -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Lemma"},
            "uid": uid,
        },
    }


def _seed_signed_entries(project_dir: Path) -> list[str]:
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    log.append(normalize(_compliance_payload("agent-1")))
    return [env.entry_hash for env in log.read_envelopes()]


def test_agent_help_lists_three_subcommands(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code == 0, result.stdout
    assert "install" in result.stdout
    assert "status" in result.stdout
    assert "sync" in result.stdout


def test_agent_install_requires_shape_and_output(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(app, ["agent", "install"])
    # Typer reports missing required options via exit code 2 (usage).
    assert result.exit_code != 0


def test_agent_install_rejects_unknown_shape(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(
        app,
        ["agent", "install", "--shape", "wat", "--output", str(tmp_path / "out")],
    )
    assert result.exit_code == 1
    assert "shape" in result.stdout.lower()


def test_agent_install_k8s_renders_sidecar_yaml(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "agent",
            "install",
            "--shape",
            "k8s",
            "--output",
            str(out),
            "--image",
            "ghcr.io/joshdoesit/lemma-agent:1.2.3",
        ],
    )
    assert result.exit_code == 0, result.stdout
    rendered = out / "lemma-agent.yaml"
    assert rendered.is_file(), f"missing: {rendered}"
    body = rendered.read_text()
    assert "{{IMAGE}}" not in body and "{{HEALTH_PORT}}" not in body, (
        "all template placeholders must be substituted"
    )
    assert "ghcr.io/joshdoesit/lemma-agent:1.2.3" in body
    assert "kind: Deployment" in body
    assert "lemma-agent" in body


def test_agent_install_systemd_renders_service_unit(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "agent",
            "install",
            "--shape",
            "systemd",
            "--output",
            str(out),
            "--binary-path",
            "/usr/local/bin/lemma-agent",
        ],
    )
    assert result.exit_code == 0, result.stdout
    rendered = out / "lemma-agent.service"
    assert rendered.is_file()
    body = rendered.read_text()
    assert "{{BINARY_PATH}}" not in body
    assert "/usr/local/bin/lemma-agent" in body
    assert "[Service]" in body and "[Install]" in body


def test_agent_install_launcher_renders_executable_shell_script(tmp_path: Path, monkeypatch):
    import os
    import stat

    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["agent", "install", "--shape", "launcher", "--output", str(out)],
    )
    assert result.exit_code == 0, result.stdout
    rendered = out / "lemma-agent.sh"
    assert rendered.is_file()
    mode = os.stat(rendered).st_mode
    assert mode & stat.S_IXUSR, f"launcher must be executable; got mode {oct(mode)}"
    body = rendered.read_text()
    assert body.startswith("#!"), "launcher must start with a shebang"
    assert "{{BINARY_PATH}}" not in body


def test_agent_install_refuses_to_overwrite_unless_force(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "lemma-agent.yaml").write_text("existing")

    first = runner.invoke(app, ["agent", "install", "--shape", "k8s", "--output", str(out)])
    assert first.exit_code == 1
    assert "exists" in first.stdout.lower() or "force" in first.stdout.lower()

    second = runner.invoke(
        app,
        ["agent", "install", "--shape", "k8s", "--output", str(out), "--force"],
    )
    assert second.exit_code == 0, second.stdout
    body = (out / "lemma-agent.yaml").read_text()
    assert body != "existing"


def test_agent_status_requires_endpoint(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(app, ["agent", "status"])
    assert result.exit_code != 0


def test_agent_status_reports_health_snapshot_from_running_agent(tmp_path: Path, monkeypatch):
    """End-to-end-ish: spin up a stub /health server in-process, run
    `lemma agent status` against it, assert the snapshot line."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from lemma.cli import app

    payload = {
        "version": "0.8.0",
        "evidence_count": 17,
        "last_signed_at": "2026-05-02T12:34:56Z",
        "producer_count": 2,
        "started_at": "2026-05-02T08:00:00Z",
        "uptime_seconds": 16500,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                body = _json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a, **k):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = runner.invoke(
            app,
            ["agent", "status", "--endpoint", f"http://127.0.0.1:{port}"],
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.exit_code == 0, result.stdout
    out = result.stdout
    assert "0.8.0" in out
    assert "17" in out  # evidence_count
    assert "2026-05-02T12:34:56Z" in out
    assert "2" in out  # producer_count


def test_agent_status_returns_one_when_endpoint_unreachable(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    # Port 1 is reserved; nothing listens. Pick a low timeout so the test
    # doesn't hang the suite.
    result = runner.invoke(
        app,
        [
            "agent",
            "status",
            "--endpoint",
            "http://127.0.0.1:1",
            "--timeout",
            "1",
        ],
    )
    assert result.exit_code == 1
    assert "unreachable" in result.stdout.lower() or "error" in result.stdout.lower()


def test_agent_sync_without_offline_exits_one_pointing_at_offline(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(app, ["agent", "sync"])
    assert result.exit_code == 1
    assert "--offline" in result.stdout
    # Online sync requires the binary + control plane, both tracked on #25.
    assert "#25" in result.stdout
    assert "agent/README.md" in result.stdout


def test_agent_sync_offline_without_output_exits_one(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)
    result = runner.invoke(app, ["agent", "sync", "--offline"])
    assert result.exit_code == 1
    assert "--output" in result.stdout


def test_agent_sync_offline_writes_audit_bundle(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    out = tmp_path / "bundle"
    result = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert (out / "manifest.json").is_file()
    assert (out / "manifest.sig").is_file()
    assert (out / "evidence").is_dir()


def test_agent_sync_offline_no_ai_skips_ai_dir(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    out = tmp_path / "bundle"
    result = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out), "--no-ai"])
    assert result.exit_code == 0, result.stdout
    assert not (out / "ai").exists()


def test_agent_sync_offline_force_overwrites_non_empty_dir(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_signed_entries(tmp_path)

    out = tmp_path / "bundle"
    out.mkdir()
    (out / "stray.txt").write_text("existing")

    first = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out)])
    assert first.exit_code == 1
    assert "force" in first.stdout.lower()

    second = runner.invoke(app, ["agent", "sync", "--offline", "--output", str(out), "--force"])
    assert second.exit_code == 0, second.stdout
    assert not (out / "stray.txt").exists()


# Evaluate subcommand tests ----------------------------------------------


def test_agent_evaluate_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["agent", "evaluate", "--output", str(tmp_path / "out.jsonl")])
    assert result.exit_code == 1
    assert "Not a Lemma project" in result.stdout


def test_agent_evaluate_writes_signed_envelopes_for_each_control(tmp_path: Path, monkeypatch):
    """End-to-end: load an indexed framework, run check, and emit one
    signed OCSF Compliance Finding envelope per control. The resulting
    JSONL is what `lemma-agent forward` would post to the Control Plane."""
    import json as _json

    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.framework import add_bundled_framework

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()

    # Seed a framework so `check` has something to evaluate.
    add_bundled_framework("nist-800-53", project_dir=tmp_path)

    out = tmp_path / "evaluate.jsonl"
    result = runner.invoke(app, ["agent", "evaluate", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.is_file()
    lines = [line for line in out.read_text().splitlines() if line.strip()]
    assert len(lines) > 0, "expected at least one signed envelope"

    # Each line is a valid signed envelope.
    for line in lines:
        env = _json.loads(line)
        assert env["entry_hash"]
        assert env["signature"]
        compliance = env["event"]["metadata"]["compliance"]
        assert compliance["control"]
        assert compliance["standards"]
        assert compliance["status"] in {"Pass", "Fail"}

    # The agent's evidence log can verify what we wrote (round-trip).
    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    envelopes = log.read_envelopes()
    assert len(envelopes) >= len(lines)


def test_agent_evaluate_framework_filter_limits_emitted_findings(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.framework import add_bundled_framework

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    add_bundled_framework("nist-800-53", project_dir=tmp_path)

    out = tmp_path / "evaluate.jsonl"
    result = runner.invoke(
        app,
        [
            "agent",
            "evaluate",
            "--framework",
            "nist-800-53",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout
    lines = [line for line in out.read_text().splitlines() if line.strip()]
    assert len(lines) > 0


def test_agent_evaluate_unknown_framework_exits_one(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    result = runner.invoke(
        app,
        [
            "agent",
            "evaluate",
            "--framework",
            "does-not-exist",
            "--output",
            str(tmp_path / "x.jsonl"),
        ],
    )
    assert result.exit_code == 1
    assert "Error" in result.stdout
