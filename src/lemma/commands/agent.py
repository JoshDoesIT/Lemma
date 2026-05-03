"""Implementation of the ``lemma agent`` CLI sub-commands (Refs #25).

The Go agent binary lives at ``agent/`` and ships with a working
``lemma-agent serve --port N --evidence-dir <dir> --keys-dir <dir>``
that exposes a ``/health`` endpoint. ``lemma agent install`` renders a
deployment artifact (Kubernetes Deployment, systemd unit, or a
bare-metal launcher script) that runs the agent in production. ``lemma
agent status`` queries the agent's ``/health`` endpoint and reports the
snapshot. ``lemma agent sync --offline`` is a thin wrapper over
``lemma evidence bundle`` for air-gapped operators.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console

console = Console()

agent_app = typer.Typer(
    name="agent",
    help="Federated agent commands (install / status / sync).",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


_REPO_ROOT = Path(__file__).resolve().parents[3]
_TEMPLATE_DIR = _REPO_ROOT / "agent" / "deploy"

_SHAPES = {
    "k8s": ("k8s-sidecar.yaml.tmpl", "lemma-agent.yaml"),
    "systemd": ("lemma-agent.service.tmpl", "lemma-agent.service"),
    "launcher": ("launcher.sh.tmpl", "lemma-agent.sh"),
}

_DEFAULT_IMAGE = "ghcr.io/joshdoesit/lemma-agent:latest"
_DEFAULT_BINARY_PATH = "/usr/local/bin/lemma-agent"
_DEFAULT_EVIDENCE_DIR = "/var/lib/lemma-agent/evidence"
_DEFAULT_KEYS_DIR = "/var/lib/lemma-agent/keys"
_DEFAULT_HEALTH_PORT = 8080


def _render_template(template_path: Path, substitutions: dict[str, str]) -> str:
    body = template_path.read_text()
    for key, value in substitutions.items():
        body = body.replace("{{" + key + "}}", value)
    return body


@agent_app.command(
    name="install",
    help=(
        "Render a deployment artifact for the Lemma agent (K8s sidecar, "
        "systemd unit, or bare-metal launcher script)."
    ),
)
def install_command(
    shape: str = typer.Option(
        ...,
        "--shape",
        help="Deployment shape: k8s, systemd, or launcher.",
    ),
    output: str = typer.Option(
        ...,
        "--output",
        help="Output directory for the rendered artifact.",
    ),
    image: str = typer.Option(
        _DEFAULT_IMAGE,
        "--image",
        help="Container image (k8s shape only).",
    ),
    binary_path: str = typer.Option(
        _DEFAULT_BINARY_PATH,
        "--binary-path",
        help="Path to the lemma-agent binary on the target host (systemd / launcher).",
    ),
    evidence_dir: str = typer.Option(
        _DEFAULT_EVIDENCE_DIR,
        "--evidence-dir",
        help="On-host evidence directory the agent serves from.",
    ),
    keys_dir: str = typer.Option(
        _DEFAULT_KEYS_DIR,
        "--keys-dir",
        help="On-host producer-keys directory.",
    ),
    health_port: int = typer.Option(
        _DEFAULT_HEALTH_PORT,
        "--health-port",
        help="TCP port the agent's /health endpoint listens on.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing rendered artifact at --output.",
    ),
) -> None:
    if shape not in _SHAPES:
        console.print(
            f"[red]Error:[/red] unknown --shape {shape!r}; "
            f"valid shapes: {', '.join(sorted(_SHAPES))}."
        )
        raise typer.Exit(code=1)

    template_name, output_name = _SHAPES[shape]
    template_path = _TEMPLATE_DIR / template_name
    if not template_path.is_file():
        console.print(f"[red]Error:[/red] missing deployment template: {template_path}")
        raise typer.Exit(code=1)

    out_path = Path(output)
    out_path.mkdir(parents=True, exist_ok=True)
    target = out_path / output_name
    if target.exists() and not force:
        console.print(f"[red]Error:[/red] {target} already exists; pass --force to overwrite.")
        raise typer.Exit(code=1)

    rendered = _render_template(
        template_path,
        {
            "IMAGE": image,
            "BINARY_PATH": binary_path,
            "EVIDENCE_DIR": evidence_dir,
            "KEYS_DIR": keys_dir,
            "HEALTH_PORT": str(health_port),
        },
    )
    target.write_text(rendered)
    if shape == "launcher":
        os.chmod(target, 0o755)

    console.print(f"[green]Wrote[/green] {shape} deployment artifact to {target}")
    if shape == "k8s":
        console.print("Apply with: [bold]kubectl apply -f " + str(target) + "[/bold]")
    elif shape == "systemd":
        console.print(
            "Install with: [bold]sudo cp "
            + str(target)
            + " /etc/systemd/system/ && sudo systemctl daemon-reload && "
            + "sudo systemctl enable --now lemma-agent[/bold]"
        )
    else:
        console.print("Run with: [bold]" + str(target) + "[/bold]")


def _format_uptime(seconds: float) -> str:
    seconds = int(seconds)
    days, rem = divmod(seconds, 86_400)
    hours, rem = divmod(rem, 3_600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return "".join(parts)


@agent_app.command(
    name="status",
    help="Report agent health, last sync time, and evidence counts via /health.",
)
def status_command(
    endpoint: str = typer.Option(
        ...,
        "--endpoint",
        help="Base URL of a running agent (e.g. http://127.0.0.1:8080).",
    ),
    timeout: int = typer.Option(
        5,
        "--timeout",
        help="HTTP timeout in seconds.",
    ),
) -> None:
    url = endpoint.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                console.print(f"[red]Error:[/red] /health returned HTTP {resp.status}.")
                raise typer.Exit(code=1)
            body = resp.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        console.print(f"[red]Error:[/red] agent endpoint unreachable: {exc}")
        raise typer.Exit(code=1) from exc

    try:
        snap = json.loads(body)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] /health returned non-JSON body: {exc}")
        raise typer.Exit(code=1) from exc

    version = snap.get("version", "?")
    evidence_count = snap.get("evidence_count", 0)
    last_signed = snap.get("last_signed_at") or "(none)"
    producer_count = snap.get("producer_count", 0)
    started_at = snap.get("started_at", "?")
    uptime = _format_uptime(snap.get("uptime_seconds", 0))

    console.print(f"[bold]Lemma agent v{version}[/bold] @ {endpoint}")
    console.print(f"  Started:           {started_at} (up {uptime})")
    console.print(f"  Evidence count:    {evidence_count}")
    console.print(f"  Last signed at:    {last_signed}")
    console.print(f"  Producer keys:     {producer_count}")
    # Drift warning if started_at is in the future relative to now —
    # operators get a hint that clocks are off.
    try:
        start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=UTC)
        if start_dt > datetime.now(UTC):
            console.print(
                "  [yellow]Warning:[/yellow] reported started_at is in the future — clock skew?"
            )
    except (ValueError, AttributeError):
        pass


@agent_app.command(
    name="sync",
    help=(
        "Sync compliance state. --offline is fully wired (audit bundle export); "
        "online federation is tracked under #25."
    ),
)
def sync_command(
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Export a signed audit bundle (the only mode wired today).",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Bundle directory to create (required for --offline).",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Omit the AI System Card and AIBOM from the bundle.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite a non-empty --output directory.",
    ),
) -> None:
    if not offline:
        console.print(
            "[yellow]Online sync not yet implemented.[/yellow] "
            "Online federation requires the agent ↔ Control Plane "
            "protocol, which is tracked under #25. Use "
            "[bold]lemma agent sync --offline --output PATH[/bold] to "
            "export a signed audit bundle today, or run "
            "[bold]lemma-agent forward[/bold] from the Go agent for "
            "HTTP/HTTPS-with-mTLS forwarding."
        )
        console.print(
            "The agent source lives at [bold]agent/[/bold]. See "
            "[bold]agent/README.md[/bold] for current build instructions."
        )
        raise typer.Exit(code=1)

    if not output:
        console.print(
            "[red]Error:[/red] --offline requires --output PATH for the bundle directory."
        )
        raise typer.Exit(code=1)

    project_dir = _require_lemma_project()
    output_path = Path(output)

    from lemma.services.audit_bundle import build_bundle

    try:
        manifest = build_bundle(
            project_dir=project_dir,
            output_dir=output_path,
            include_ai=not no_ai,
            force=force,
        )
    except FileExistsError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]Wrote[/green] audit bundle to {output_path} ({len(manifest.files)} files)."
    )


@agent_app.command(
    name="evaluate",
    help=(
        "Evaluate the project's controls against scope-as-code, then emit "
        "one signed OCSF Compliance Finding envelope per control to "
        "<evidence-dir>/<YYYY-MM-DD>.jsonl (Refs #25). Pair with "
        "`lemma-agent forward` to push the findings to a Control Plane."
    ),
)
def evaluate_command(
    output: str = typer.Option(
        "",
        "--output",
        help=(
            "Append the resulting signed envelopes to PATH (a JSONL file) "
            "in addition to writing them to the project's evidence log."
        ),
    ),
    framework: str = typer.Option(
        "",
        "--framework",
        help="Restrict evaluation to a single framework short name.",
    ),
    min_confidence: float = typer.Option(
        0.0,
        "--min-confidence",
        help="Minimum SATISFIES edge confidence to count toward PASSED.",
    ),
) -> None:
    project_dir = _require_lemma_project()

    # Importing inline keeps the agent CLI lazy — `lemma agent --help`
    # doesn't need to import the graph + compliance_check stack.
    from lemma.services.compliance_check import check
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.ocsf_normalizer import normalize

    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")
    try:
        result = check(
            graph,
            framework=framework or None,
            min_confidence=min_confidence,
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    written: list[str] = []

    for outcome in result.outcomes:
        ocsf_status = "Pass" if outcome.status.value == "PASSED" else "Fail"
        event = normalize(
            {
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
                    # entry uid: framework + short_id + status, so
                    # re-running evaluate dedups on today's day-file.
                    "uid": f"{outcome.framework}:{outcome.short_id}:{ocsf_status}",
                    "compliance": {
                        "control": outcome.short_id,
                        "standards": [outcome.framework],
                        "status": ocsf_status,
                    },
                },
            }
        )
        if log.append(event):
            envelopes = log.read_envelopes()
            written.append(envelopes[-1].model_dump_json())

    if output:
        Path(output).write_text("\n".join(written) + ("\n" if written else ""))

    console.print(
        f"[green]Evaluated[/green] {result.total} controls "
        f"({result.passed} passed, {result.failed} failed); "
        f"signed {len(written)} new envelope(s)."
    )


# Keep `stat` referenced so static checkers don't strip the import on
# platforms where the launcher chmod path is the sole consumer.
_ = stat
