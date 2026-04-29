"""Implementation of the ``lemma agent`` CLI sub-commands (Refs #25 Slice C).

The agent itself — a stateless Go/Rust binary deployed inside target
environments and federating compliance state to a control plane — is
tracked under #25 and not implemented yet. This CLI lands the surface
operators will eventually script against, with three sub-commands:

- ``lemma agent install``  — placeholder; tracked under #25.
- ``lemma agent status``   — placeholder; tracked under #25.
- ``lemma agent sync``     — ``--offline`` is fully wired today (thin
  wrapper over ``lemma evidence bundle``); other modes are placeholders.

The reason ``sync --offline`` ships now even though the binary doesn't
exist: the underlying primitive is ``audit_bundle.build_bundle``, which
shipped in #183. The eventual federated-online ``sync`` will reuse the
same primitive on the agent side, so operators can script against
``lemma agent sync --offline`` today knowing their scripts won't need
to change when the binary lands.
"""

from __future__ import annotations

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


_NOT_YET = (
    "[yellow]Not yet implemented.[/yellow] The Lemma agent binary, federation "
    "protocol, and control plane are tracked under #25 (Federated Agent "
    "Architecture). The CLI surface lands here so future operator scripts "
    "stay stable across the implementation rollout."
)


_SCAFFOLD_POINTER = (
    "The agent source lives at [bold]agent/[/bold]. See "
    "[bold]agent/README.md[/bold] for current build instructions. "
    "Install/status/sync wiring is tracked under #25."
)


@agent_app.command(
    name="install",
    help="Install the Lemma agent in the target environment (not yet implemented).",
)
def install_command() -> None:
    console.print(_NOT_YET)
    console.print(_SCAFFOLD_POINTER)
    raise typer.Exit(code=1)


@agent_app.command(
    name="status",
    help=(
        "Report agent health, last sync time, and control evaluation counts (not yet implemented)."
    ),
)
def status_command() -> None:
    console.print(_NOT_YET)
    console.print(_SCAFFOLD_POINTER)
    raise typer.Exit(code=1)


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
        console.print(_NOT_YET)
        console.print(
            "Online sync requires the agent binary + Control Plane; "
            "use [bold]lemma agent sync --offline[/bold] to export a signed "
            "audit bundle today."
        )
        console.print(_SCAFFOLD_POINTER)
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
