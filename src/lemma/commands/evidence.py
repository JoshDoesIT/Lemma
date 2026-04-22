"""Implementation of the ``lemma evidence`` CLI sub-commands.

Sub-commands:
    lemma evidence verify <entry_hash>   — integrity check for a single entry
    lemma evidence log                   — timeline with integrity state per row
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.signed_evidence import EvidenceIntegrityState
from lemma.services.evidence_log import EvidenceLog

console = Console()

evidence_app = typer.Typer(
    name="evidence",
    help="Inspect and verify the evidence log.",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def _state_style(state: EvidenceIntegrityState) -> str:
    if state == EvidenceIntegrityState.PROVEN:
        return "[green]PROVEN[/green]"
    if state == EvidenceIntegrityState.DEGRADED:
        return "[yellow]DEGRADED[/yellow]"
    return "[red]VIOLATED[/red]"


def _producer_of(metadata: dict) -> str:
    product = metadata.get("product") if isinstance(metadata, dict) else None
    if isinstance(product, dict):
        name = product.get("name")
        if isinstance(name, str) and name:
            return name
    return "unknown"


@evidence_app.command(
    name="verify",
    help="Verify the integrity of a specific evidence entry by entry_hash.",
)
def verify_command(
    entry_hash: str = typer.Argument(
        help="Entry hash of the evidence to verify (hex)",
    ),
) -> None:
    project_dir = _require_lemma_project()
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")

    result = log.verify_entry(entry_hash)
    console.print(f"{_state_style(result.state)}  {entry_hash[:16]}…")
    console.print(f"  {result.detail}")

    if result.state != EvidenceIntegrityState.PROVEN:
        raise typer.Exit(code=1)


@evidence_app.command(
    name="log",
    help="Show the evidence timeline with integrity state per entry.",
)
def log_command() -> None:
    project_dir = _require_lemma_project()
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    envelopes = log.read_envelopes()

    if not envelopes:
        console.print("[dim]No evidence entries. 0 entries.[/dim]")
        return

    table = Table(title=f"Evidence Log ({len(envelopes)} entries)")
    table.add_column("Time", style="dim", width=19)
    table.add_column("Class", min_width=14)
    table.add_column("Producer", style="cyan")
    table.add_column("Entry", style="dim", no_wrap=True)
    table.add_column("State")

    for env in envelopes:
        result = log.verify_entry(env.entry_hash)
        table.add_row(
            env.event.time.strftime("%Y-%m-%d %H:%M:%S"),
            env.event.class_name,
            _producer_of(env.event.metadata),
            env.entry_hash[:12] + "…",
            _state_style(result.state),
        )

    console.print(table)
