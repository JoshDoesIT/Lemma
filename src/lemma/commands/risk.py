"""Implementation of the ``lemma risk`` CLI sub-commands.

Sub-commands:
    lemma risk load   — load declared risks into the compliance graph
    lemma risk list   — render declared risks in a Rich table
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.risk import RiskSeverity
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.risk import load_all_risks

console = Console()

risk_app = typer.Typer(
    name="risk",
    help="Manage risk-as-code definitions.",
    no_args_is_help=True,
)


_SEVERITY_STYLE = {
    RiskSeverity.LOW: "[dim]LOW[/dim]",
    RiskSeverity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    RiskSeverity.HIGH: "[red]HIGH[/red]",
    RiskSeverity.CRITICAL: "[bold red]CRITICAL[/bold red]",
}


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


@risk_app.command(
    name="load",
    help="Load every declared risk into the compliance graph.",
)
def load_command() -> None:
    project_dir = _require_lemma_project()
    risks_dir = project_dir / "risks"

    try:
        risks = load_all_risks(risks_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not risks:
        console.print(
            "[dim]No risks declared. Create YAML files under [bold]risks/[/bold] and re-run.[/dim]"
        )
        return

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    try:
        for r in risks:
            graph.add_risk(
                risk_id=r.id,
                title=r.title,
                description=r.description,
                severity=r.severity.value,
                threatens=r.threatens,
                mitigated_by=r.mitigated_by,
            )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    graph.save(graph_path)
    console.print(f"[green]Loaded[/green] {len(risks)} risk(s) into the graph.")
    for r in risks:
        console.print(
            f"  [cyan]{r.id}[/cyan] — {_SEVERITY_STYLE[r.severity]}; "
            f"threatens {len(r.threatens)}, mitigated by {len(r.mitigated_by)}"
        )


@risk_app.command(name="list", help="List declared risks ordered by severity.")
def list_command() -> None:
    project_dir = _require_lemma_project()
    risks_dir = project_dir / "risks"

    try:
        risks = load_all_risks(risks_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not risks:
        console.print(
            "[dim]No risks declared. "
            "Create YAML files under [bold]risks/[/bold] and run "
            "[bold]lemma risk load[/bold] to register them.[/dim]"
        )
        return

    severity_order = {
        RiskSeverity.CRITICAL: 0,
        RiskSeverity.HIGH: 1,
        RiskSeverity.MEDIUM: 2,
        RiskSeverity.LOW: 3,
    }
    risks_sorted = sorted(risks, key=lambda r: (severity_order[r.severity], r.id))

    table = Table(title=f"Declared Risks ({len(risks)})")
    table.add_column("ID", style="bold cyan")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Threatens", justify="right")
    table.add_column("Mitigated By", justify="right")

    for r in risks_sorted:
        table.add_row(
            r.id,
            r.title,
            _SEVERITY_STYLE[r.severity],
            str(len(r.threatens)),
            str(len(r.mitigated_by)),
        )

    Console(width=120).print(table)
