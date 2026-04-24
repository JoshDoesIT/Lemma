"""Implementation of the ``lemma person`` CLI sub-commands.

Sub-commands:
    lemma person load   — load declared people into the compliance graph
    lemma person list   — render declared people in a Rich table
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.person import load_all_people

console = Console()

person_app = typer.Typer(
    name="person",
    help="Manage person-as-code definitions.",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


@person_app.command(
    name="load",
    help="Load every declared person into the compliance graph.",
)
def load_command() -> None:
    project_dir = _require_lemma_project()
    people_dir = project_dir / "people"

    try:
        people = load_all_people(people_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not people:
        console.print(
            "[dim]No people declared. "
            "Create YAML files under [bold]people/[/bold] and re-run.[/dim]"
        )
        return

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    try:
        for p in people:
            graph.add_person(
                person_id=p.id,
                name=p.name,
                email=p.email,
                role=p.role,
                owns=p.owns,
            )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    graph.save(graph_path)
    console.print(f"[green]Loaded[/green] {len(people)} person(s) into the graph.")
    for p in people:
        console.print(
            f"  [cyan]{p.id}[/cyan] — {p.name} ({p.role or 'no role'}); owns {len(p.owns)}"
        )


@person_app.command(name="list", help="List declared people with ownership-target validity.")
def list_command() -> None:
    project_dir = _require_lemma_project()
    people_dir = project_dir / "people"

    try:
        people = load_all_people(people_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not people:
        console.print(
            "[dim]No people declared. "
            "Create YAML files under [bold]people/[/bold] and run "
            "[bold]lemma person load[/bold] to register them.[/dim]"
        )
        return

    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    table = Table(title=f"Declared People ({len(people)})")
    table.add_column("ID", style="bold cyan")
    table.add_column("Name")
    table.add_column("Role", style="dim")
    table.add_column("Owns", justify="right")
    table.add_column("Targets OK", justify="center")

    for p in people:
        all_resolved = all(graph.get_node(ref) is not None for ref in p.owns)
        table.add_row(
            p.id,
            p.name,
            p.role or "—",
            str(len(p.owns)),
            "[green]✓[/green]" if all_resolved else "[red]✗[/red]",
        )

    Console(width=120).print(table)
