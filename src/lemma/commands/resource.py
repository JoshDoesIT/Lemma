"""Implementation of the ``lemma resource`` CLI sub-commands.

Sub-commands:
    lemma resource load   — load declared resources into the graph
    lemma resource list   — render declared resources in a Rich table
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.resource import load_all_resources

console = Console()

resource_app = typer.Typer(
    name="resource",
    help="Manage declared infrastructure resources.",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


@resource_app.command(
    name="load",
    help="Load every declared resource into the compliance graph.",
)
def load_command() -> None:
    project_dir = _require_lemma_project()
    resources_dir = project_dir / "resources"

    try:
        resources = load_all_resources(resources_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not resources:
        console.print(
            "[dim]No resources declared. "
            "Create YAML files under [bold]resources/[/bold] and re-run.[/dim]"
        )
        return

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    try:
        for r in resources:
            graph.add_resource(
                resource_id=r.id,
                type_=r.type,
                scope=r.scope,
                attributes=r.attributes,
            )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    graph.save(graph_path)
    console.print(f"[green]Loaded[/green] {len(resources)} resource(s) into the graph.")
    for r in resources:
        console.print(f"  [cyan]{r.id}[/cyan]  →  scope:{r.scope}")


@resource_app.command(name="list", help="List declared resources grouped by scope state.")
def list_command() -> None:
    project_dir = _require_lemma_project()
    resources_dir = project_dir / "resources"

    try:
        resources = load_all_resources(resources_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not resources:
        console.print(
            "[dim]No resources declared. "
            "Create YAML files under [bold]resources/[/bold] and run "
            "[bold]lemma resource load[/bold] to register them.[/dim]"
        )
        return

    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    table = Table(title=f"Declared Resources ({len(resources)})")
    table.add_column("Resource", style="bold cyan")
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Scope OK", justify="center")
    table.add_column("Attributes", justify="right")

    for r in resources:
        scope_in_graph = graph.get_node(f"scope:{r.scope}") is not None
        table.add_row(
            r.id,
            r.type,
            r.scope,
            "[green]✓[/green]" if scope_in_graph else "[red]✗[/red]",
            str(len(r.attributes)),
        )

    # Wider console so the Scope OK column doesn't squeeze Type on narrow terminals.
    Console(width=120).print(table)
