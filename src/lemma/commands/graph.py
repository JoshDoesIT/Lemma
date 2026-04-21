"""Implementation of the `lemma graph` CLI commands.

Provides sub-commands for querying the compliance knowledge graph:
    lemma graph export          — Export the graph as JSON
    lemma graph impact <node>   — Show compliance impact of a node
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.knowledge_graph import ComplianceGraph

console = Console()

graph_app = typer.Typer(
    name="graph",
    help="Query the compliance knowledge graph.",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    """Verify CWD is an initialized Lemma project, return project dir."""
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def _load_graph(project_dir: Path) -> ComplianceGraph:
    """Load the project's knowledge graph.

    Args:
        project_dir: Root of the Lemma project.

    Returns:
        ComplianceGraph instance (empty if no graph file exists).
    """
    return ComplianceGraph.load(project_dir / ".lemma" / "graph.json")


@graph_app.command(name="export", help="Export the knowledge graph as JSON.")
def export_command() -> None:
    """Export the full compliance graph as JSON for visualization."""
    project_dir = _require_lemma_project()
    graph = _load_graph(project_dir)

    data = graph.export_json()
    console.print(json.dumps(data, indent=2))


@graph_app.command(name="impact", help="Analyze compliance impact of a node.")
def impact_command(
    node_id: str = typer.Argument(
        help="Node ID to analyze (e.g., policy:access-control.md, control:nist-800-53:ac-1)"
    ),
) -> None:
    """Show all controls and frameworks affected by a node."""
    project_dir = _require_lemma_project()
    graph = _load_graph(project_dir)

    result = graph.impact(node_id)

    controls = result.get("controls", [])
    frameworks = result.get("frameworks", [])

    if not controls and not frameworks:
        console.print(
            f"[dim]No impact found for [bold]{node_id}[/bold]. 0 controls affected.[/dim]"
        )
        return

    console.print(f"\n[bold]Impact Analysis: {node_id}[/bold]\n")

    if frameworks:
        console.print(f"[cyan]Frameworks affected:[/cyan] {', '.join(frameworks)}")
        console.print()

    if controls:
        table = Table(title=f"Controls Affected ({len(controls)})")
        table.add_column("Control ID", style="bold")
        table.add_column("Title")
        table.add_column("Family")

        for ctrl in controls:
            table.add_row(
                ctrl.get("control_id", ""),
                ctrl.get("title", ""),
                ctrl.get("family", ""),
            )

        console.print(table)
