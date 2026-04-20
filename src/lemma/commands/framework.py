"""Implementation of the `lemma framework` CLI commands.

Provides sub-commands for managing compliance frameworks:
    lemma framework add <name>     — Index a bundled framework
    lemma framework list           — List indexed frameworks
    lemma framework import <file>  — Import a user-provided framework file
"""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.framework import (
    add_bundled_framework,
    import_framework,
    list_frameworks,
)

console = Console()

_FILE_ARGUMENT = typer.Argument(
    help="Path to framework file (.json, .pdf, .xlsx, .csv)",
    exists=True,
    readable=True,
)

framework_app = typer.Typer(
    name="framework",
    help="Manage compliance frameworks.",
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


@framework_app.command(name="add", help="Index a bundled compliance framework.")
def add_command(
    name: str = typer.Argument(help="Framework name (e.g., nist-800-53)"),
) -> None:
    """Index a bundled compliance framework by name."""
    project_dir = _require_lemma_project()

    try:
        result = add_bundled_framework(name, project_dir=project_dir)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from None

    console.print(
        f"[green]Indexed[/green] [bold]{result['name']}[/bold] — "
        f"{result['control_count']} controls indexed."
    )


@framework_app.command(name="list", help="List all indexed frameworks.")
def list_command() -> None:
    """Display a table of all indexed frameworks."""
    project_dir = _require_lemma_project()

    frameworks = list_frameworks(project_dir=project_dir)

    if not frameworks:
        console.print("[dim]No frameworks indexed yet.[/dim]")
        console.print("Run [bold]lemma framework add nist-800-53[/bold] to get started.")
        return

    table = Table(title="Indexed Frameworks")
    table.add_column("Framework", style="bold")
    table.add_column("Controls", justify="right")

    for fw in frameworks:
        table.add_row(fw["name"], str(fw["control_count"]))

    console.print(table)


@framework_app.command(name="import", help="Import a framework from a file.")
def import_command(
    file: Path = _FILE_ARGUMENT,
) -> None:
    """Import a user-provided framework file and index it."""
    project_dir = _require_lemma_project()

    try:
        result = import_framework(file, project_dir=project_dir)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from None
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from None

    console.print(
        f"[green]Imported[/green] [bold]{result['name']}[/bold] — "
        f"{result['control_count']} controls indexed."
    )
