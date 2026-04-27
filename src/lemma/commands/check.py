"""Implementation of the ``lemma check`` CLI command.

Runs a coverage check over the compliance graph and exits non-zero if
any control in the selected framework has zero satisfying policies.
Output formats: ``text`` (default, Rich), ``json`` (machine-readable),
and ``sarif`` (GitHub Code Scanning / GitLab CI ingestion).
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.check_result import CheckStatus
from lemma.services.compliance_check import check as run_check
from lemma.services.compliance_check import to_sarif
from lemma.services.knowledge_graph import ComplianceGraph

console = Console()

_VALID_FORMATS = ("text", "json", "sarif")


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def check_command(
    framework: str = typer.Option(
        "",
        "--framework",
        help="Restrict the check to a single framework (e.g. nist-800-53).",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text (default), json, or sarif.",
    ),
    min_confidence: float = typer.Option(
        0.0,
        "--min-confidence",
        help=(
            "Only count SATISFIES edges with confidence >= this threshold. "
            "Default 0.0 = no filtering. Orthogonal to ai.automation.thresholds.map "
            "(auto-accept floor for new mappings); --min-confidence raises the bar "
            "specifically for the CI gate without changing what gets accepted."
        ),
        min=0.0,
        max=1.0,
    ),
) -> None:
    """Evaluate compliance posture and exit non-zero on any uncovered control."""
    if output_format not in _VALID_FORMATS:
        console.print(
            f"[red]Error:[/red] Unknown --format '{output_format}'. "
            f"Choose one of: {', '.join(_VALID_FORMATS)}."
        )
        raise typer.Exit(code=1)

    project_dir = _require_lemma_project()
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    try:
        result = run_check(graph, framework=framework or None, min_confidence=min_confidence)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if output_format == "json":
        # Plain stdout (no Rich) so it stays parseable.
        import json as _json

        print(_json.dumps(result.model_dump(), indent=2))
        if result.failed:
            raise typer.Exit(code=1)
        return

    if output_format == "sarif":
        sarif = to_sarif(result)
        print(sarif.model_dump_json(by_alias=True, indent=2))
        if result.failed:
            raise typer.Exit(code=1)
        return

    # Text output.
    scope = f"framework [cyan]{result.framework}[/cyan]" if result.framework else "all frameworks"
    console.print(
        f"[bold]Compliance Check[/bold]  —  {scope}  —  "
        f"{result.total} checked · [green]{result.passed} passed[/green] · "
        f"[red]{result.failed} failed[/red]"
    )

    if result.failed == 0:
        console.print("[green]All controls have at least one satisfying policy.[/green]")
        return

    table = Table(title=f"Failed Controls ({result.failed})")
    table.add_column("Status")
    table.add_column("Control", style="bold")
    table.add_column("Framework", style="cyan")
    table.add_column("Title")
    for outcome in result.outcomes:
        if outcome.status != CheckStatus.FAILED:
            continue
        table.add_row("[red]FAILED[/red]", outcome.short_id, outcome.framework, outcome.title)
    console.print(table)

    raise typer.Exit(code=1)
