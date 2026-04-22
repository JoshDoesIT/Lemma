"""Implementation of the `lemma ai` CLI commands.

Provides sub-commands for AI transparency and governance:
    lemma ai system-card     — Display the AI System Card
    lemma ai audit           — Query and filter the AI trace log
    lemma ai bom             — Export the AI Bill of Materials (CycloneDX 1.6)
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.system_card import get_default_system_card
from lemma.services.aibom import build_aibom, validate_aibom
from lemma.services.trace_log import TraceLog

console = Console()

ai_app = typer.Typer(
    name="ai",
    help="AI transparency and governance commands.",
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


@ai_app.command(name="system-card", help="Display the AI System Card.")
def system_card_command(
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown or json",
    ),
) -> None:
    """Display the AI transparency card documenting all models used."""
    _require_lemma_project()

    card = get_default_system_card()

    if output_format == "json":
        print(card.model_dump_json(indent=2))
    else:
        console.print(card.render_markdown())


@ai_app.command(
    name="bom",
    help="Export the AI Bill of Materials as CycloneDX 1.6 JSON.",
)
def bom_command() -> None:
    """Emit a CycloneDX 1.6 AI BOM for the current system card to stdout."""
    _require_lemma_project()
    bom = build_aibom(get_default_system_card())
    validate_aibom(bom)
    print(json.dumps(bom, indent=2))


@ai_app.command(name="audit", help="Query and filter the AI trace log.")
def audit_command(
    model: str = typer.Option(
        "",
        "--model",
        "-m",
        help="Filter traces by model ID (e.g., ollama/llama3.2)",
    ),
    status: str = typer.Option(
        "",
        "--status",
        "-s",
        help="Filter traces by review status (PROPOSED, ACCEPTED, REJECTED)",
    ),
    operation: str = typer.Option(
        "",
        "--operation",
        "-o",
        help="Filter traces by operation (e.g., map, harmonize)",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table or json",
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Show aggregate statistics instead of individual traces",
    ),
) -> None:
    """Display and filter AI trace log entries."""
    project_dir = _require_lemma_project()
    trace_log = TraceLog(log_dir=project_dir / ".lemma" / "traces")

    # Load and filter traces
    traces = trace_log.read_all()

    if model:
        traces = [t for t in traces if t.model_id == model]

    if status:
        traces = [t for t in traces if t.status.value == status]

    if operation:
        traces = [t for t in traces if t.operation == operation]

    if summary:
        _show_summary(traces)
        return

    if not traces:
        console.print("[dim]No trace entries found. 0 traces.[/dim]")
        return

    if output_format == "json":
        data = [json.loads(t.model_dump_json()) for t in traces]
        print(json.dumps(data, indent=2))
    else:
        _show_table(traces)


def _show_table(traces: list) -> None:
    """Render traces as a Rich table.

    Args:
        traces: List of AITrace records to display.
    """
    table = Table(title=f"AI Trace Log ({len(traces)} entries)")
    table.add_column("Timestamp", style="dim", width=19)
    table.add_column("Model", style="cyan", min_width=20, no_wrap=True)
    table.add_column("Control", style="bold", min_width=20, no_wrap=True)
    table.add_column("Confidence", justify="right")
    table.add_column("Status")
    table.add_column("Determination")

    for trace in traces:
        # Color-code status
        status_str = trace.status.value
        if status_str == "ACCEPTED":
            status_display = f"[green]{status_str}[/green]"
        elif status_str == "REJECTED":
            status_display = f"[red]{status_str}[/red]"
        else:
            status_display = f"[yellow]{status_str}[/yellow]"

        # Color-code confidence
        conf = trace.confidence
        if conf >= 0.8:
            conf_display = f"[green]{conf:.2f}[/green]"
        elif conf >= 0.6:
            conf_display = f"[yellow]{conf:.2f}[/yellow]"
        else:
            conf_display = f"[red]{conf:.2f}[/red]"

        table.add_row(
            trace.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            trace.model_id,
            f"{trace.framework}:{trace.control_id}",
            conf_display,
            status_display,
            trace.determination,
        )

    console.print(table)


def _show_summary(traces: list) -> None:
    """Render aggregate statistics for the trace log.

    Args:
        traces: List of AITrace records to summarize.
    """
    if not traces:
        console.print("[dim]No trace entries found. 0 traces.[/dim]")
        return

    console.print(f"\n[bold]AI Audit Summary[/bold] — {len(traces)} traces\n")

    # Model distribution
    model_counts = Counter(t.model_id for t in traces)
    model_table = Table(title="Traces by Model")
    model_table.add_column("Model", style="cyan")
    model_table.add_column("Count", justify="right")
    for model_id, count in model_counts.most_common():
        model_table.add_row(model_id, str(count))
    console.print(model_table)
    console.print()

    # Status distribution
    status_counts = Counter(t.status.value for t in traces)
    status_table = Table(title="Traces by Status")
    status_table.add_column("Status")
    status_table.add_column("Count", justify="right")
    for status_val, count in status_counts.most_common():
        status_table.add_row(status_val, str(count))
    console.print(status_table)
    console.print()

    # Confidence statistics
    confidences = [t.confidence for t in traces]
    avg_conf = sum(confidences) / len(confidences)
    min_conf = min(confidences)
    max_conf = max(confidences)

    console.print(
        f"[bold]Confidence:[/bold] avg={avg_conf:.2f}, min={min_conf:.2f}, max={max_conf:.2f}"
    )
