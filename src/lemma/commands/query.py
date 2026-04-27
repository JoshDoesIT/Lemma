"""Implementation of the ``lemma query`` CLI.

Translates a natural-language question into a structured ``QueryPlan``
via an LLM, executes the plan against the compliance graph, emits an
``AITrace`` with ``operation="query"``, and renders results.
"""

from __future__ import annotations

import json as _json
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from lemma.models.trace import AITrace
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.llm import LLMClient, get_llm_client
from lemma.services.query_executor import execute
from lemma.services.query_translator import translate
from lemma.services.trace_log import TraceLog

console = Console()


def _error(message: str) -> None:
    typer.echo(f"Error: {message}")
    raise typer.Exit(code=1)


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def _load_llm(project_dir: Path) -> LLMClient:
    config_file = project_dir / "lemma.config.yaml"
    ai_config: dict = {}
    if config_file.exists():
        full_config = yaml.safe_load(config_file.read_text()) or {}
        ai_config = full_config.get("ai", {})
    try:
        return get_llm_client(ai_config)
    except ImportError as exc:
        _error(str(exc))


def _model_id_from(llm_client: LLMClient) -> str:
    model = str(getattr(llm_client, "model", "unknown"))
    class_name = type(llm_client).__name__.lower()
    if "ollama" in class_name:
        return f"ollama/{model}"
    if "openai" in class_name:
        return f"openai/{model}"
    return model


def _summarize_attrs(node: dict) -> str:
    """Compact one-line summary of a node's most audit-relevant attributes.

    The same table is reused across node types; blank cells are acceptable.
    Evidence shows its provenance, Risk its severity, Person their email,
    Control/Policy their title.
    """
    node_type = str(node.get("type", ""))
    if node_type == "Evidence":
        producer = str(node.get("producer", ""))
        time_iso = str(node.get("time_iso", ""))
        if producer and time_iso:
            return f"{producer} · {time_iso}"
        return producer or time_iso
    if node_type == "Risk":
        title = str(node.get("title", ""))
        severity = str(node.get("severity", "")).upper()
        if title and severity:
            return f"{title} [{severity}]"
        return title or severity
    if node_type == "Person":
        return str(node.get("email") or node.get("full_name") or "")
    if node_type == "Resource":
        return str(node.get("resource_type") or node.get("type_") or "")
    if node_type == "Scope":
        return str(node.get("name", ""))
    if node_type in ("Control", "Policy", "Framework"):
        return str(node.get("title") or node.get("name") or "")
    return ""


def _format_list(results: list[dict]) -> None:
    if not results:
        console.print("[dim]No matching nodes. 0 results.[/dim]")
        return

    table = Table(title=f"Query Results ({len(results)})")
    table.add_column("Node", style="cyan", no_wrap=True)
    table.add_column("Type")
    table.add_column("Attributes")
    table.add_column("Edge", style="dim")

    for row in results:
        table.add_row(
            str(row.get("id", "")),
            str(row.get("type", "")),
            _summarize_attrs(row),
            str(row.get("_edge", "")),
        )
    Console(width=140).print(table)


def query_command(
    question: str = typer.Argument(help="Natural-language question about the graph"),
    verbose: bool = typer.Option(
        False, "--verbose", help="Print the resolved query plan before the results"
    ),
    output_format: str = typer.Option("table", "--format", help="Output format: table or json"),
) -> None:
    """Ask the compliance graph a question in plain English."""
    project_dir = _require_lemma_project()
    graph_path = project_dir / ".lemma" / "graph.json"
    if not graph_path.exists():
        _error("No compliance graph found. Run `lemma framework add` and `lemma map` first.")
    graph = ComplianceGraph.load(graph_path)

    llm_client = _load_llm(project_dir)

    # Translate — the translator is the only place LLM calls happen in
    # this command, so we capture prompt + raw output via a spy.
    prompt_seen: dict = {}
    raw_output_seen: dict = {}

    original_generate = llm_client.generate

    def _spying_generate(prompt: str) -> str:
        prompt_seen.setdefault("first", prompt)
        response = original_generate(prompt)
        raw_output_seen.setdefault("first", response)
        return response

    llm_client.generate = _spying_generate  # type: ignore[method-assign]

    try:
        plan = translate(question=question, graph=graph, llm_client=llm_client)
    except ValueError as exc:
        _error(str(exc))

    if verbose:
        console.print("[bold]Resolved plan:[/bold]")
        console.print(plan.model_dump_json(indent=2))

    try:
        result = execute(plan, graph)
    except ValueError as exc:
        _error(str(exc))

    # Emit trace: one entry per query, with prompt + first raw response.
    has_evidence_filters = any(
        attr is not None for attr in (plan.time_range, plan.severity, plan.producer, plan.class_uid)
    )
    trace_log = TraceLog(log_dir=project_dir / ".lemma" / "traces")
    trace_log.append(
        AITrace(
            operation="evidence_query" if has_evidence_filters else "query",
            operation_kind="read",
            input_text=question[:500],
            prompt=prompt_seen.get("first", ""),
            model_id=_model_id_from(llm_client),
            model_version="",
            raw_output=raw_output_seen.get("first", ""),
            confidence=0.0,  # convention: query traces are reads, not decisions
            determination="QUERY_EXECUTED",
            control_id="",
            framework="",
        )
    )

    # Render result
    if output_format == "json":
        if isinstance(result, int):
            typer.echo(_json.dumps({"count": result}))
        else:
            typer.echo(_json.dumps(result, indent=2))
    else:
        if isinstance(result, int):
            console.print(f"[bold]{result}[/bold]")
        else:
            _format_list(result)
