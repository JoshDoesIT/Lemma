"""Implementation of the ``lemma scope`` CLI sub-commands.

Sub-commands:
    lemma scope init [--name <name>]  — scaffold a starter scopes/<name>.yaml
    lemma scope status                — parse and report declared scopes
    lemma scope load                  — load declared scopes into the graph
    lemma scope matches <resource-id> — show scopes that match a declared resource
    lemma scope impact --plan <file>  — scope impact of a Terraform plan
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.resource import load_all_resources
from lemma.services.scope import load_all_scopes
from lemma.services.scope_matcher import scope_impact_for_change, scopes_containing
from lemma.services.terraform_plan import parse_terraform_plan

console = Console()

scope_app = typer.Typer(
    name="scope",
    help="Manage scope-as-code definitions.",
    no_args_is_help=True,
)


_STARTER_TEMPLATE = """\
# Scope-as-code definition. Edit the fields below to declare the
# compliance frameworks that apply to a slice of your infrastructure,
# plus the rules that decide which resources fall inside the slice.
#
# `lemma scope status` parses every *.yaml in this directory and
# validates the schema; errors point to the offending file and line.

name: default
frameworks:
  - nist-csf-2.0
justification: >-
  Replace this with a short statement of why these frameworks apply
  to the resources that match the rules below. Auditors read this.
match_rules:
  - source: aws.tags.Environment
    operator: equals
    value: prod
"""


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


@scope_app.command(name="init", help="Scaffold a starter scope-as-code YAML file.")
def init_command(
    name: str = typer.Option(
        "default",
        "--name",
        help="Scope file name (writes scopes/<name>.yaml).",
    ),
) -> None:
    project_dir = _require_lemma_project()
    scopes_dir = project_dir / "scopes"
    scopes_dir.mkdir(exist_ok=True)

    target = scopes_dir / f"{name}.yaml"
    if target.exists():
        console.print(
            f"[red]Error:[/red] {target.relative_to(project_dir)} already exists; "
            "refusing to overwrite. Delete it first if you want to regenerate."
        )
        raise typer.Exit(code=1)

    target.write_text(_STARTER_TEMPLATE)
    console.print(f"[green]Created[/green] {target.relative_to(project_dir)}.")
    console.print("Edit it to match your environment, then run [bold]lemma scope status[/bold].")


@scope_app.command(name="status", help="Parse and display every declared scope.")
def status_command() -> None:
    project_dir = _require_lemma_project()
    scopes_dir = project_dir / "scopes"

    try:
        scopes = load_all_scopes(scopes_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not scopes:
        console.print(
            "[dim]No scopes defined. Run [bold]lemma scope init[/bold] to create one.[/dim]"
        )
        return

    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    table = Table(title=f"Declared Scopes ({len(scopes)})")
    table.add_column("Scope", style="bold cyan")
    table.add_column("Frameworks")
    table.add_column("Rules", justify="right")
    table.add_column("In Graph", justify="center")
    table.add_column("Justification", style="dim")

    for scope in scopes:
        in_graph = graph.get_node(f"scope:{scope.name}") is not None
        table.add_row(
            scope.name,
            ", ".join(scope.frameworks),
            str(len(scope.match_rules)),
            "[green]✓[/green]" if in_graph else "[dim]✗[/dim]",
            scope.justification or "—",
        )

    console.print(table)


@scope_app.command(
    name="load",
    help="Load every declared scope into the compliance graph.",
)
def load_command() -> None:
    project_dir = _require_lemma_project()
    scopes_dir = project_dir / "scopes"

    try:
        scopes = load_all_scopes(scopes_dir)
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    if not scopes:
        console.print(
            "[dim]No scopes defined. Run [bold]lemma scope init[/bold] to create one.[/dim]"
        )
        return

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    try:
        for scope in scopes:
            graph.add_scope(
                name=scope.name,
                frameworks=scope.frameworks,
                justification=scope.justification,
                rule_count=len(scope.match_rules),
            )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    graph.save(graph_path)
    console.print(f"[green]Loaded[/green] {len(scopes)} scope(s) into the graph.")
    for scope in scopes:
        console.print(f"  [cyan]{scope.name}[/cyan]  →  {', '.join(scope.frameworks)}")


@scope_app.command(
    name="matches",
    help="Show which declared scopes contain a declared resource.",
)
def matches_command(
    resource_id: str = typer.Argument(
        help="Resource id (from a resources/*.yaml file) to evaluate.",
    ),
) -> None:
    project_dir = _require_lemma_project()

    try:
        scopes = load_all_scopes(project_dir / "scopes")
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    try:
        resources = load_all_resources(project_dir / "resources")
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    resource = next((r for r in resources if r.id == resource_id), None)
    if resource is None:
        console.print(
            f"[red]Error:[/red] No declared resource with id '{resource_id}'. "
            "Check resources/*.yaml."
        )
        raise typer.Exit(code=1)

    try:
        matching = scopes_containing(resource.attributes, scopes)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not matching:
        console.print(f"[dim]No matching scope — {resource_id} satisfies 0 scopes' rules.[/dim]")
        return

    console.print(f"[green]{resource_id}[/green] matches {len(matching)} scope(s):")
    for scope_name in matching:
        declared_scope = next(s for s in scopes if s.name == scope_name)
        frameworks = ", ".join(declared_scope.frameworks)
        console.print(f"  [cyan]{scope_name}[/cyan]  →  {frameworks}")


@scope_app.command(
    name="impact",
    help="Compute scope impact of a Terraform plan (exits non-zero on any scope change).",
)
def impact_command(
    plan: str = typer.Option(
        ...,
        "--plan",
        help="Path to a Terraform plan JSON file ('terraform show -json plan.tfplan').",
    ),
) -> None:
    project_dir = _require_lemma_project()

    try:
        scopes = load_all_scopes(project_dir / "scopes")
    except ValueError as exc:
        for line in str(exc).splitlines():
            console.print(f"[red]Error:[/red] {line}")
        raise typer.Exit(code=1) from exc

    try:
        changes = parse_terraform_plan(Path(plan))
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    affected_rows: list[tuple[str, str, list[str], list[str]]] = []
    unaffected = 0
    for change in changes:
        impact = scope_impact_for_change(before=change.before, after=change.after, scopes=scopes)
        if impact.entered or impact.exited:
            affected_rows.append(
                (change.address, ",".join(change.actions), impact.entered, impact.exited)
            )
        else:
            unaffected += 1

    if not affected_rows:
        console.print(
            f"[green]No scope impact.[/green] "
            f"{len(changes)} plan change(s) inspected; 0 scope memberships change."
        )
        return

    table = Table(title=f"Scope Impact ({len(affected_rows)} of {len(changes)} changes)")
    table.add_column("Resource", style="bold cyan")
    table.add_column("Action")
    table.add_column("Entered")
    table.add_column("Exited")

    for address, action, entered, exited in affected_rows:
        table.add_row(
            address,
            action,
            ", ".join(entered) or "—",
            ", ".join(exited) or "—",
        )

    Console(width=120).print(table)
    console.print(
        f"[red]{len(affected_rows)} change(s) move scope membership.[/red] "
        f"{unaffected} change(s) without scope impact."
    )
    raise typer.Exit(code=1)
