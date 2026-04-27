"""Implementation of the ``lemma scope`` CLI sub-commands.

Sub-commands:
    lemma scope init [--name <name>]  — scaffold a starter scopes/<name>.yaml
    lemma scope status                — parse and report declared scopes
    lemma scope load                  — load declared scopes into the graph
    lemma scope matches <resource-id> — show scopes that match a declared resource
    lemma scope impact --plan <file>  — scope impact of a Terraform plan
    lemma scope posture [<name>]      — per-framework coverage metrics per scope
    lemma scope visualize [<name>]    — render scope subgraph as Graphviz DOT
    lemma scope discover aws          — auto-discover AWS resources into the graph
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from lemma.services.ansible_discovery import (
    discover_resources_from_ansible as ansible_discover_resources,
)
from lemma.services.aws_discovery import discover_resources as aws_discover_resources
from lemma.services.azure_discovery import (
    discover_resources_from_azure as azure_discover_resources,
)
from lemma.services.device42_discovery import (
    discover_resources_from_device42 as device42_discover_resources,
)
from lemma.services.file_discovery import (
    discover_resources_from_file as file_discover_resources,
)
from lemma.services.gcp_discovery import (
    discover_resources_from_gcp as gcp_discover_resources,
)
from lemma.services.k8s_discovery import (
    discover_resources_from_cluster as k8s_discover_resources,
)
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.network_discovery import (
    discover_resources_from_network as network_discover_resources,
)
from lemma.services.resource import load_all_resources
from lemma.services.scope import load_all_scopes
from lemma.services.scope_dot import render_scope_dot
from lemma.services.scope_drift import compute_drift
from lemma.services.scope_matcher import scope_impact_for_change, scopes_containing
from lemma.services.scope_posture import compute_posture
from lemma.services.scope_watch import reload_after_yaml_change
from lemma.services.servicenow_discovery import (
    discover_resources_from_servicenow as servicenow_discover_resources,
)
from lemma.services.terraform_plan import parse_terraform_plan
from lemma.services.terraform_state import (
    discover_resources_from_state as tf_state_discover_resources,
)
from lemma.services.vsphere_discovery import (
    discover_resources_from_vsphere as vsphere_discover_resources,
)

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
# `lemma scope status` parses every *.yaml/*.yml/*.hcl in this directory
# and validates the schema; errors point to the offending file and line.

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

_STARTER_TEMPLATE_HCL = """\
# Scope-as-code definition (HCL/Terraform syntax). Edit the fields
# below to declare the compliance frameworks that apply to a slice of
# your infrastructure, plus the rules that decide which resources fall
# inside the slice.
#
# `lemma scope status` parses every *.yaml/*.yml/*.hcl in this directory
# and validates the schema.

name = "default"
frameworks = ["nist-csf-2.0"]
justification = <<-EOT
  Replace this with a short statement of why these frameworks apply
  to the resources that match the rules below. Auditors read this.
EOT

match_rule {
  source   = "aws.tags.Environment"
  operator = "equals"
  value    = "prod"
}
"""


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


@scope_app.command(name="init", help="Scaffold a starter scope-as-code file (YAML or HCL).")
def init_command(
    name: str = typer.Option(
        "default",
        "--name",
        help="Scope file name (writes scopes/<name>.<ext>; ext follows --format).",
    ),
    format_: str = typer.Option(
        "yaml",
        "--format",
        help="Output format: yaml (default) or hcl. HCL uses Terraform-style block syntax.",
    ),
) -> None:
    project_dir = _require_lemma_project()
    scopes_dir = project_dir / "scopes"
    scopes_dir.mkdir(exist_ok=True)

    if format_ not in ("yaml", "hcl"):
        console.print(f"[red]Error:[/red] Unknown --format '{format_}'. Choose 'yaml' or 'hcl'.")
        raise typer.Exit(code=1)

    extension = format_
    template = _STARTER_TEMPLATE_HCL if format_ == "hcl" else _STARTER_TEMPLATE
    target = scopes_dir / f"{name}.{extension}"
    if target.exists():
        console.print(
            f"[red]Error:[/red] {target.relative_to(project_dir)} already exists; "
            "refusing to overwrite. Delete it first if you want to regenerate."
        )
        raise typer.Exit(code=1)

    target.write_text(template)
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
    name="explain",
    help="Show per-scope rule attribution for a Resource node in the graph.",
)
def explain_command(
    resource_id: str = typer.Argument(
        help="Resource id (with or without 'resource:' prefix) to explain.",
    ),
) -> None:
    project_dir = _require_lemma_project()
    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    node_id = resource_id if resource_id.startswith("resource:") else f"resource:{resource_id}"
    node = graph.get_node(node_id)
    if node is None or node.get("type") != "Resource":
        console.print(
            f"[red]Error:[/red] No Resource node '{resource_id}' in the graph. "
            "Run [bold]lemma resource list[/bold] to see declared resources, or "
            "[bold]lemma scope discover <provider>[/bold] to populate from infrastructure."
        )
        raise typer.Exit(code=1)

    out_edges = graph.outgoing_edges(node_id)
    scoped_edges = [e for e in out_edges if e.get("relationship") == "SCOPED_TO"]

    console.print(
        f"[bold]Resource:[/bold] {node['resource_id']} ([cyan]{node['resource_type']}[/cyan])"
    )
    if not scoped_edges:
        console.print(
            "[dim]Not in any scope (unexpected; resources should always be scoped).[/dim]"
        )
        return

    console.print(f"In {len(scoped_edges)} scope(s):")
    for edge in scoped_edges:
        scope_name = edge["target"].removeprefix("scope:")
        rules = edge.get("matched_rules") or []
        if not rules:
            console.print(
                f"  [cyan]{scope_name}[/cyan]  ← [dim](no rule attribution — "
                f"manual declaration or catch-all scope)[/dim]"
            )
            continue
        for i, rule in enumerate(rules):
            prefix = f"  [cyan]{scope_name}[/cyan]  ← " if i == 0 else "                ← "
            console.print(f"{prefix}{rule['source']}, {rule['operator']}, {rule['value']!r}")


@scope_app.command(
    name="reuse",
    help=(
        "Show Cross-Scope Evidence Reuse chains for a scope: which controls are "
        "implicitly evidenced via HARMONIZED_WITH equivalences."
    ),
)
def reuse_command(
    scope_name: str = typer.Argument(
        help="Scope to inspect (must already be loaded into the graph).",
    ),
) -> None:
    project_dir = _require_lemma_project()
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    scope_node_id = f"scope:{scope_name}"
    if graph.get_node(scope_node_id) is None:
        console.print(
            f"[red]Error:[/red] Scope '{scope_name}' is not in the graph. "
            "Run [bold]lemma scope load[/bold] first."
        )
        raise typer.Exit(code=1)

    export = graph.export_json()

    bound_frameworks = sorted(
        edge["target"]
        for edge in export["edges"]
        if edge["source"] == scope_node_id and edge.get("relationship") == "APPLIES_TO"
    )
    controls_in_scope: set[str] = set()
    for edge in export["edges"]:
        if edge.get("relationship") == "CONTAINS" and edge["source"] in bound_frameworks:
            controls_in_scope.add(edge["target"])

    implicit_edges = [
        edge
        for edge in export["edges"]
        if edge.get("relationship") == "IMPLICITLY_EVIDENCES"
        and edge["target"] in controls_in_scope
    ]

    framework_names = ", ".join(fw.removeprefix("framework:") for fw in bound_frameworks)
    console.print(
        f"[bold]Scope:[/bold] [cyan]{scope_name}[/cyan] → {framework_names or '(no frameworks)'}"
    )
    console.print(f"Implicitly evidenced controls ({len(implicit_edges)}):")
    if not implicit_edges:
        console.print(
            "[dim](none — no Cross-Scope Evidence Reuse via harmonization for this scope. "
            "Run [bold]lemma harmonize[/bold] and [bold]lemma evidence load[/bold] to "
            "populate.)[/dim]"
        )
        return

    for edge in sorted(implicit_edges, key=lambda e: e["target"]):
        control_name = edge["target"].removeprefix("control:")
        evidence_id = edge["source"].removeprefix("evidence:")[:12]
        via = edge.get("via_control", "").removeprefix("control:")
        similarity = edge.get("similarity", 0.0)
        console.print(
            f"  [cyan]{control_name}[/cyan]  ← evidence:{evidence_id}…  "
            f"[dim](via {via}, similarity {similarity})[/dim]"
        )


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


def _scope_names_in_graph(graph: ComplianceGraph) -> list[str]:
    export = graph.export_json()
    return sorted(node["name"] for node in export["nodes"] if node.get("type") == "Scope")


@scope_app.command(
    name="posture",
    help="Per-framework compliance posture for declared scopes.",
)
def posture_command(
    scope_name: str = typer.Argument(
        "",
        help="Specific scope to report on. Omit to summarize every declared scope.",
    ),
) -> None:
    project_dir = _require_lemma_project()
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    scope_names = _scope_names_in_graph(graph)
    if not scope_names:
        console.print("[dim]No scopes in the graph. Run [bold]lemma scope load[/bold] first.[/dim]")
        return

    if scope_name:
        # Detailed per-framework drill-down for a single scope.
        try:
            posture = compute_posture(scope_name, graph)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc

        console.print(f"[bold]Posture: [cyan]{posture.scope}[/cyan][/bold]")
        table = Table(title=f"Frameworks applied to {posture.scope}")
        table.add_column("Framework", style="bold cyan")
        table.add_column("Controls", justify="right")
        table.add_column("Mapped", justify="right")
        table.add_column("Evidenced", justify="right")
        table.add_column("Reused", justify="right")
        table.add_column("Covered", justify="right")
        for fw in posture.frameworks:
            table.add_row(
                fw.name,
                str(fw.total),
                str(fw.mapped),
                str(fw.evidenced),
                str(fw.reused),
                str(fw.covered),
            )
        Console(width=120).print(table)
        return

    # Summary across every scope in the graph.
    table = Table(title=f"Scope Posture ({len(scope_names)} scopes)")
    table.add_column("Scope", style="bold cyan")
    table.add_column("Framework")
    table.add_column("Controls", justify="right")
    table.add_column("Mapped", justify="right")
    table.add_column("Evidenced", justify="right")
    table.add_column("Reused", justify="right")
    table.add_column("Covered", justify="right")
    for name in scope_names:
        posture = compute_posture(name, graph)
        if not posture.frameworks:
            table.add_row(name, "[dim]—[/dim]", "0", "0", "0", "0", "0")
            continue
        for i, fw in enumerate(posture.frameworks):
            table.add_row(
                name if i == 0 else "",
                fw.name,
                str(fw.total),
                str(fw.mapped),
                str(fw.evidenced),
                str(fw.reused),
                str(fw.covered),
            )
    Console(width=120).print(table)


@scope_app.command(
    name="visualize",
    help="Render the scope subgraph as Graphviz DOT (pipe to `dot -Tpng` to render).",
)
def visualize_command(
    scope_name: str = typer.Argument(
        "",
        help="Scope to render. Omit to render every declared scope.",
    ),
) -> None:
    project_dir = _require_lemma_project()
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    try:
        dot = render_scope_dot(graph, scope_filter=scope_name or None)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Plain stdout — Rich would add color codes that break `dot`.
    print(dot, end="")


def _build_aws_session(region: str) -> Any:
    """Build a boto3.Session for the given region.

    Wrapped in a function so tests can monkeypatch this seam without
    touching the real boto3 default credential chain.
    """
    import boto3
    from botocore.exceptions import NoCredentialsError

    session = boto3.Session(region_name=region)
    sts = session.client("sts")
    try:
        sts.get_caller_identity()
    except NoCredentialsError as exc:
        msg = (
            "lemma scope discover aws could not resolve AWS credentials. "
            "Configure the AWS credential chain (env vars, profile, or IMDS) "
            "and try again."
        )
        raise ValueError(msg) from exc
    return session


def _build_k8s_clients(context: str | None) -> Any:
    """Build a Kubernetes API client bundle from kubeconfig.

    Wrapped so tests can monkeypatch this seam without touching real
    kubeconfig. Returns an object exposing ``version_api``, ``core_v1``,
    and ``apps_v1`` sub-clients (the surface k8s_discovery expects).
    """
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
    from kubernetes.config.config_exception import ConfigException

    try:
        k8s_config.load_kube_config(context=context)
    except (ConfigException, FileNotFoundError) as exc:
        msg = (
            "lemma scope discover k8s could not load kubeconfig. "
            "Set KUBECONFIG or place a config at ~/.kube/config and try again."
        )
        raise ValueError(msg) from exc

    bundle = type("K8sClients", (), {})()
    bundle.version_api = k8s_client.VersionApi()
    bundle.core_v1 = k8s_client.CoreV1Api()
    bundle.apps_v1 = k8s_client.AppsV1Api()
    return bundle


def _build_gcp_client(project: str, asset_types: list[str]) -> Any:
    """Build a Cloud Asset Inventory client and validate project reachability.

    Wrapped so tests can monkeypatch this seam without touching real
    Google credentials. Probes with the first user-supplied asset type
    so an operator passing only `--asset-type storage.googleapis.com/Bucket`
    doesn't get a spurious failure when Compute API is disabled.
    """
    from google.api_core.exceptions import GoogleAPIError
    from google.auth.exceptions import DefaultCredentialsError, RefreshError
    from google.cloud import asset_v1

    try:
        client = asset_v1.AssetServiceClient()
    except (DefaultCredentialsError, RefreshError) as exc:
        msg = (
            "lemma scope discover gcp could not resolve Google credentials. "
            "Set GOOGLE_APPLICATION_CREDENTIALS or run "
            "'gcloud auth application-default login' and try again."
        )
        raise ValueError(msg) from exc

    probe_type = asset_types[0] if asset_types else "compute.googleapis.com/Instance"
    try:
        request = asset_v1.ListAssetsRequest(
            parent=f"projects/{project}",
            asset_types=[probe_type],
            page_size=1,
        )
        next(iter(client.list_assets(request=request)), None)
    except GoogleAPIError as exc:
        msg = (
            f"GCP project '{project}' is unreachable or the Cloud Asset API is "
            f"not enabled. Run 'gcloud services enable cloudasset.googleapis.com' "
            f"and verify project access. Underlying error: {exc}"
        )
        raise ValueError(msg) from exc

    return client


def _build_azure_clients(subscription: str, resource_types: list[str]) -> Any:
    """Build a Resource Graph client and validate subscription reachability.

    Validates ``resource_types`` against the allow-list **before** running
    the reachability probe so a typo'd ``--resource-type`` surfaces as a
    clean validation error rather than a confusing API failure.
    """
    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    from lemma.services.azure_discovery import _KNOWN_RESOURCE_TYPES

    unknown = [t for t in resource_types if t not in _KNOWN_RESOURCE_TYPES]
    if unknown:
        msg = (
            f"Unknown Azure resource type(s): {', '.join(unknown)}. "
            f"Known: {', '.join(_KNOWN_RESOURCE_TYPES)}."
        )
        raise ValueError(msg)

    try:
        credential = DefaultAzureCredential()
        client = ResourceGraphClient(credential)
    except ClientAuthenticationError as exc:
        msg = (
            "lemma scope discover azure could not resolve Azure credentials. "
            "Set AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET env vars "
            "or run 'az login' and try again."
        )
        raise ValueError(msg) from exc

    probe_type = resource_types[0]
    try:
        client.resources(
            QueryRequest(
                subscriptions=[subscription],
                query=f"Resources | where type =~ '{probe_type}' | take 1",
            )
        )
    except (ClientAuthenticationError, HttpResponseError) as exc:
        msg = (
            f"Azure subscription '{subscription}' is unreachable or the "
            f"Microsoft.ResourceGraph provider isn't registered. Run "
            f"'az provider register --namespace Microsoft.ResourceGraph' "
            f"and verify subscription access. Underlying error: {exc}"
        )
        raise ValueError(msg) from exc

    return client


def _build_servicenow_client(instance: str) -> Any:
    """Build an httpx.Client for a ServiceNow instance, validating reachability.

    Auth via Basic auth from ``LEMMA_SNOW_USER`` / ``LEMMA_SNOW_PASSWORD`` env
    vars (mirrors the GitHub / Okta connector pattern). Reachability probed
    with a 1-row Table API query before discovery starts.
    """
    import os

    import httpx as httpx_module

    user = os.environ.get("LEMMA_SNOW_USER")
    password = os.environ.get("LEMMA_SNOW_PASSWORD")
    if not user or not password:
        msg = (
            "lemma scope discover servicenow requires LEMMA_SNOW_USER and "
            "LEMMA_SNOW_PASSWORD environment variables."
        )
        raise ValueError(msg)

    base_url = f"https://{instance}.service-now.com"
    client = httpx_module.Client(base_url=base_url, auth=(user, password), timeout=30.0)

    try:
        response = client.get(
            "/api/now/table/cmdb_ci",
            params={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
        )
        response.raise_for_status()
    except httpx_module.HTTPStatusError as exc:
        msg = (
            f"ServiceNow instance '{instance}' returned {exc.response.status_code}. "
            f"Verify the instance name and credentials."
        )
        raise ValueError(msg) from exc
    except httpx_module.RequestError as exc:
        msg = (
            f"ServiceNow instance '{instance}' is unreachable: {exc}. "
            f"Verify the instance name and network access."
        )
        raise ValueError(msg) from exc

    return client


def _build_device42_client(url: str) -> Any:
    """Build an httpx.Client for a Device42 deployment, validating reachability.

    Auth via Basic auth from ``LEMMA_DEVICE42_USER`` / ``LEMMA_DEVICE42_PASSWORD``
    env vars. Reachability probed with a 1-row Devices query before discovery
    starts. URL must include a scheme (``https://`` or ``http://``).
    """
    import os

    import httpx as httpx_module

    user = os.environ.get("LEMMA_DEVICE42_USER")
    password = os.environ.get("LEMMA_DEVICE42_PASSWORD")
    if not user or not password:
        msg = (
            "lemma scope discover device42 requires LEMMA_DEVICE42_USER and "
            "LEMMA_DEVICE42_PASSWORD environment variables."
        )
        raise ValueError(msg)

    if not (url.startswith("http://") or url.startswith("https://")):
        msg = f"Device42 --url must include a scheme (https:// or http://); got '{url}'."
        raise ValueError(msg)

    client = httpx_module.Client(base_url=url, auth=(user, password), timeout=30.0)

    try:
        response = client.get("/api/1.0/devices/", params={"limit": "1", "offset": "0"})
        response.raise_for_status()
    except httpx_module.HTTPStatusError as exc:
        msg = (
            f"Device42 deployment '{url}' returned {exc.response.status_code}. "
            f"Verify the URL and credentials."
        )
        raise ValueError(msg) from exc
    except httpx_module.RequestError as exc:
        msg = (
            f"Device42 deployment '{url}' is unreachable: {exc}. Verify the URL and network access."
        )
        raise ValueError(msg) from exc

    return client


def _build_vsphere_clients(host: str, port: int, insecure: bool) -> Any:
    """Connect to vCenter and return the ServiceInstanceContent.

    Auth via ``LEMMA_VSPHERE_USER`` / ``LEMMA_VSPHERE_PASSWORD`` env vars.
    ``insecure=True`` skips SSL verification (lab/dev vCenters with self-signed
    certs); production should configure proper certs and leave it ``False``.
    Process exit cleans up the session — no explicit ``Disconnect()``.
    """
    import os

    from pyVim.connect import SmartConnect
    from pyVmomi import vim

    user = os.environ.get("LEMMA_VSPHERE_USER")
    password = os.environ.get("LEMMA_VSPHERE_PASSWORD")
    if not user or not password:
        msg = (
            "lemma scope discover vsphere requires LEMMA_VSPHERE_USER and "
            "LEMMA_VSPHERE_PASSWORD environment variables."
        )
        raise ValueError(msg)

    try:
        si = SmartConnect(
            host=host,
            user=user,
            pwd=password,
            port=port,
            disableSslVerification=insecure,
        )
    except vim.fault.InvalidLogin as exc:
        msg = (
            f"vCenter '{host}:{port}' rejected credentials. "
            f"Verify LEMMA_VSPHERE_USER and LEMMA_VSPHERE_PASSWORD."
        )
        raise ValueError(msg) from exc
    except Exception as exc:
        msg = f"vCenter '{host}:{port}' is unreachable: {exc}"
        raise ValueError(msg) from exc

    return si.RetrieveContent()


def _build_network_scanner(
    *,
    privileged: bool = False,
    detect_versions: bool = False,
    ipv6: bool = False,
) -> Callable[[list[str], list[int]], dict[str, dict]]:
    """Return a scan function that shells out to nmap and parses -oX XML.

    Errors loud at construction if nmap is missing, or if ``privileged`` is
    set without raw-socket capability. The default is unprivileged TCP-connect
    (``-sT -Pn``); ``--privileged`` switches to ``-sS -O`` (SYN scan + OS
    fingerprint), ``--detect-versions`` appends ``-sV``, ``--ipv6`` adds ``-6``.
    """
    import os
    import shutil

    if shutil.which("nmap") is None:
        msg = (
            "lemma scope discover network requires the nmap binary. "
            "Install it: `brew install nmap` (macOS) or `apt install nmap` (Debian/Ubuntu)."
        )
        raise ValueError(msg)

    if privileged and hasattr(os, "geteuid") and os.geteuid() != 0:
        msg = (
            "--privileged requires root (or CAP_NET_RAW on Linux) so nmap can use "
            "raw sockets for SYN scan and OS fingerprinting. Re-run under sudo, "
            "or drop --privileged to use unprivileged TCP-connect (-sT)."
        )
        raise ValueError(msg)

    scan_flag = "-sS" if privileged else "-sT"

    def _scan(cidrs: list[str], ports: list[int]) -> dict[str, dict]:
        import subprocess

        cmd = ["nmap", scan_flag, "-Pn", "-R", "-oX", "-"]
        if privileged:
            cmd.append("-O")
        if detect_versions:
            cmd.append("-sV")
        if ipv6:
            cmd.append("-6")
        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        cmd.extend(cidrs)

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            msg = f"nmap exited {result.returncode}: {detail}"
            raise ValueError(msg)

        return _parse_nmap_xml(result.stdout, ipv6=ipv6)

    return _scan


def _parse_nmap_xml(xml_text: str, *, ipv6: bool = False) -> dict[str, dict]:
    """Parse nmap -oX output into ``{ip: {hostname, open_ports, os, mac, services}}``.

    Filters down hosts and address families that don't match ``ipv6``. ``os``,
    ``mac``, and ``services`` populate when nmap returned them (i.e. the
    invocation included ``-O`` / a local subnet / ``-sV``); otherwise each is
    ``None`` and the service projector omits the corresponding attribute.
    """
    import xml.etree.ElementTree as ET

    addr_type = "ipv6" if ipv6 else "ipv4"
    out: dict[str, dict] = {}
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find(f"address[@addrtype='{addr_type}']")
        if addr is None:
            continue
        ip = addr.get("addr")
        if ip is None:
            continue
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        open_ports: list[int] = []
        services: dict[str, dict] = {}
        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port_el.get("portid")
            if portid is None:
                continue
            open_ports.append(int(portid))
            svc_el = port_el.find("service")
            if svc_el is not None:
                attrs = {
                    k: svc_el.get(k)
                    for k in ("name", "product", "version", "extrainfo")
                    if svc_el.get(k)
                }
                if attrs:
                    services[portid] = attrs

        os_info: dict[str, Any] | None = None
        best = host.find("os/osmatch")
        if best is not None:
            osclass = best.find("osclass")
            family = (osclass.get("osfamily") if osclass is not None else "") or ""
            os_info = {
                "name": best.get("name") or "",
                "family": family.lower(),
                "accuracy": int(best.get("accuracy") or 0),
            }

        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get("addr").lower() if mac_el is not None and mac_el.get("addr") else None

        out[ip] = {
            "hostname": hostname,
            "open_ports": sorted(open_ports),
            "os": os_info,
            "mac": mac,
            "services": services or None,
        }
    return out


_VALID_PROVIDERS = (
    "aws",
    "terraform",
    "k8s",
    "gcp",
    "azure",
    "file",
    "ansible",
    "servicenow",
    "device42",
    "vsphere",
    "network",
)


def _validate_provider(provider: str) -> None:
    if provider not in _VALID_PROVIDERS:
        console.print(
            f"[red]Error:[/red] Unknown provider '{provider}'. "
            f"Currently supported: {', '.join(_VALID_PROVIDERS)}."
        )
        raise typer.Exit(code=1)


def _build_candidates_for_provider(provider: str, **flags: Any) -> tuple[list, str]:
    """Build provider auth + invoke discover_resources. Returns (candidates, label).

    Used by both ``discover_command`` and ``drift_command``. Raises
    ``typer.Exit(1)`` with a printed error on missing flags or auth/discover
    failure (same exit semantics either command had inline today).
    """
    if provider == "aws":
        services = [s.strip() for s in flags["service"].split(",") if s.strip()]
        try:
            session = _build_aws_session(flags["region"])
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                aws_discover_resources(session=session, region=flags["region"], services=services),
                "AWS",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "terraform":
        if not flags["path"]:
            console.print("[red]Error:[/red] --path is required when provider is 'terraform'.")
            raise typer.Exit(code=1)
        try:
            return tf_state_discover_resources(Path(flags["path"])), "Terraform-state"
        except (ValueError, FileNotFoundError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "k8s":
        kinds = [k.strip() for k in flags["kind"].split(",") if k.strip()]
        namespaces = [n.strip() for n in flags["namespace"].split(",") if n.strip()] or None
        try:
            api_client = _build_k8s_clients(flags["context"] or None)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                k8s_discover_resources(
                    api_client=api_client,
                    context=flags["context"] or None,
                    namespaces=namespaces,
                    kinds=kinds,
                ),
                "Kubernetes",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "gcp":
        if not flags["project"]:
            console.print("[red]Error:[/red] --project is required when provider is 'gcp'.")
            raise typer.Exit(code=1)
        asset_types = [t.strip() for t in flags["asset_type"].split(",") if t.strip()]
        try:
            asset_client = _build_gcp_client(flags["project"], asset_types)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                gcp_discover_resources(
                    asset_client=asset_client,
                    project=flags["project"],
                    asset_types=asset_types,
                ),
                "GCP",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "azure":
        sub = flags["subscription"].strip()
        if not sub:
            console.print("[red]Error:[/red] --subscription is required when provider is 'azure'.")
            raise typer.Exit(code=1)
        resource_types = [t.strip() for t in flags["resource_type"].split(",") if t.strip()]
        try:
            rg_client = _build_azure_clients(sub, resource_types)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                azure_discover_resources(
                    rg_client=rg_client, subscription=sub, resource_types=resource_types
                ),
                "Azure",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "file":
        if not flags["path"]:
            console.print("[red]Error:[/red] --path is required when provider is 'file'.")
            raise typer.Exit(code=1)
        try:
            return file_discover_resources(Path(flags["path"])), "file"
        except (ValueError, FileNotFoundError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "ansible":
        if not flags["inventory"]:
            console.print("[red]Error:[/red] --inventory is required when provider is 'ansible'.")
            raise typer.Exit(code=1)
        try:
            return ansible_discover_resources(Path(flags["inventory"])), "ansible"
        except (ValueError, FileNotFoundError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "servicenow":
        inst = flags["instance"].strip()
        if not inst:
            console.print("[red]Error:[/red] --instance is required when provider is 'servicenow'.")
            raise typer.Exit(code=1)
        try:
            sn_client = _build_servicenow_client(inst)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                servicenow_discover_resources(
                    client=sn_client, instance=inst, ci_class=flags["ci_class"]
                ),
                "servicenow",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "device42":
        deployment_url = flags["url"].strip()
        if not deployment_url:
            console.print("[red]Error:[/red] --url is required when provider is 'device42'.")
            raise typer.Exit(code=1)
        try:
            d42_client = _build_device42_client(deployment_url)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                device42_discover_resources(client=d42_client, url=deployment_url),
                "device42",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    if provider == "vsphere":
        vc_host = flags["vsphere_host"].strip()
        if not vc_host:
            console.print("[red]Error:[/red] --host is required when provider is 'vsphere'.")
            raise typer.Exit(code=1)
        kinds = [k.strip() for k in flags["vsphere_kind"].split(",") if k.strip()]
        try:
            vsphere_content = _build_vsphere_clients(
                vc_host, flags["vsphere_port"], flags["insecure"]
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        try:
            return (
                vsphere_discover_resources(
                    content=vsphere_content,
                    vc_host=vc_host,
                    datacenter=flags["datacenter"] or None,
                    kinds=kinds,
                ),
                "vsphere",
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    # provider == "network"
    cidr_list = [c.strip() for c in flags["cidr"].split(",") if c.strip()]
    if not cidr_list:
        console.print("[red]Error:[/red] --cidr is required when provider is 'network'.")
        raise typer.Exit(code=1)
    try:
        port_list = [int(p.strip()) for p in flags["network_port"].split(",") if p.strip()]
    except ValueError as exc:
        console.print(
            f"[red]Error:[/red] --network-port must be a comma-separated list of integers: {exc}"
        )
        raise typer.Exit(code=1) from exc
    try:
        scan_fn = _build_network_scanner(
            privileged=flags["privileged"],
            detect_versions=flags["detect_versions"],
            ipv6=flags["ipv6"],
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    try:
        return (
            network_discover_resources(
                scan_function=scan_fn,
                cidrs=cidr_list,
                ports=port_list,
                label=flags["label"] or None,
                ipv6=flags["ipv6"],
            ),
            "network",
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@scope_app.command(
    name="discover",
    help=(
        "Auto-discover resources into the graph. Provider must be one of: "
        "aws, terraform, k8s, gcp, azure, file, ansible, servicenow, device42, "
        "vsphere, network."
    ),
)
def discover_command(
    provider: str = typer.Argument(
        help=(
            "Discovery source (one of: "
            "aws, terraform, k8s, gcp, azure, file, ansible, servicenow, "
            "device42, vsphere, network)."
        ),
    ),
    region: str = typer.Option(
        "us-east-1",
        "--region",
        help="AWS region for region-scoped APIs (EC2). aws only.",
    ),
    service: str = typer.Option(
        "ec2,s3,iam",
        "--service",
        help="Comma-separated AWS services to enumerate. aws only.",
    ),
    path: str = typer.Option(
        "",
        "--path",
        help="Path to terraform.tfstate. terraform only.",
    ),
    context: str = typer.Option(
        "",
        "--context",
        help="kubeconfig context to use. k8s only; default = current context.",
    ),
    namespace: str = typer.Option(
        "",
        "--namespace",
        help="Comma-separated k8s namespace(s) to restrict to. k8s only; default = all.",
    ),
    kind: str = typer.Option(
        "namespace,deployment,service",
        "--kind",
        help="Comma-separated k8s kinds to enumerate. k8s only.",
    ),
    project: str = typer.Option(
        "",
        "--project",
        help="GCP project id. gcp only; required when provider is 'gcp'.",
    ),
    asset_type: str = typer.Option(
        "compute.googleapis.com/Instance,storage.googleapis.com/Bucket,iam.googleapis.com/ServiceAccount",
        "--asset-type",
        help="Comma-separated CAI asset types. gcp only.",
    ),
    subscription: str = typer.Option(
        "",
        "--subscription",
        help="Azure subscription id. azure only; required when provider is 'azure'.",
    ),
    resource_type: str = typer.Option(
        "microsoft.compute/virtualmachines,microsoft.storage/storageaccounts,microsoft.managedidentity/userassignedidentities",
        "--resource-type",
        help="Comma-separated Azure resource types. azure only.",
    ),
    inventory: str = typer.Option(
        "",
        "--inventory",
        help="Path to `ansible-inventory --list` JSON output. ansible only.",
    ),
    instance: str = typer.Option(
        "",
        "--instance",
        help=(
            "ServiceNow instance name (the <name> in https://<name>.service-now.com). "
            "servicenow only."
        ),
    ),
    ci_class: str = typer.Option(
        "cmdb_ci",
        "--ci-class",
        help=(
            "ServiceNow CI table to query. servicenow only. "
            "Default `cmdb_ci` (parent — all subclasses)."
        ),
    ),
    url: str = typer.Option(
        "",
        "--url",
        help="Device42 deployment URL (e.g. https://d42.example.com). device42 only.",
    ),
    vsphere_host: str = typer.Option(
        "",
        "--host",
        help="vCenter hostname (e.g. vcenter.example.com). vsphere only.",
    ),
    vsphere_port: int = typer.Option(
        443,
        "--port",
        help="vCenter port. vsphere only; default 443.",
    ),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="Skip vCenter SSL verification (lab/dev only). vsphere only.",
    ),
    datacenter: str = typer.Option(
        "",
        "--datacenter",
        help="Datacenter name filter. vsphere only; default = all datacenters.",
    ),
    vsphere_kind: str = typer.Option(
        "vm,host,datastore",
        "--vsphere-kind",
        help="Comma-separated vSphere kinds to enumerate. vsphere only.",
    ),
    cidr: str = typer.Option(
        "",
        "--cidr",
        help="Comma-separated CIDR(s) to scan (e.g. 10.0.0.0/24,10.0.1.0/24). network only.",
    ),
    network_port: str = typer.Option(
        "22,80,443,3389,445,3306,5432,8080",
        "--network-port",
        help=(
            "Comma-separated TCP ports to probe per host. network only. "
            "Empty = host-discovery only."
        ),
    ),
    label: str = typer.Option(
        "",
        "--label",
        help=(
            "Optional label baked into discovered resource ids "
            "(network-<label>-<ip>). network only."
        ),
    ),
    privileged: bool = typer.Option(
        False,
        "--privileged",
        help=(
            "Enable nmap SYN scan + OS fingerprinting (-sS -O). Requires root / "
            "CAP_NET_RAW. network only."
        ),
    ),
    detect_versions: bool = typer.Option(
        False,
        "--detect-versions",
        help=(
            "Enable nmap service-version detection (-sV). Adds banners to "
            "attributes.network.services.<port>. network only."
        ),
    ),
    ipv6: bool = typer.Option(
        False,
        "--ipv6",
        help="Scan IPv6 CIDR(s) instead of IPv4. network only.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print matched resources as YAML to stdout; do not write to the graph.",
    ),
) -> None:
    _validate_provider(provider)

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
            "[red]Error:[/red] No scopes declared. "
            "Run [bold]lemma scope init[/bold] to create one, then re-run discover."
        )
        raise typer.Exit(code=1)

    candidates, source_label = _build_candidates_for_provider(
        provider,
        region=region,
        service=service,
        path=path,
        context=context,
        namespace=namespace,
        kind=kind,
        project=project,
        asset_type=asset_type,
        subscription=subscription,
        resource_type=resource_type,
        inventory=inventory,
        instance=instance,
        ci_class=ci_class,
        url=url,
        vsphere_host=vsphere_host,
        vsphere_port=vsphere_port,
        insecure=insecure,
        datacenter=datacenter,
        vsphere_kind=vsphere_kind,
        cidr=cidr,
        network_port=network_port,
        label=label,
        privileged=privileged,
        detect_versions=detect_versions,
        ipv6=ipv6,
    )

    scope_by_name = {s.name: s for s in scopes}
    matched: list = []
    matched_attribution: list[dict[str, list[dict]]] = []
    skipped_no_match = 0
    for resource in candidates:
        match_names = sorted(scopes_containing(resource.attributes, scopes))
        if not match_names:
            console.print(f"[dim]No scope match for {resource.id}; skipping.[/dim]")
            skipped_no_match += 1
            continue
        # Pydantic models are immutable-ish; rebuild with scopes set.
        matched.append(resource.model_copy(update={"scopes": match_names}))
        # Attribution: every rule in a matched scope fired (the matcher
        # requires all rules to pass for the scope to match).
        matched_attribution.append(
            {
                name: [
                    {"source": r.source, "operator": r.operator.value, "value": r.value}
                    for r in scope_by_name[name].match_rules
                ]
                for name in match_names
            }
        )

    if dry_run:
        # Emit YAML preview — one document per matched resource.
        previews = [r.model_dump() for r in matched]
        console.print("[bold]Dry run — matched resources:[/bold]")
        print(yaml.safe_dump_all(previews, sort_keys=False), end="")
        return

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)
    for resource, attribution in zip(matched, matched_attribution, strict=True):
        graph.add_resource(
            resource_id=resource.id,
            type_=resource.type,
            scopes=resource.scopes,
            attributes=resource.attributes,
            impacts=resource.impacts,
            matched_rules_by_scope=attribution,
        )
    graph.save(graph_path)

    console.print(
        f"[green]Discovered[/green] {len(candidates)} {source_label} resource(s); "
        f"{len(matched)} scoped, {skipped_no_match} skipped (no scope match)."
    )


@scope_app.command(
    name="drift",
    help=(
        "Compare a provider's current discover output against the graph and report "
        "the SCOPED_TO delta. --apply mutates (and prunes deleted Resources)."
    ),
)
def drift_command(
    provider: str = typer.Argument(
        help="Discovery source — same set as `lemma scope discover`.",
    ),
    region: str = typer.Option("us-east-1", "--region"),
    service: str = typer.Option("ec2,s3,iam", "--service"),
    path: str = typer.Option("", "--path"),
    context: str = typer.Option("", "--context"),
    namespace: str = typer.Option("", "--namespace"),
    kind: str = typer.Option("namespace,deployment,service", "--kind"),
    project: str = typer.Option("", "--project"),
    asset_type: str = typer.Option(
        "compute.googleapis.com/Instance,storage.googleapis.com/Bucket,iam.googleapis.com/ServiceAccount",
        "--asset-type",
    ),
    subscription: str = typer.Option("", "--subscription"),
    resource_type: str = typer.Option(
        "microsoft.compute/virtualmachines,microsoft.storage/storageaccounts,microsoft.managedidentity/userassignedidentities",
        "--resource-type",
    ),
    inventory: str = typer.Option("", "--inventory"),
    instance: str = typer.Option("", "--instance"),
    ci_class: str = typer.Option("cmdb_ci", "--ci-class"),
    url: str = typer.Option("", "--url"),
    vsphere_host: str = typer.Option("", "--host"),
    vsphere_port: int = typer.Option(443, "--port"),
    insecure: bool = typer.Option(False, "--insecure"),
    datacenter: str = typer.Option("", "--datacenter"),
    vsphere_kind: str = typer.Option("vm,host,datastore", "--vsphere-kind"),
    cidr: str = typer.Option("", "--cidr"),
    network_port: str = typer.Option("22,80,443,3389,445,3306,5432,8080", "--network-port"),
    label: str = typer.Option("", "--label"),
    privileged: bool = typer.Option(False, "--privileged"),
    detect_versions: bool = typer.Option(False, "--detect-versions"),
    ipv6: bool = typer.Option(False, "--ipv6"),
    apply: bool = typer.Option(
        False,
        "--apply",
        help=(
            "Apply the drift to the graph: re-evaluate scope memberships for "
            "changed resources, prune Resource nodes the live infrastructure no "
            "longer has. Without --apply this is a read-only report."
        ),
    ),
) -> None:
    _validate_provider(provider)
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
            "[red]Error:[/red] No scopes declared. "
            "Run [bold]lemma scope init[/bold] to create one, then re-run drift."
        )
        raise typer.Exit(code=1)

    candidates, _label = _build_candidates_for_provider(
        provider,
        region=region,
        service=service,
        path=path,
        context=context,
        namespace=namespace,
        kind=kind,
        project=project,
        asset_type=asset_type,
        subscription=subscription,
        resource_type=resource_type,
        inventory=inventory,
        instance=instance,
        ci_class=ci_class,
        url=url,
        vsphere_host=vsphere_host,
        vsphere_port=vsphere_port,
        insecure=insecure,
        datacenter=datacenter,
        vsphere_kind=vsphere_kind,
        cidr=cidr,
        network_port=network_port,
        label=label,
        privileged=privileged,
        detect_versions=detect_versions,
        ipv6=ipv6,
    )

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)
    existing = graph.iter_resources()

    report = compute_drift(
        existing_resources=existing,
        fresh_candidates=candidates,
        scopes=scopes,
    )

    if not report.has_drift:
        console.print(f"[green]No drift.[/green] {len(report.entries)} resource(s) checked.")
        return

    table = Table(
        title=f"Scope Drift ({sum(1 for e in report.entries if e.status != 'unchanged')} changes)"
    )
    table.add_column("Resource", style="bold cyan")
    table.add_column("Status")
    table.add_column("Entered")
    table.add_column("Exited")
    table.add_column("Attribute changes")
    for entry in report.entries:
        if entry.status == "unchanged":
            continue
        attr_summary = (
            ", ".join(f"{k}: {b!r}→{a!r}" for k, (b, a) in entry.attribute_changes.items()) or "—"
        )
        table.add_row(
            entry.resource_id,
            entry.status,
            ", ".join(entry.entered_scopes) or "—",
            ", ".join(entry.exited_scopes) or "—",
            attr_summary,
        )
    Console(width=140).print(table)

    if not apply:
        console.print(
            "[yellow]Drift detected.[/yellow] Re-run with [bold]--apply[/bold] to update the graph."
        )
        raise typer.Exit(code=1)

    scope_by_name = {s.name: s for s in scopes}
    candidates_by_id = {c.id: c for c in candidates}
    applied_changes = 0
    pruned = 0
    for entry in report.entries:
        if entry.status == "unchanged":
            continue
        if entry.status == "deleted":
            graph.remove_resource(entry.resource_id)
            pruned += 1
            continue
        candidate = candidates_by_id[entry.resource_id]
        match_names = sorted(scopes_containing(candidate.attributes, scopes))
        if not match_names:
            graph.remove_resource(entry.resource_id)
            pruned += 1
            continue
        attribution = {
            name: [
                {"source": r.source, "operator": r.operator.value, "value": r.value}
                for r in scope_by_name[name].match_rules
            ]
            for name in match_names
        }
        graph.add_resource(
            resource_id=candidate.id,
            type_=candidate.type,
            scopes=match_names,
            attributes=candidate.attributes,
            impacts=candidate.impacts,
            matched_rules_by_scope=attribution,
        )
        applied_changes += 1
    graph.save(graph_path)
    console.print(
        f"[green]Applied[/green] {applied_changes} resource update(s); "
        f"pruned {pruned} stale Resource node(s)."
    )


def _wait_for_shutdown(observer: Any) -> None:  # pragma: no cover - OS signal-driven
    """Block until SIGINT/SIGTERM, then return so the caller can stop the observer.

    Pulled out so `lemma scope watch` tests can monkeypatch this to return
    immediately without a real signal arriving.
    """
    import signal
    import threading

    stop_event = threading.Event()

    def _handler(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)
    stop_event.wait()


@scope_app.command(
    name="watch",
    help=(
        "Foreground daemon: re-validate scopes/resources whenever YAML/HCL files "
        "in the project change. Re-evaluates existing Resources against new rules "
        "so YAML edits propagate to scope memberships instantly."
    ),
)
def watch_command(
    debounce_ms: int = typer.Option(
        300,
        "--debounce-ms",
        help="Coalesce file events fired within this window (default 300ms).",
    ),
) -> None:
    import threading
    import time

    project_dir = _require_lemma_project()
    scopes_dir = project_dir / "scopes"
    resources_dir = project_dir / "resources"

    pending = threading.Event()
    debounce_window = max(debounce_ms, 0) / 1000.0

    class _ReloadHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            src = str(getattr(event, "src_path", ""))
            if not src.endswith((".yaml", ".yml", ".hcl")):
                return
            pending.set()

    handler = _ReloadHandler()
    observer = Observer()
    if scopes_dir.exists():
        observer.schedule(handler, str(scopes_dir), recursive=False)
    if resources_dir.exists():
        observer.schedule(handler, str(resources_dir), recursive=False)
    observer.start()

    console.print(
        f"[green]Watching[/green] {scopes_dir.relative_to(project_dir)}/ and "
        f"{resources_dir.relative_to(project_dir)}/ — Ctrl+C to stop."
    )

    def _drain_loop():  # pragma: no cover - background thread; tested via reload_after_yaml_change
        while True:
            if not pending.wait(timeout=1.0):
                continue
            time.sleep(debounce_window)
            pending.clear()
            try:
                summary = reload_after_yaml_change(project_dir)
            except ValueError as exc:
                console.print(f"[red]Error:[/red] {exc}")
                continue
            stamp = time.strftime("%H:%M:%S")
            console.print(
                f"[dim]{stamp}[/dim] reloaded {summary['scopes_loaded']} scope(s), "
                f"{summary['resources_loaded']} resource(s); "
                f"propagated {summary['propagated']}, pruned {summary['pruned']}."
            )

    drain_thread = threading.Thread(target=_drain_loop, daemon=True)
    drain_thread.start()

    try:
        _wait_for_shutdown(observer)
    finally:
        observer.stop()
        observer.join()
