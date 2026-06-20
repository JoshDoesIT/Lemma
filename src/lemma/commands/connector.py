"""Implementation of ``lemma connector`` CLI subcommands.

Subcommands:
    lemma connector init <name>     — scaffold a new connector project
    lemma connector test <path>     — validate a connector's output
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import typer
from rich.console import Console

from lemma.models.connector_manifest import ConnectorManifest
from lemma.sdk.connector import Connector

console = Console()

connector_app = typer.Typer(
    name="connector",
    help="Build, scaffold, and test Lemma connectors.",
    no_args_is_help=True,
)


_CONNECTOR_PY_TEMPLATE = '''"""Scaffolded Lemma connector: {name}.

Edit ``collect`` to yield OCSF events from your upstream source. When
you run ``lemma connector test .`` from this directory, the CLI
imports this module, instantiates the connector, and validates the
output against the OCSF schema.

Delete the reference JsonlConnector inheritance below and implement a
real source when you're ready — the JsonlConnector is here so the
scaffolded project works end-to-end out of the box.
"""

from __future__ import annotations

from pathlib import Path

from lemma.sdk.reference.jsonl import JsonlConnector


class Connector(JsonlConnector):
    """The entry point ``lemma connector test`` looks for.

    Replace the body with your own ``collect`` and a non-JSONL-backed
    upstream when you move past the scaffold.
    """

    def __init__(self) -> None:
        super().__init__(
            source=Path(__file__).parent / "fixtures" / "events.jsonl",
            producer="{producer}",
        )
'''

_README_TEMPLATE = """# {name} — Lemma Connector

Scaffolded by `lemma connector init`.

## Next steps

1. Edit `connector.py` — replace the JSONL reference source with your
   real upstream integration.
2. Drop a few sample OCSF events into `fixtures/events.jsonl` so
   `lemma connector test .` has something to exercise.
3. Validate with `lemma connector test .` before publishing.

## Layout

```
{name}/
  manifest.json     # identity + capabilities
  connector.py      # Connector subclass entry point
  fixtures/
    events.jsonl    # sample events for local testing
  README.md
```
"""


def _fail(msg: str) -> None:
    console.print(f"[red]Error:[/red] {msg}")
    raise typer.Exit(code=1)


def _secret_store():
    """Open the project's encrypted secret store (Refs #117)."""
    import os

    from lemma.services.secret_store import SecretStore

    project = Path.cwd()
    if not (project / ".lemma").exists():
        _fail("Not a Lemma project. Run `lemma init` first.")
    if not os.environ.get("LEMMA_SECRET_PASSPHRASE"):
        _fail(
            "Set LEMMA_SECRET_PASSPHRASE in the environment to unlock the encrypted secret store."
        )
    return SecretStore(project / ".lemma" / "secrets.json")


@connector_app.command(
    name="set-secret",
    help="Store or rotate a connector credential in the encrypted secret store.",
)
def set_secret_command(
    name: str = typer.Argument(help="Secret name, referenced as ${secret:NAME} in config"),
) -> None:
    """Set/rotate a secret. The value is read from the LEMMA_SECRET_VALUE env
    var if set, otherwise prompted (hidden) — never passed as an argument, so
    it can't leak into shell history or process listings."""
    import os

    store = _secret_store()
    value = os.environ.get("LEMMA_SECRET_VALUE")
    if value is None:
        value = typer.prompt(f"Value for secret '{name}'", hide_input=True)
    if not value:
        _fail("Refusing to store an empty secret value.")

    existed = name in store.names()
    try:
        store.set(name, value)
    except ValueError as exc:
        _fail(str(exc))

    verb = "Rotated" if existed else "Stored"
    console.print(
        f"[green]{verb}[/green] secret [cyan]{name}[/cyan]. "
        f"Reference it in config as [bold]${{secret:{name}}}[/bold]."
    )


@connector_app.command(
    name="list-secrets",
    help="List the names of stored connector secrets (never the values).",
)
def list_secrets_command() -> None:
    store = _secret_store()
    try:
        names = store.names()
    except ValueError as exc:
        _fail(str(exc))

    if not names:
        console.print("[dim]No secrets stored. Add one with `lemma connector set-secret`.[/dim]")
        return
    for name in names:
        console.print(f"• {name}")


@connector_app.command(
    name="rm-secret",
    help="Remove a stored connector secret.",
)
def rm_secret_command(
    name: str = typer.Argument(help="Secret name to remove"),
) -> None:
    store = _secret_store()
    try:
        if name not in store.names():
            _fail(f"No secret named '{name}' is stored.")
        store.delete(name)
    except ValueError as exc:
        _fail(str(exc))
    console.print(f"[green]Removed[/green] secret [cyan]{name}[/cyan].")


@connector_app.command(
    name="init",
    help="Scaffold a new connector project with a working reference implementation.",
)
def init_command(
    name: str = typer.Argument(help="Name of the connector project (path-safe)"),
    producer: str = typer.Option(
        "",
        "--producer",
        help=(
            "Signing identity for events this connector will emit. Defaults to the project name."
        ),
    ),
) -> None:
    cwd = Path.cwd()
    project = cwd / name
    if project.exists():
        _fail(f"Path {project} already exists. Pick a different name.")

    effective_producer = producer or name

    project.mkdir(parents=True)
    (project / "fixtures").mkdir()

    manifest = ConnectorManifest(
        name=name,
        version="0.1.0",
        producer=effective_producer,
        description=f"Scaffolded Lemma connector for {name}.",
    )
    (project / "manifest.json").write_text(manifest.model_dump_json(indent=2))

    (project / "connector.py").write_text(
        _CONNECTOR_PY_TEMPLATE.format(name=name, producer=effective_producer)
    )
    (project / "README.md").write_text(_README_TEMPLATE.format(name=name))

    (project / "fixtures" / "events.jsonl").write_text("")

    console.print(
        f"Scaffolded [cyan]{name}[/cyan] at {project}. "
        f"Edit [bold]connector.py[/bold] and run [bold]lemma connector test {name}[/bold]."
    )


def _load_connector_module(project: Path):
    """Dynamically import ``connector.py`` from a project directory."""
    connector_py = project / "connector.py"
    if not connector_py.exists():
        _fail(f"{connector_py} does not exist.")
    spec = importlib.util.spec_from_file_location(
        f"lemma_connector_project_{project.name}", connector_py
    )
    if spec is None or spec.loader is None:
        _fail(f"Could not load {connector_py}.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@connector_app.command(
    name="test",
    help="Validate a connector project's output against the OCSF schema.",
)
def test_command(
    path: str = typer.Argument(
        help="Path to a connector project created by `lemma connector init`",
    ),
) -> None:
    project = Path(path)
    if not project.exists() or not project.is_dir():
        _fail(f"Connector project {project} does not exist.")

    module = _load_connector_module(project)
    connector_cls = getattr(module, "Connector", None)
    if connector_cls is None or not isinstance(connector_cls, type):
        _fail(f"{project}/connector.py must define a class named 'Connector'.")
    if not issubclass(connector_cls, Connector):
        _fail(f"{project}/connector.py::Connector must subclass lemma.sdk.connector.Connector.")

    connector = connector_cls()

    try:
        events = list(connector.collect())
    except (ValueError, FileNotFoundError) as exc:
        _fail(str(exc))

    console.print(
        f"[green]OK[/green] Connector [cyan]{connector.manifest.name}[/cyan] "
        f"emitted {len(events)} event(s). All events validated against the OCSF schema."
    )
