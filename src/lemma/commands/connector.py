"""Implementation of ``lemma connector`` CLI subcommands.

Subcommands:
    lemma connector init <name>     — scaffold a new connector project
    lemma connector test <path>     — validate a connector's output
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

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


@connector_app.command(
    name="registry",
    help="List the available first-party connectors and their required config.",
)
def registry_command() -> None:
    """Show the connector registry — the catalog of available connectors."""
    from lemma.services.connector_registry import FIRST_PARTY_REGISTRY

    table = Table(title=f"First-party connectors ({len(FIRST_PARTY_REGISTRY)})")
    table.add_column("Name", style="bold cyan")
    table.add_column("Producer")
    table.add_column("Config keys")
    table.add_column("Secret (env var)")
    table.add_column("Description")
    for d in sorted(FIRST_PARTY_REGISTRY, key=lambda x: x.name):
        table.add_row(
            d.name,
            d.producer,
            ", ".join(d.config_keys) or "—",
            d.required_secret or "—",
            d.description,
        )
    # Wider console so the secret/description columns aren't truncated on
    # narrow terminals (mirrors `lemma evidence log`).
    Console(width=160).print(table)
    console.print(
        "\nUse a connector via [bold]lemma evidence collect <name>[/bold] or a "
        "[bold]lemma_connector_config.yaml[/bold] (see `lemma evidence collect --config`)."
    )


@connector_app.command(
    name="validate",
    help=(
        "Validate a connector manifest against the registry schema: path-safe "
        "name, semantic version, and at least one declared capability."
    ),
)
def validate_command(
    file: str = typer.Argument(help="Path to a connector manifest (.json / .yaml)."),
) -> None:
    import yaml

    from lemma.services.manifest_validation import validate_manifest

    path = Path(file)
    if not path.exists():
        _fail(f"{path}: file not found.")
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        _fail(f"{path.name}: could not parse manifest ({exc}).")

    errors = validate_manifest(data)
    if errors:
        console.print(f"[red]✗[/red] {path.name}: {len(errors)} validation error(s):")
        for error in errors:
            console.print(f"  • {error}")
        raise typer.Exit(code=1)

    name = data.get("name") if isinstance(data, dict) else path.name
    console.print(f"[green]✓[/green] {name}: manifest is valid.")


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


def _sleep_until(target) -> None:
    """Sleep until ``target`` (a tz-aware datetime). Seam for tests."""
    import time
    from datetime import UTC, datetime

    seconds = (target - datetime.now(UTC)).total_seconds()
    if seconds > 0:
        time.sleep(seconds)


def _run_connector_once(connector, evidence_log) -> None:
    """Collect from ``connector`` into ``evidence_log`` and report the tally."""
    result = connector.run(evidence_log)
    console.print(
        f"[green]Collected[/green] from [cyan]{connector.manifest.name}[/cyan]: "
        f"{result.ingested} new, {result.skipped_duplicates} duplicate(s) skipped."
    )


@connector_app.command(
    name="run",
    help="Run a configured connector once, or on its schedule (pull execution model).",
)
def run_command(
    config: str = typer.Option(
        ...,
        "--config",
        help="Path to a lemma_connector_config.yaml describing the connector to run.",
    ),
    once: bool = typer.Option(
        False,
        "--once",
        help="Run a single collection now and exit (ignores the schedule).",
    ),
    max_runs: int = typer.Option(
        0,
        "--max-runs",
        help="Stop after this many scheduled runs (0 = run indefinitely).",
        min=0,
    ),
) -> None:
    """Scheduled "pull" execution for a connector (Refs #111).

    Loads the connector from a config file (the same format as
    ``lemma evidence collect --config``), then either runs it once
    (``--once``) or repeatedly on the config's cron ``schedule`` — no external
    orchestrator required. Each run appends to the project's signed evidence
    log, deduped by the log's per-day guard.
    """
    import os
    from datetime import UTC, datetime

    from lemma.services.connector_config import load_connector_config
    from lemma.services.cron import CronSchedule
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.secret_backends import resolve_secret_backend

    project = Path.cwd()
    if not (project / ".lemma").exists():
        _fail("Not a Lemma project. Run `lemma init` first.")

    try:
        # Backend selected via LEMMA_SECRET_BACKEND (default: the local store,
        # used only when LEMMA_SECRET_PASSPHRASE is set so plain ${ENV_VAR}
        # configs keep working with no passphrase).
        secret_store = resolve_secret_backend(project_root=project, env=os.environ)
        cfg = load_connector_config(Path(config), secret_store=secret_store)
    except (FileNotFoundError, ValueError) as exc:
        _fail(str(exc))

    if not cfg.enabled:
        console.print(
            f"[yellow]Connector '{cfg.connector}' is disabled in config; skipping.[/yellow]"
        )
        return

    # Reuse the first-party connector factory from the evidence command.
    from lemma.commands.evidence import _connector_from_config_dict

    try:
        connector = _connector_from_config_dict(cfg.connector, cfg.config)
    except ValueError as exc:
        _fail(str(exc))

    evidence_log = EvidenceLog(log_dir=project / ".lemma" / "evidence")

    if once:
        _run_connector_once(connector, evidence_log)
        return

    if not cfg.schedule:
        _fail(
            "This config has no `schedule`; add a cron expression (e.g. "
            "`schedule: '*/30 * * * *'`) or use --once."
        )
    try:
        schedule = CronSchedule.parse(cfg.schedule)
    except ValueError as exc:
        _fail(f"Invalid schedule '{cfg.schedule}': {exc}")

    console.print(
        f"Scheduling [cyan]{cfg.connector}[/cyan] on [bold]{cfg.schedule}[/bold]"
        + (f" for {max_runs} run(s)." if max_runs else " (Ctrl-C to stop).")
    )
    runs = 0
    while True:
        due = schedule.next_after(datetime.now(UTC))
        _sleep_until(due)
        _run_connector_once(connector, evidence_log)
        runs += 1
        if max_runs and runs >= max_runs:
            break


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


def _parse_events_file(path: Path) -> list[tuple[str, dict]]:
    """Load OCSF events from a fixture file as ``(label, event_dict)`` pairs.

    Accepts either a JSON document (a single event object or an array of them)
    or JSON Lines (one event per line). ``label`` identifies the event in error
    messages — ``line N`` for JSONL, ``event N`` for a JSON array — so a
    failure points at the exact offending record.
    """
    text = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    else:
        if isinstance(doc, dict):
            return [("event 1", doc)]
        if isinstance(doc, list):
            return [(f"event {i + 1}", e) for i, e in enumerate(doc)]
        _fail(f"{path}: expected an OCSF event object or array, got {type(doc).__name__}.")

    # JSON Lines: one event per non-blank line; line numbers track the file.
    events: list[tuple[str, dict]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            events.append((f"line {lineno}", json.loads(raw)))
        except json.JSONDecodeError as exc:
            _fail(f"{path} line {lineno}: not valid JSON ({exc.msg}).")
    return events


def _validate_events_fixture(path: Path) -> None:
    """Validate an emitted OCSF event fixture against the canonical schema.

    The cross-language path: a connector authored in any language (e.g. the
    TypeScript SDK) emits its events to a file, and this validates them against
    the same OCSF models a Python connector's output is held to (#228).
    """
    from pydantic import ValidationError

    from lemma.models.ocsf import validate_ocsf_event

    events = _parse_events_file(path)
    if not events:
        _fail(f"No events found in {path}.")

    for label, event in events:
        if not isinstance(event, dict):
            _fail(f"{path} {label}: expected an OCSF event object, got {type(event).__name__}.")
        try:
            validate_ocsf_event(event)
        except ValidationError as exc:
            _fail(f"{path} {label}: invalid OCSF event.\n{exc}")

    console.print(
        f"[green]OK[/green] {len(events)} event(s) in [cyan]{path.name}[/cyan] "
        "validated against the OCSF schema."
    )


@connector_app.command(
    name="test",
    help="Validate a connector project's output (or an emitted OCSF fixture) against the schema.",
)
def test_command(
    path: str = typer.Argument(
        help=(
            "A connector project created by `lemma connector init`, or a fixture "
            "file (.jsonl/.json) of emitted OCSF events to validate."
        ),
    ),
) -> None:
    project = Path(path)
    if not project.exists():
        _fail(f"{project} does not exist.")
    # A file is an emitted-events fixture (the cross-language validation path);
    # a directory is a Python connector project.
    if project.is_file():
        _validate_events_fixture(project)
        return

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


@connector_app.command(
    name="package",
    help="Bundle a connector project into a signed, verifiable <name>-<version>.tar.gz.",
)
def package_command(
    path: str = typer.Argument(
        help="A connector project directory (as created by `lemma connector init`).",
    ),
    output: str = typer.Option(
        "",
        "--output",
        "-o",
        help="Directory to write the tarball into (default: the project's parent).",
    ),
    key_dir: str = typer.Option(
        "",
        "--key-dir",
        help="Keystore for the signing identity (default: <project>/.keys).",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing package tarball."),
) -> None:
    from lemma.services.connector_package import build_package

    project = Path(path)
    if not project.is_dir():
        _fail(f"{project} is not a connector project directory.")

    try:
        tarball, manifest = build_package(
            project,
            output_dir=Path(output) if output else None,
            key_dir=Path(key_dir) if key_dir else None,
            force=force,
        )
    except FileExistsError as exc:
        _fail(str(exc))
    except (FileNotFoundError, ValueError) as exc:
        _fail(str(exc))

    console.print(
        f"[green]Packaged[/green] [cyan]{manifest.name}[/cyan] v{manifest.version} "
        f"→ {tarball} ({len(manifest.files)} files, signed by {manifest.producer})."
    )


@connector_app.command(
    name="verify-package",
    help="Verify a connector package's signature and per-file integrity.",
)
def verify_package_command(
    path: str = typer.Argument(help="Path to a connector package (.tar.gz)."),
) -> None:
    from lemma.services.connector_package import verify_package

    result = verify_package(Path(path))
    if not result.ok:
        where = f" ({result.failed_path})" if result.failed_path else ""
        _fail(f"{result.detail}{where}")
    console.print(f"[green]OK[/green] {result.detail}")
