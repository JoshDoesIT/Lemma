"""Implementation of the ``lemma evidence`` CLI sub-commands.

Sub-commands:
    lemma evidence verify <entry_hash>   — integrity check for a single entry
    lemma evidence log                   — timeline with integrity state per row
    lemma evidence ingest <FILE>         — load OCSF JSON/JSONL into the log
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.ocsf import OcsfBaseEvent
from lemma.models.signed_evidence import EvidenceIntegrityState
from lemma.sdk.connector import Connector
from lemma.services import crypto
from lemma.services.evidence_log import EvidenceLog
from lemma.services.ocsf_normalizer import normalize

console = Console()

evidence_app = typer.Typer(
    name="evidence",
    help="Inspect and verify the evidence log.",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def _state_style(state: EvidenceIntegrityState) -> str:
    if state == EvidenceIntegrityState.PROVEN:
        return "[green]PROVEN[/green]"
    if state == EvidenceIntegrityState.DEGRADED:
        return "[yellow]DEGRADED[/yellow]"
    return "[red]VIOLATED[/red]"


def _producer_of(metadata: dict) -> str:
    product = metadata.get("product") if isinstance(metadata, dict) else None
    if isinstance(product, dict):
        name = product.get("name")
        if isinstance(name, str) and name:
            return name
    return "unknown"


@evidence_app.command(
    name="verify",
    help="Verify the integrity of a specific evidence entry by entry_hash.",
)
def verify_command(
    entry_hash: str = typer.Argument(
        help="Entry hash of the evidence to verify (hex)",
    ),
) -> None:
    project_dir = _require_lemma_project()
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")

    result = log.verify_entry(entry_hash)
    console.print(f"{_state_style(result.state)}  {entry_hash[:16]}…")
    console.print(f"  {result.detail}")

    if result.state != EvidenceIntegrityState.PROVEN:
        raise typer.Exit(code=1)


@evidence_app.command(
    name="log",
    help="Show the evidence timeline with integrity state per entry.",
)
def log_command() -> None:
    project_dir = _require_lemma_project()
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    envelopes = log.read_envelopes()

    if not envelopes:
        console.print("[dim]No evidence entries. 0 entries.[/dim]")
        return

    table = Table(title=f"Evidence Log ({len(envelopes)} entries)")
    table.add_column("Time", style="dim", width=19)
    table.add_column("Class", min_width=14)
    table.add_column("Producer", style="cyan")
    table.add_column("Entry", style="dim", no_wrap=True)
    table.add_column("State")

    for env in envelopes:
        result = log.verify_entry(env.entry_hash)
        table.add_row(
            env.event.time.strftime("%Y-%m-%d %H:%M:%S"),
            env.event.class_name,
            _producer_of(env.event.metadata),
            env.entry_hash[:12] + "…",
            _state_style(result.state),
        )

    console.print(table)


def _key_status_style(status_value: str) -> str:
    if status_value == "ACTIVE":
        return "[green]ACTIVE[/green]"
    if status_value == "RETIRED":
        return "[yellow]RETIRED[/yellow]"
    return "[red]REVOKED[/red]"


@evidence_app.command(
    name="rotate-key",
    help="Retire the producer's active signing key and generate a new one.",
)
def rotate_key_command(
    producer: str = typer.Option(..., "--producer", help="Producer name (e.g. Lemma, Okta, AWS)"),
) -> None:
    project_dir = _require_lemma_project()
    key_dir = project_dir / ".lemma" / "keys"
    try:
        new_key_id = crypto.rotate_key(producer=producer, key_dir=key_dir)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    console.print(
        f"Rotated signing key for [cyan]{producer}[/cyan]. "
        f"Prior key marked RETIRED; new active key [green]{new_key_id}[/green]."
    )


@evidence_app.command(
    name="revoke-key",
    help="Revoke a specific signing key with a required reason.",
)
def revoke_key_command(
    producer: str = typer.Option(
        ..., "--producer", help="Producer name whose key is being revoked"
    ),
    key_id: str = typer.Option(
        ..., "--key-id", help="Exact key_id (e.g. ed25519:abcd1234) to revoke"
    ),
    reason: str = typer.Option(..., "--reason", help="Why this key is being revoked (required)"),
) -> None:
    project_dir = _require_lemma_project()
    key_dir = project_dir / ".lemma" / "keys"

    try:
        record = crypto.revoke_key(producer=producer, key_id=key_id, reason=reason, key_dir=key_dir)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    console.print(
        f"Key [cyan]{record.key_id}[/cyan] for producer [cyan]{producer}[/cyan] "
        f"is now [red]REVOKED[/red] (reason: {record.revoked_reason})."
    )


def _first_party_connector(name: str, *, repo: str | None) -> Connector:
    """Instantiate a first-party connector by short name.

    Raises ``ValueError`` with the list of known names when the given
    name is unrecognized.
    """
    if name == "github":
        from lemma.sdk.connectors.github import GitHubConnector

        if not repo:
            msg = "The github connector requires --repo owner/name."
            raise ValueError(msg)
        return GitHubConnector(repo=repo)

    known = ["github"]
    msg = f"Unknown connector '{name}'. Known first-party connectors: {', '.join(known)}."
    raise ValueError(msg)


@evidence_app.command(
    name="collect",
    help="Run a first-party connector and append its output to the evidence log.",
)
def collect_command(
    connector_name: str = typer.Argument(
        help="First-party connector name (e.g. 'github')",
    ),
    repo: str = typer.Option("", "--repo", help="Repository in owner/name form (github connector)"),
) -> None:
    project_dir = _require_lemma_project()
    try:
        connector = _first_party_connector(connector_name, repo=repo or None)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    evidence_log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    try:
        result = connector.run(evidence_log)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]{connector.manifest.name}[/green]: "
        f"{result.ingested} ingested, {result.skipped_duplicates} skipped (duplicate)."
    )


@evidence_app.command(
    name="keys",
    help="List every signing key with its lifecycle state.",
)
def keys_command() -> None:
    project_dir = _require_lemma_project()
    key_dir = project_dir / ".lemma" / "keys"

    if not key_dir.exists():
        console.print("[dim]No keys on file. 0 producers.[/dim]")
        return

    producers: list[str] = sorted([p.name for p in key_dir.iterdir() if p.is_dir()])
    if not producers:
        console.print("[dim]No keys on file. 0 producers.[/dim]")
        return

    # Plain-text output — Rich tables truncate in narrow terminals.
    console.print("[bold]Evidence Signing Keys[/bold]")
    for producer in producers:
        lifecycle = crypto.read_lifecycle(producer, key_dir=key_dir)
        for record in lifecycle.keys:
            lifecycle_ts = record.revoked_at or record.retired_at
            timestamp_suffix = (
                f"  (→ {lifecycle_ts.strftime('%Y-%m-%d %H:%M:%S')})" if lifecycle_ts else ""
            )
            reason_suffix = f"  reason: {record.revoked_reason}" if record.revoked_reason else ""
            console.print(
                f"  [cyan]{producer}[/cyan]  "
                f"{_key_status_style(record.status.value)}  "
                f"{record.key_id}  "
                f"activated {record.activated_at.strftime('%Y-%m-%d %H:%M:%S')}"
                f"{timestamp_suffix}{reason_suffix}"
            )


def _parse_records(source_label: str, text: str, *, is_jsonl: bool) -> list[OcsfBaseEvent]:
    """Parse and validate OCSF records. Raises ValueError on any failure.

    Runs in a single pass: on the first bad record the whole batch is
    rejected, so the caller can write all-or-nothing. For JSONL the
    error message carries the line number; for single JSON it doesn't.
    """
    events: list[OcsfBaseEvent] = []
    if is_jsonl:
        for lineno, raw in enumerate(text.splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                payload = json.loads(raw)
                events.append(normalize(payload))
            except (json.JSONDecodeError, ValueError) as exc:
                msg = f"{source_label}:{lineno}: {exc}"
                raise ValueError(msg) from exc
    else:
        try:
            payload = json.loads(text)
            events.append(normalize(payload))
        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"{source_label}: {exc}"
            raise ValueError(msg) from exc
    return events


@evidence_app.command(
    name="ingest",
    help="Read OCSF events from a file (or stdin) and append them to the evidence log.",
)
def ingest_command(
    file: str = typer.Argument(
        help=(
            "Path to a .json (single payload) or .jsonl (newline-delimited) file. "
            "Use '-' for stdin (JSONL)."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate every record without writing to the evidence log.",
    ),
) -> None:
    project_dir = _require_lemma_project()

    if file == "-":
        source_label = "<stdin>"
        text = sys.stdin.read()
        is_jsonl = True
    else:
        path = Path(file)
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            is_jsonl = True
        elif suffix == ".json":
            is_jsonl = False
        else:
            console.print(
                f"[red]Error:[/red] {path.name}: unsupported extension '{suffix or '(none)'}'. "
                "Accepted: .json (single payload) or .jsonl (newline-delimited)."
            )
            raise typer.Exit(code=1)
        if not path.exists():
            console.print(f"[red]Error:[/red] {path}: file not found.")
            raise typer.Exit(code=1)
        source_label = path.name
        text = path.read_text()

    try:
        events = _parse_records(source_label, text, is_jsonl=is_jsonl)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if dry_run:
        console.print(f"{len(events)} valid (dry run — nothing written).")
        return

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    ingested = 0
    skipped = 0
    for event in events:
        if log.append(event):
            ingested += 1
        else:
            skipped += 1
    console.print(f"{ingested} ingested, {skipped} skipped (duplicate).")
