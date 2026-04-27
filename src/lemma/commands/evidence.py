"""Implementation of the ``lemma evidence`` CLI sub-commands.

Sub-commands:
    lemma evidence verify <entry_hash>   — integrity check for a single entry
    lemma evidence log                   — timeline with integrity state per row
    lemma evidence ingest <FILE>         — load OCSF JSON/JSONL into the log
    lemma evidence infer                 — AI-propose EVIDENCES edges for orphans
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from lemma.models.ocsf import OcsfBaseEvent
from lemma.models.signed_evidence import (
    EvidenceIntegrityState,
    ProvenanceRecord,
    RevocationList,
)
from lemma.sdk.connector import Connector
from lemma.services import crypto
from lemma.services.config import load_automation_config
from lemma.services.evidence_infer import infer_mappings
from lemma.services.evidence_log import EvidenceLog
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.llm import get_llm_client
from lemma.services.ocsf_normalizer import normalize_with_provenance, severity_name

_DEFAULT_EVIDENCE_REUSE_THRESHOLD = 0.7

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


def _load_and_verify_crl(crl_path: Path, key_dir: Path) -> RevocationList:
    """Load a CRL JSON file and verify its signature, or exit 1 with a clear error.

    Helpers in `crypto.verify_crl` are the actual cryptographic check;
    this wrapper handles file I/O and the CLI exit-code semantics. A
    CRL that fails any check (parse, public key lookup, signature
    verify) aborts with exit 1 — silently ignoring an unverifiable
    CRL would let an attacker suppress the local revocation check by
    supplying a bad one.
    """
    try:
        crl = RevocationList.model_validate_json(crl_path.read_text())
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] Could not read CRL at {crl_path}: {exc}")
        raise typer.Exit(code=1) from exc

    pem_path = key_dir / crypto._safe_producer(crl.producer) / f"{crl.issuer_key_id}.public.pem"
    if not pem_path.exists():
        console.print(
            f"[red]Error:[/red] Cannot verify CRL: no public key on file for "
            f"producer '{crl.producer}' (key_id {crl.issuer_key_id})."
        )
        raise typer.Exit(code=1)

    if not crypto.verify_crl(crl, pem_path.read_bytes()):
        console.print("[red]Error:[/red] CRL signature invalid — refusing to merge.")
        raise typer.Exit(code=1)

    return crl


@evidence_app.command(
    name="verify",
    help=(
        "Verify the integrity of a specific evidence entry by entry_hash. "
        "Pass --crl to merge an offline RevocationList; without --crl, "
        "the verifier prints a note that revocations issued elsewhere "
        "are not visible."
    ),
)
def verify_command(
    entry_hash: str = typer.Argument(
        help="Entry hash of the evidence to verify (hex)",
    ),
    crl_path: str = typer.Option(
        "",
        "--crl",
        help=(
            "Path to a signed RevocationList JSON. The CRL's signature is "
            "checked against the producer's currently-known public key; "
            "an unverifiable CRL aborts with exit 1."
        ),
    ),
) -> None:
    project_dir = _require_lemma_project()
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")

    crl = None
    if crl_path:
        crl = _load_and_verify_crl(Path(crl_path), project_dir / ".lemma" / "keys")

    result = log.verify_entry(entry_hash, crl=crl)
    console.print(f"{_state_style(result.state)}  {entry_hash[:16]}…")
    console.print(f"  {result.detail}")

    # Provenance chain — skipped when VIOLATED (the records can't be trusted).
    if result.state != EvidenceIntegrityState.VIOLATED:
        envelope = next((env for env in log.read_envelopes() if env.entry_hash == entry_hash), None)
        if envelope is not None and envelope.provenance:
            console.print("  [bold]Provenance chain:[/bold]")
            for record in envelope.provenance:
                ts = record.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
                console.print(
                    f"    [cyan]{record.stage}[/cyan] ({ts}) "
                    f"actor: {record.actor}  "
                    f"hash: [dim]{record.content_hash[:12]}…[/dim]"
                )

    if not crl_path:
        # Operators running verify without --crl have an incomplete picture
        # — they only see local revocations, not ones issued elsewhere.
        # Surface this once per invocation; exit code is unchanged.
        console.print(
            "[dim]Note: No CRL supplied; revocations issued elsewhere are not visible.[/dim]"
        )

    if result.state != EvidenceIntegrityState.PROVEN:
        raise typer.Exit(code=1)


@evidence_app.command(
    name="export-crl",
    help="Emit a signed RevocationList for a producer (default: stdout).",
)
def export_crl_command(
    producer: str = typer.Option(..., "--producer", help="Producer name (e.g. Lemma, Okta)"),
    output: str = typer.Option(
        "",
        "--output",
        help="Write CRL JSON to this path. Default: stdout.",
    ),
) -> None:
    project_dir = _require_lemma_project()
    key_dir = project_dir / ".lemma" / "keys"
    try:
        crl = crypto.export_crl(producer=producer, key_dir=key_dir)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    payload = crl.model_dump_json(indent=2)
    if output:
        Path(output).write_text(payload + "\n")
        console.print(
            f"Wrote CRL for [cyan]{producer}[/cyan] "
            f"({len(crl.revocations)} revocation(s)) to {output}."
        )
    else:
        # Plain stdout — pipe-friendly, no Rich markup.
        typer.echo(payload)


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

    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    table = Table(title=f"Evidence Log ({len(envelopes)} entries)")
    table.add_column("Time", style="dim", width=19)
    table.add_column("Class", min_width=14)
    table.add_column("Producer", style="cyan")
    table.add_column("Entry", style="dim", no_wrap=True)
    table.add_column("Graph", justify="center")
    table.add_column("State", no_wrap=True)

    for env in envelopes:
        result = log.verify_entry(env.entry_hash)
        in_graph = graph.get_node(f"evidence:{env.entry_hash}") is not None
        table.add_row(
            env.event.time.strftime("%Y-%m-%d %H:%M:%S"),
            env.event.class_name,
            _producer_of(env.event.metadata),
            env.entry_hash[:12] + "…",
            "[green]✓[/green]" if in_graph else "[dim]✗[/dim]",
            _state_style(result.state),
        )

    # Use a wider effective width so adding the "Graph" column doesn't
    # squeeze the State column into "PROV" on narrow terminals.
    Console(width=120).print(table)


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


def _first_party_connector(
    name: str,
    *,
    repo: str | None,
    domain: str | None,
    region: str | None,
) -> Connector:
    """Instantiate a first-party connector by short name.

    Raises ``ValueError`` with the list of known names when the given
    name is unrecognized, or with a connector-specific message when a
    required option is missing.
    """
    if name == "github":
        from lemma.sdk.connectors.github import GitHubConnector

        if not repo:
            msg = "The github connector requires --repo owner/name."
            raise ValueError(msg)
        return GitHubConnector(repo=repo)

    if name == "okta":
        from lemma.sdk.connectors.okta import OktaConnector

        if not domain:
            msg = "The okta connector requires --domain <your-org>.okta.com."
            raise ValueError(msg)
        return OktaConnector(domain=domain)

    if name == "aws":
        from lemma.sdk.connectors.aws import AWSConnector

        return AWSConnector(region=region or "us-east-1")

    known = ["github", "okta", "aws"]
    msg = f"Unknown connector '{name}'. Known first-party connectors: {', '.join(known)}."
    raise ValueError(msg)


@evidence_app.command(
    name="collect",
    help="Run a first-party connector and append its output to the evidence log.",
)
def collect_command(
    connector_name: str = typer.Argument(
        help="First-party connector name (e.g. 'github', 'okta', 'aws')",
    ),
    repo: str = typer.Option("", "--repo", help="Repository in owner/name form (github connector)"),
    domain: str = typer.Option(
        "", "--domain", help="Okta domain, e.g. your-org.okta.com (okta connector)"
    ),
    region: str = typer.Option(
        "", "--region", help="AWS region (aws connector; defaults to us-east-1)"
    ),
) -> None:
    project_dir = _require_lemma_project()
    try:
        connector = _first_party_connector(
            connector_name,
            repo=repo or None,
            domain=domain or None,
            region=region or None,
        )
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


def _parse_records(
    source_label: str, text: str, *, is_jsonl: bool
) -> list[tuple[OcsfBaseEvent, ProvenanceRecord]]:
    """Parse and validate OCSF records, pairing each with a normalization record.

    Runs in a single pass: on the first bad record the whole batch is
    rejected, so the caller can write all-or-nothing. For JSONL the
    error message carries the line number; for single JSON it doesn't.
    """
    pairs: list[tuple[OcsfBaseEvent, ProvenanceRecord]] = []
    if is_jsonl:
        for lineno, raw in enumerate(text.splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                payload = json.loads(raw)
                pairs.append(normalize_with_provenance(payload))
            except (json.JSONDecodeError, ValueError) as exc:
                msg = f"{source_label}:{lineno}: {exc}"
                raise ValueError(msg) from exc
    else:
        try:
            payload = json.loads(text)
            pairs.append(normalize_with_provenance(payload))
        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"{source_label}: {exc}"
            raise ValueError(msg) from exc
    return pairs


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
        raw_bytes = text.encode()
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
        raw_bytes = path.read_bytes()
        text = raw_bytes.decode()

    try:
        pairs = _parse_records(source_label, text, is_jsonl=is_jsonl)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if dry_run:
        console.print(f"{len(pairs)} valid (dry run — nothing written).")
        return

    source_record = ProvenanceRecord(
        stage="source",
        actor=f"ingest-cli:{source_label}",
        content_hash=hashlib.sha256(raw_bytes).hexdigest(),
    )

    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    ingested = 0
    skipped = 0
    for event, norm_record in pairs:
        if log.append(event, provenance=[source_record, norm_record]):
            ingested += 1
        else:
            skipped += 1
    console.print(f"{ingested} ingested, {skipped} skipped (duplicate).")


def _extract_control_refs(metadata: dict) -> list[str]:
    """Pull ``control_refs`` off a free-form metadata dict, safely."""
    refs = metadata.get("control_refs") if isinstance(metadata, dict) else None
    if not isinstance(refs, list):
        return []
    return [ref for ref in refs if isinstance(ref, str) and ref]


@evidence_app.command(
    name="load",
    help="Load every envelope in the evidence log into the compliance graph.",
)
def load_command() -> None:
    project_dir = _require_lemma_project()
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    envelopes = log.read_envelopes()

    if not envelopes:
        console.print(
            "[dim]No evidence to load. Run a connector or "
            "[bold]lemma evidence ingest[/bold] first.[/dim]"
        )
        return

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    try:
        for env in envelopes:
            graph.add_evidence(
                entry_hash=env.entry_hash,
                producer=_producer_of(env.event.metadata),
                class_name=env.event.class_name,
                time_iso=env.event.time.isoformat(),
                control_refs=_extract_control_refs(env.event.metadata),
                severity=severity_name(int(env.event.severity_id)),
                class_uid=env.event.class_uid,
            )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    config_file = project_dir / "lemma.config.yaml"
    automation = load_automation_config(config_file) if config_file.exists() else None
    reuse_threshold = (
        automation.threshold_for("evidence-reuse") if automation is not None else None
    ) or _DEFAULT_EVIDENCE_REUSE_THRESHOLD
    implicit_count = graph.rebuild_implicit_evidences(min_similarity=reuse_threshold)

    graph.save(graph_path)

    linked = sum(1 for env in envelopes if _extract_control_refs(env.event.metadata))
    console.print(
        f"[green]Loaded[/green] {len(envelopes)} evidence entr"
        f"{'y' if len(envelopes) == 1 else 'ies'}; "
        f"{linked} linked to at least one control."
    )
    if implicit_count:
        console.print(
            f"[green]Wrote[/green] {implicit_count} implicit reuse edge(s) via "
            f"harmonization (min similarity {reuse_threshold})."
        )


@evidence_app.command(
    name="rebuild-reuse",
    help=(
        "Recompute IMPLICITLY_EVIDENCES edges (Cross-Scope Evidence Reuse) without "
        "re-running discover or load."
    ),
)
def rebuild_reuse_command(
    min_similarity: float = typer.Option(
        None,
        "--min-similarity",
        help=(
            "Harmonization-similarity floor (0.0-1.0). "
            "Defaults to ai.automation.thresholds.evidence-reuse from lemma.config.yaml, "
            "or 0.7 if unset."
        ),
    ),
) -> None:
    project_dir = _require_lemma_project()
    if min_similarity is None:
        config_file = project_dir / "lemma.config.yaml"
        automation = load_automation_config(config_file) if config_file.exists() else None
        min_similarity = (
            automation.threshold_for("evidence-reuse") if automation is not None else None
        ) or _DEFAULT_EVIDENCE_REUSE_THRESHOLD

    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)
    count = graph.rebuild_implicit_evidences(min_similarity=min_similarity)
    graph.save(graph_path)

    console.print(
        f"[green]Rebuilt[/green] {count} implicit reuse edge(s) (min similarity {min_similarity})."
    )


@evidence_app.command(
    name="infer",
    help=(
        "AI-propose EVIDENCES edges for Evidence nodes with no control refs. "
        "Costs ~9 LLM calls per orphaned event by default."
    ),
)
def infer_command(
    top_k: int = typer.Option(3, "--top-k", help="Candidate controls per framework per evidence."),
    accept_all: bool = typer.Option(
        False,
        "--accept-all",
        help="Accept every parseable proposal as an edge, bypassing thresholds.",
    ),
) -> None:
    project_dir = _require_lemma_project()

    config_file = project_dir / "lemma.config.yaml"
    ai_config: dict = {}
    if config_file.exists():
        full_config = yaml.safe_load(config_file.read_text()) or {}
        ai_config = full_config.get("ai", {})

    try:
        llm_client = get_llm_client(ai_config)
    except ImportError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    try:
        automation = load_automation_config(config_file)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    report = infer_mappings(
        project_dir=project_dir,
        llm_client=llm_client,
        top_k=top_k,
        accept_all=accept_all,
        automation=automation,
    )

    if report.orphans_processed == 0:
        console.print(
            "[dim]0 orphaned evidences. "
            "Run [bold]lemma evidence load[/bold] first if you expected some.[/dim]"
        )
        return

    console.print(
        f"[green]{report.edges_written}[/green] newly linked via AI "
        f"({report.edges_written} auto-accepted, "
        f"{report.traces_proposed} proposed for review). "
        f"{report.orphans_processed} orphan(s) processed; "
        f"{report.skipped_missing_envelope} skipped (envelope missing)."
    )
