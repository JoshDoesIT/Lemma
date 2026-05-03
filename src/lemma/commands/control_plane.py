"""Implementation of the ``lemma control-plane`` CLI (Refs #25).

The Control Plane is the receiving end of ``lemma-agent forward``. It
accepts signed evidence envelopes via HTTP, verifies them against the
producer's public key, and persists them to a per-producer day file.

This slice ships ``serve`` only — aggregation, unified-graph build,
and policy push are tracked under #25 as separate slices.
"""

from __future__ import annotations

import json
import signal
import ssl
from dataclasses import asdict
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.control_plane import (
    aggregate,
    build_topology,
    make_handler_class,
    render_topology_dot,
)

console = Console()

control_plane_app = typer.Typer(
    name="control-plane",
    help="Federated Control Plane commands (receiver, aggregation, policy push).",
    no_args_is_help=True,
)


@control_plane_app.command(
    name="serve",
    help=(
        "Run the Control Plane receiver. Accepts POSTed signed envelopes "
        "from `lemma-agent forward` and persists them per producer."
    ),
)
def serve_command(
    port: int = typer.Option(
        ...,
        "--port",
        help="TCP port to bind on 127.0.0.1.",
    ),
    evidence_dir: str = typer.Option(
        ...,
        "--evidence-dir",
        help="Directory under which the receiver writes <producer>/<YYYY-MM-DD>.jsonl files.",
    ),
    keys_dir: str = typer.Option(
        ...,
        "--keys-dir",
        help="Directory of producer public keys (subdirectories named after each producer).",
    ),
    cert: str = typer.Option(
        "",
        "--cert",
        help="PEM server certificate (enables HTTPS). Pair with --key.",
    ),
    key: str = typer.Option(
        "",
        "--key",
        help="PEM server private key (enables HTTPS). Pair with --cert.",
    ),
    client_ca: str = typer.Option(
        "",
        "--client-ca",
        help="PEM CA bundle that signs client certs — when set, the receiver requires mTLS.",
    ),
    bind: str = typer.Option(
        "127.0.0.1",
        "--bind",
        help="Bind address. Default 127.0.0.1; pass 0.0.0.0 to expose on all interfaces.",
    ),
) -> None:
    if (cert and not key) or (key and not cert):
        console.print("[red]Error:[/red] --cert and --key must be set together (both or neither).")
        raise typer.Exit(code=1)
    if client_ca and not cert:
        console.print(
            "[red]Error:[/red] --client-ca requires --cert / --key (mTLS only "
            "makes sense over HTTPS)."
        )
        raise typer.Exit(code=1)

    evidence_path = Path(evidence_dir)
    keys_path = Path(keys_dir)
    evidence_path.mkdir(parents=True, exist_ok=True)
    keys_path.mkdir(parents=True, exist_ok=True)

    handler_cls = make_handler_class(evidence_dir=evidence_path, keys_dir=keys_path)
    server = ThreadingHTTPServer((bind, port), handler_cls)

    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        if client_ca:
            ctx.load_verify_locations(cafile=client_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    actual_port = server.server_address[1]
    console.print(
        f"[green]Lemma Control Plane[/green] listening on "
        f"{scheme}://{bind}:{actual_port}/v1/evidence (POST signed envelopes here)"
    )
    console.print(f"  evidence-dir: {evidence_path}")
    console.print(f"  keys-dir:     {keys_path}")
    if client_ca:
        console.print(f"  mTLS:         CERT_REQUIRED (CA={client_ca})")
    elif cert:
        console.print("  mTLS:         disabled (server cert only)")

    def _shutdown(_signo: int, _frame: object) -> None:
        console.print("[yellow]Lemma Control Plane shutting down.[/yellow]")
        server.shutdown()

    # signal.signal only works on the main thread; tests run the CLI
    # from a worker thread, so swallow the ValueError there.
    try:
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)
    except ValueError:
        pass
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _isoformat(dt: datetime | None) -> str:
    return dt.isoformat() if dt is not None else ""


@control_plane_app.command(
    name="aggregate",
    help=(
        "Summarise persisted evidence across all producers (the unified "
        "compliance view). Pair with `serve` to inspect what's been received."
    ),
)
def aggregate_command(
    evidence_dir: str = typer.Option(
        ...,
        "--evidence-dir",
        help="Directory the receiver writes <producer>/<YYYY-MM-DD>.jsonl files to.",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Write the rollup as JSON to PATH instead of printing a table.",
    ),
) -> None:
    state = aggregate(Path(evidence_dir))

    if output:
        # Convert dataclasses to JSON-friendly dicts; datetimes become
        # ISO 8601 strings so a downstream consumer can parse them
        # without bespoke decoders.
        payload = asdict(state)
        for key in ("first_signed_at", "last_signed_at"):
            payload[key] = _isoformat(payload[key])
        for prod in payload["producers"]:
            for key in ("first_signed_at", "last_signed_at"):
                prod[key] = _isoformat(prod[key])
        Path(output).write_text(json.dumps(payload, indent=2) + "\n")
        console.print(f"[green]Wrote[/green] aggregated rollup to {output}")
        return

    if state.producer_count == 0:
        console.print(f"[yellow]No producer evidence found under[/yellow] {evidence_dir}")
        return

    table = Table(title=f"Lemma Control Plane — {evidence_dir}")
    table.add_column("Producer", style="bold")
    table.add_column("Envelopes", justify="right")
    table.add_column("Day files", justify="right")
    table.add_column("First signed", style="dim")
    table.add_column("Last signed", style="dim")
    for p in state.producers:
        table.add_row(
            p.producer,
            str(p.envelope_count),
            str(p.day_file_count),
            _isoformat(p.first_signed_at),
            _isoformat(p.last_signed_at),
        )
    console.print(table)
    console.print(
        f"[bold]Total:[/bold] {state.total_envelopes} envelopes "
        f"across {state.producer_count} producers"
        + (f" ({state.parse_errors} parse errors)" if state.parse_errors else "")
    )


@control_plane_app.command(
    name="graph",
    help=(
        "Render the federation topology as Graphviz DOT or JSON — every "
        "producer's envelope chain in one view. Pair with `serve` and "
        "`aggregate` for the full Control Plane operator workflow."
    ),
)
def graph_command(
    evidence_dir: str = typer.Option(
        ...,
        "--evidence-dir",
        help="Directory the receiver writes <producer>/<YYYY-MM-DD>.jsonl files to.",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Write the rendered graph to PATH instead of stdout.",
    ),
    fmt: str = typer.Option(
        "dot",
        "--format",
        help="Output format: dot (Graphviz) or json.",
    ),
) -> None:
    if fmt not in {"dot", "json"}:
        console.print(f"[red]Error:[/red] unknown --format {fmt!r}; valid: dot, json.")
        raise typer.Exit(code=1)

    topology = build_topology(Path(evidence_dir))

    if fmt == "dot":
        body = render_topology_dot(topology)
    else:
        payload = {
            "envelope_count": topology.envelope_count,
            "producers": [
                {
                    "producer": p.producer,
                    "chain": [
                        {
                            "entry_hash": e.entry_hash,
                            "prev_hash": e.prev_hash,
                            "signed_at": e.signed_at.isoformat(),
                        }
                        for e in p.chain
                    ],
                }
                for p in topology.producers
            ],
        }
        body = json.dumps(payload, indent=2) + "\n"

    if output:
        Path(output).write_text(body)
        console.print(f"[green]Wrote[/green] {fmt} topology graph to {output}")
    else:
        # `print` (not console.print) to avoid Rich's wrapping/escaping —
        # the DOT output needs to be byte-stable for Graphviz to parse.
        print(body, end="")
