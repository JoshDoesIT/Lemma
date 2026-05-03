"""Implementation of the ``lemma control-plane`` CLI (Refs #25).

The Control Plane is the receiving end of ``lemma-agent forward``. It
accepts signed evidence envelopes via HTTP, verifies them against the
producer's public key, and persists them to a per-producer day file.

This slice ships ``serve`` only — aggregation, unified-graph build,
and policy push are tracked under #25 as separate slices.
"""

from __future__ import annotations

import signal
import ssl
from http.server import ThreadingHTTPServer
from pathlib import Path

import typer
from rich.console import Console

from lemma.services.control_plane import make_handler_class

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
