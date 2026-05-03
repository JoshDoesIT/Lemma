"""Lemma Control Plane receiver (Refs #25).

The receiving end of `lemma-agent forward`. Accepts signed evidence
envelopes via HTTP POST, verifies them against the producer's public
key, persists them to a per-producer day file under
``<evidence-dir>/<producer>/<YYYY-MM-DD>.jsonl``, and returns the
verification verdict in the response.

Two endpoints:

- ``POST /v1/evidence`` — body is a single signed envelope JSON
  (matches one line of the agent's forward output). 200 on PROVEN, 422
  on VIOLATED/DEGRADED, 400 on malformed input.
- ``GET /health`` — JSON snapshot of the receiver's observable state
  (mirrors the agent's /health convention so a single observability
  probe works for both sides of the federation).

Stdlib-only — uses ``http.server`` so the Control Plane has no new
runtime dependencies. TLS termination + mTLS (server cert + optional
client-cert verification) is wired through ``ssl.SSLContext`` and
applied to the listening socket; see ``lemma control-plane serve``
for the operator surface.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from lemma.models.signed_evidence import SignedEvidence
from lemma.services.evidence_log import EvidenceLog, _producer_of

_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB cap on a single envelope


def make_handler_class(
    *,
    evidence_dir: Path,
    keys_dir: Path,
    started_at: datetime | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a BaseHTTPRequestHandler subclass closed over the
    receiver's evidence + keys directories.

    Returned class is intended for ``http.server.HTTPServer`` /
    ``ThreadingHTTPServer``.
    """
    evidence_dir = Path(evidence_dir)
    keys_dir = Path(keys_dir)
    server_started = started_at or datetime.now(UTC)
    write_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        # Silence the default access log; operators wanting structured
        # logs should instrument upstream (reverse proxy / sidecar).
        def log_message(self, *args: object, **kwargs: object) -> None:
            return

        def _send_json(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(200, _health_snapshot(evidence_dir, keys_dir, server_started))
                return
            self._send_json(404, {"error": f"unknown path {self.path}"})

        def do_POST(self) -> None:
            if self.path != "/v1/evidence":
                self._send_json(404, {"error": f"unknown path {self.path}"})
                return

            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > _MAX_BODY_BYTES:
                self._send_json(400, {"error": "missing or oversized body"})
                return
            raw = self.rfile.read(length)

            try:
                envelope = SignedEvidence.model_validate_json(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                self._send_json(400, {"error": f"malformed envelope: {exc}"})
                return

            with write_lock:
                verdict, reason = _persist_and_verify(
                    envelope, evidence_dir=evidence_dir, keys_dir=keys_dir
                )

            body: dict = {
                "verdict": verdict,
                "entry_hash": envelope.entry_hash,
            }
            if reason:
                body["reason"] = reason
            status = 200 if verdict == "PROVEN" else 422
            self._send_json(status, body)

    return Handler


def _persist_and_verify(
    envelope: SignedEvidence,
    *,
    evidence_dir: Path,
    keys_dir: Path,
) -> tuple[str, str]:
    """Append `envelope` to the per-producer day file, then run a full
    chain verification on it. Returns (verdict, reason).

    Verdicts mirror Python's ``EvidenceIntegrityState`` strings — PROVEN,
    VIOLATED, DEGRADED. DEGRADED happens when the chain + content hash
    are intact but the signature can't be verified (typically because
    the receiver doesn't have the producer's public key on file).
    """
    producer = _producer_of(envelope.event)
    producer_dir = evidence_dir / producer
    producer_dir.mkdir(parents=True, exist_ok=True)

    day = envelope.signed_at.astimezone(UTC).strftime("%Y-%m-%d")
    day_file = producer_dir / f"{day}.jsonl"
    line = envelope.model_dump_json() + "\n"
    with day_file.open("a", encoding="utf-8") as fh:
        fh.write(line)

    log = EvidenceLog(log_dir=producer_dir, key_dir=keys_dir)
    result = log.verify_entry(envelope.entry_hash)
    return result.state.value, result.detail


@dataclass
class ProducerSummary:
    """Per-producer rollup for the unified aggregation view."""

    producer: str
    envelope_count: int
    day_file_count: int
    first_signed_at: datetime | None
    last_signed_at: datetime | None
    latest_entry_hash: str


@dataclass
class AggregatedState:
    """Output of :func:`aggregate`. The "unified compliance view" the
    AC on #25 calls for: a Control Plane operator's single rollup of
    every producer's signed evidence persisted by the receiver."""

    total_envelopes: int
    producer_count: int
    parse_errors: int
    first_signed_at: datetime | None
    last_signed_at: datetime | None
    producers: list[ProducerSummary] = field(default_factory=list)


def aggregate(evidence_dir: Path) -> AggregatedState:
    """Walk a Control Plane evidence directory and return a unified
    compliance summary across all producers.

    The receiver writes envelopes to ``<evidence-dir>/<producer>/<YYYY-MM-DD>.jsonl``;
    each producer subdirectory represents one agent's evidence stream.
    Aggregation is read-only — the directory is not modified.

    Malformed lines are counted (``parse_errors``) but don't abort the
    rollup; operators see them in the summary so a corrupt day-file
    surfaces without hiding the rest of the unified view.
    """
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.exists():
        return AggregatedState(
            total_envelopes=0,
            producer_count=0,
            parse_errors=0,
            first_signed_at=None,
            last_signed_at=None,
        )

    parse_errors = 0
    overall_first: datetime | None = None
    overall_last: datetime | None = None
    summaries: list[ProducerSummary] = []

    for producer_dir in sorted(p for p in evidence_dir.iterdir() if p.is_dir()):
        envelope_count = 0
        day_files = sorted(producer_dir.glob("*.jsonl"))
        first_at: datetime | None = None
        last_at: datetime | None = None
        latest_hash = ""

        for day_file in day_files:
            with day_file.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        envelope = SignedEvidence.model_validate_json(line)
                    except (json.JSONDecodeError, ValueError):
                        parse_errors += 1
                        continue
                    envelope_count += 1
                    signed_at = envelope.signed_at
                    if first_at is None or signed_at < first_at:
                        first_at = signed_at
                    if last_at is None or signed_at > last_at:
                        last_at = signed_at
                        latest_hash = envelope.entry_hash

        if envelope_count == 0 and not day_files:
            # Empty producer directory — skip silently. A directory
            # with day-files that all parse-error still surfaces as a
            # producer (with zero envelope_count) so operators can see
            # which producer's data is corrupt.
            continue
        summaries.append(
            ProducerSummary(
                producer=producer_dir.name,
                envelope_count=envelope_count,
                day_file_count=len(day_files),
                first_signed_at=first_at,
                last_signed_at=last_at,
                latest_entry_hash=latest_hash,
            )
        )
        if first_at is not None:
            overall_first = first_at if overall_first is None else min(overall_first, first_at)
        if last_at is not None:
            overall_last = last_at if overall_last is None else max(overall_last, last_at)

    return AggregatedState(
        total_envelopes=sum(p.envelope_count for p in summaries),
        producer_count=len(summaries),
        parse_errors=parse_errors,
        first_signed_at=overall_first,
        last_signed_at=overall_last,
        producers=summaries,
    )


def _health_snapshot(evidence_dir: Path, keys_dir: Path, started_at: datetime) -> dict:
    evidence_count = 0
    if evidence_dir.exists():
        for jsonl in evidence_dir.rglob("*.jsonl"):
            with jsonl.open(encoding="utf-8") as fh:
                evidence_count += sum(1 for line in fh if line.strip())

    producer_count = 0
    if keys_dir.exists():
        for child in keys_dir.iterdir():
            if child.is_dir() and (child / "meta.json").exists():
                producer_count += 1

    now = datetime.now(UTC)
    return {
        "evidence_count": evidence_count,
        "producer_count": producer_count,
        "started_at": started_at.isoformat(),
        "uptime_seconds": int((now - started_at).total_seconds()),
    }
