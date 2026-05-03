"""Tests for the Lemma Control Plane receiver (Refs #25).

The Control Plane is the receiving side of `lemma-agent forward`: it
accepts signed evidence envelopes via HTTP, verifies them against the
producer's public key, persists them to a per-producer day file, and
reports the verification verdict in the response.

These tests spin up the handler in-process via `http.server.HTTPServer`
on a free port, then exercise it with stdlib `urllib.request`.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.server import HTTPServer
from pathlib import Path

from lemma.services.control_plane import make_handler_class
from lemma.services.evidence_log import EvidenceLog
from lemma.services.ocsf_normalizer import normalize


def _compliance_event(uid: str = "evt-1") -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Lemma"},
            "uid": uid,
        },
    }


def _produce_signed_envelope(project_dir: Path, uid: str = "evt-1") -> dict:
    """Sign one envelope locally and return its dict shape — what an
    agent would POST to the Control Plane."""
    log = EvidenceLog(log_dir=project_dir / ".lemma" / "evidence")
    appended = log.append(normalize(_compliance_event(uid)))
    assert appended, "EvidenceLog.append returned False (deduped?)"
    envelopes = log.read_envelopes()
    return json.loads(envelopes[-1].model_dump_json())


def _start_server(handler_cls) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def _post_json(url: str, body: dict, timeout: float = 5.0) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_post_evidence_persists_to_per_producer_day_file(tmp_path: Path) -> None:
    """Agent posts a signed envelope; receiver writes it to
    <evidence-dir>/<producer>/<date>.jsonl."""
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"  # producer key already on disk

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, body = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
    finally:
        server.shutdown()
        server.server_close()

    assert status == 200, f"status={status} body={body}"
    assert body["verdict"] == "PROVEN"
    assert body["entry_hash"] == envelope["entry_hash"]

    producer_dir = cp_evidence / "Lemma"
    written_files = list(producer_dir.glob("*.jsonl"))
    assert len(written_files) == 1, f"expected 1 day file, got {written_files}"
    written = json.loads(written_files[0].read_text().strip())
    assert written["entry_hash"] == envelope["entry_hash"]


def test_post_evidence_rejects_malformed_json(tmp_path: Path) -> None:
    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/evidence",
            data=b"not json",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected HTTPError")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, f"expected 400, got {exc.code}"
    finally:
        server.shutdown()
        server.server_close()


def test_post_evidence_rejects_envelope_without_known_producer_key(tmp_path: Path) -> None:
    """An envelope signed by a producer whose public key is not in
    `--keys-dir` must be rejected (we can't verify the signature)."""
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)

    cp_evidence = tmp_path / "cp-evidence"
    # Empty keys-dir — Control Plane has no public key for "Lemma".
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, body = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
    finally:
        server.shutdown()
        server.server_close()

    assert status == 422, f"status={status} body={body}"
    assert body["verdict"] in {"VIOLATED", "DEGRADED"}


def test_post_evidence_detects_tampered_signature(tmp_path: Path) -> None:
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)
    # Flip a hex char in the signature.
    sig = envelope["signature"]
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    envelope["signature"] = flipped

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, body = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
    finally:
        server.shutdown()
        server.server_close()

    assert status == 422
    assert body["verdict"] in {"VIOLATED", "DEGRADED"}


def test_post_evidence_unknown_path_returns_404(tmp_path: Path) -> None:
    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/wrong", timeout=5)
            raise AssertionError("expected HTTPError")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_health_endpoint_returns_basic_status(tmp_path: Path) -> None:
    """Control Plane mirrors the agent's /health convention so operators
    have a uniform observability probe."""
    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
    finally:
        server.shutdown()
        server.server_close()

    for key in ("evidence_count", "producer_count", "started_at", "uptime_seconds"):
        assert key in body, f"missing key {key} in /health"


def test_two_envelopes_from_same_producer_form_a_chain(tmp_path: Path) -> None:
    """Receiver appends in arrival order; the per-producer evidence log
    must be chain-consistent across two envelopes."""
    project = tmp_path / "agent-side"
    project.mkdir()
    e1 = _produce_signed_envelope(project, "evt-cp-1")
    e2 = _produce_signed_envelope(project, "evt-cp-2")
    assert e2["prev_hash"] == e1["entry_hash"]

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        s1, _ = _post_json(f"http://127.0.0.1:{port}/v1/evidence", e1)
        s2, b2 = _post_json(f"http://127.0.0.1:{port}/v1/evidence", e2)
    finally:
        server.shutdown()
        server.server_close()

    assert s1 == 200
    assert s2 == 200, f"second envelope failed: {b2}"
    written = list((cp_evidence / "Lemma").glob("*.jsonl"))
    # All envelopes for the same UTC date land in one file; both
    # envelopes were signed in the same test run so this is stable.
    text = "".join(f.read_text() for f in written)
    assert e1["entry_hash"] in text
    assert e2["entry_hash"] in text


def test_two_producers_get_separate_directories(tmp_path: Path) -> None:
    """Cross-producer isolation: a Lemma envelope and an Okta envelope
    write to different per-producer directories."""
    from lemma.services import crypto as lemma_crypto

    # Bootstrap two producers in the same keys-dir.
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    lemma_crypto.generate_keypair(producer="Lemma", key_dir=keys_dir)
    lemma_crypto.generate_keypair(producer="Okta", key_dir=keys_dir)

    # Each producer gets its own log dir + chain on the agent side so
    # the receiver can verify them independently — chain isolation per
    # producer is the correct receiver-side semantic.
    lemma_log = EvidenceLog(log_dir=tmp_path / "agent-lemma", key_dir=keys_dir)
    lemma_log.append(normalize(_compliance_event("lemma-evt")))
    e_lemma = lemma_log.read_envelopes()[-1]

    okta_event = _compliance_event("okta-evt")
    okta_event["metadata"]["product"]["name"] = "Okta"
    okta_log = EvidenceLog(log_dir=tmp_path / "agent-okta", key_dir=keys_dir)
    okta_log.append(normalize(okta_event))
    e_okta = okta_log.read_envelopes()[-1]

    cp_evidence = tmp_path / "cp-evidence"
    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=keys_dir)
    server, port = _start_server(handler)
    try:
        s1, _ = _post_json(
            f"http://127.0.0.1:{port}/v1/evidence",
            json.loads(e_lemma.model_dump_json()),
        )
        s2, _ = _post_json(
            f"http://127.0.0.1:{port}/v1/evidence",
            json.loads(e_okta.model_dump_json()),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert s1 == 200 and s2 == 200
    assert (cp_evidence / "Lemma").is_dir()
    assert (cp_evidence / "Okta").is_dir()
    assert list((cp_evidence / "Lemma").glob("*.jsonl"))
    assert list((cp_evidence / "Okta").glob("*.jsonl"))


# Aggregation tests -----------------------------------------------------


def _seed_per_producer_envelopes(
    evidence_dir: Path, agent_evidence_dir: Path, producer: str, count: int
) -> None:
    """Sign `count` envelopes locally as `producer` and copy them into
    the Control Plane's per-producer day file. Mirrors what the live
    receiver writes to disk after a series of POSTs."""
    log = EvidenceLog(log_dir=agent_evidence_dir, key_dir=evidence_dir.parent / "keys")
    for i in range(count):
        ev = _compliance_event(f"{producer}-evt-{i}")
        ev["metadata"]["product"]["name"] = producer
        log.append(normalize(ev))

    target_dir = evidence_dir / producer
    target_dir.mkdir(parents=True, exist_ok=True)
    for jsonl in agent_evidence_dir.glob("*.jsonl"):
        target = target_dir / jsonl.name
        # Append (so multi-producer call into the same agent log still works).
        with target.open("a", encoding="utf-8") as out, jsonl.open() as src:
            for line in src:
                env = json.loads(line)
                if (
                    env.get("event", {}).get("metadata", {}).get("product", {}).get("name")
                    == producer
                ):
                    out.write(line)


def test_aggregate_summarises_evidence_across_producers(tmp_path: Path) -> None:
    """The unified compliance view: aggregating over an evidence-dir
    that contains envelopes from ≥ 2 agents/producers must produce a
    per-producer rollup plus totals."""
    from lemma.services.control_plane import aggregate

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()

    _seed_per_producer_envelopes(cp_evidence, tmp_path / "agent-lemma", "Lemma", 3)
    _seed_per_producer_envelopes(cp_evidence, tmp_path / "agent-okta", "Okta", 2)

    result = aggregate(cp_evidence)

    # Top-level shape.
    assert result.total_envelopes == 5
    assert result.producer_count == 2
    assert result.first_signed_at <= result.last_signed_at

    # Per-producer breakdown.
    by_name = {p.producer: p for p in result.producers}
    assert set(by_name) == {"Lemma", "Okta"}
    assert by_name["Lemma"].envelope_count == 3
    assert by_name["Okta"].envelope_count == 2
    assert by_name["Lemma"].latest_entry_hash != ""
    assert by_name["Okta"].latest_entry_hash != ""


def test_aggregate_empty_evidence_dir_returns_zero_summary(tmp_path: Path) -> None:
    from lemma.services.control_plane import aggregate

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    result = aggregate(cp_evidence)
    assert result.total_envelopes == 0
    assert result.producer_count == 0
    assert result.producers == []


def test_aggregate_skips_blank_lines_and_garbage(tmp_path: Path) -> None:
    """Lines that don't parse as envelopes don't crash the summary —
    they're counted as parse failures so operators can see something is
    wrong without losing the rollup."""
    from lemma.services.control_plane import aggregate

    cp_evidence = tmp_path / "cp-evidence"
    (cp_evidence / "Lemma").mkdir(parents=True)
    (cp_evidence / "Lemma" / "2026-05-03.jsonl").write_text(
        "\n\n   \n" + '{"not":"a valid envelope"}\n'
    )

    result = aggregate(cp_evidence)
    assert result.total_envelopes == 0
    # The malformed line should surface as a parse_error count so the
    # operator gets a signal without losing the per-producer entry.
    assert result.parse_errors == 1


def test_aggregate_missing_evidence_dir_returns_zero_summary(tmp_path: Path) -> None:
    from lemma.services.control_plane import aggregate

    result = aggregate(tmp_path / "does-not-exist")
    assert result.total_envelopes == 0
    assert result.producer_count == 0


def test_aggregate_per_producer_day_file_count(tmp_path: Path) -> None:
    """A single producer with envelopes spanning two days produces two
    day-files; aggregate reports both."""
    from lemma.services.control_plane import aggregate

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    target_dir = cp_evidence / "Lemma"
    target_dir.mkdir()

    # Sign two envelopes via the production EvidenceLog, then split
    # them into per-day files — mimicking the receiver's behaviour
    # across two days of operation.
    log = EvidenceLog(log_dir=tmp_path / "agent", key_dir=tmp_path / "keys")
    ev1 = _compliance_event("day1")
    ev1["time"] = "2026-05-01T12:00:00+00:00"
    ev2 = _compliance_event("day2")
    ev2["time"] = "2026-05-02T12:00:00+00:00"
    log.append(normalize(ev1))
    log.append(normalize(ev2))
    envs = log.read_envelopes()
    (target_dir / "2026-05-01.jsonl").write_text(envs[0].model_dump_json() + "\n")
    (target_dir / "2026-05-02.jsonl").write_text(envs[1].model_dump_json() + "\n")

    result = aggregate(cp_evidence)
    by_name = {p.producer: p for p in result.producers}
    assert by_name["Lemma"].day_file_count == 2
    assert by_name["Lemma"].envelope_count == 2
    assert by_name["Lemma"].first_signed_at < by_name["Lemma"].last_signed_at


# Metrics endpoint tests ------------------------------------------------


def test_metrics_endpoint_returns_prometheus_text_format(tmp_path: Path) -> None:
    """`GET /metrics` returns Prometheus exposition format with the
    standard `# HELP` / `# TYPE` headers and at least the
    receiver-state counters."""
    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
            assert resp.status == 200
            ct = resp.headers.get("Content-Type", "")
            # Prometheus exposition uses text/plain; charset=utf-8.
            assert ct.startswith("text/plain")
            body = resp.read().decode()
    finally:
        server.shutdown()
        server.server_close()

    # Required metric names + the HELP / TYPE preamble for at least one.
    for marker in (
        "# HELP control_plane_uptime_seconds",
        "# TYPE control_plane_uptime_seconds gauge",
        "control_plane_uptime_seconds ",
        "# HELP control_plane_evidence_total",
        "# TYPE control_plane_evidence_total counter",
        "control_plane_evidence_total ",
        "# HELP control_plane_producers",
        "control_plane_producers ",
    ):
        assert marker in body, f"missing {marker!r} in /metrics body:\n{body}"


def test_metrics_increments_envelope_counter_with_producer_and_verdict_labels(
    tmp_path: Path,
) -> None:
    """Posting envelopes ticks the per-producer-per-verdict counter so
    a Prometheus scraper can break down receive volume by source and
    outcome."""
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        # Pre-condition: counter series is absent (or zero).
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
            before = resp.read().decode()
        series = 'control_plane_envelopes_received_total{producer="Lemma",verdict="PROVEN"}'
        assert series not in before or f"{series} 0" in before

        # POST one envelope; verdict will be PROVEN.
        status, _ = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
        assert status == 200

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
            after = resp.read().decode()
    finally:
        server.shutdown()
        server.server_close()

    assert 'control_plane_envelopes_received_total{producer="Lemma",verdict="PROVEN"} 1' in after, (
        f"expected counter to tick to 1\nafter:\n{after}"
    )


def test_metrics_counts_violated_envelopes_under_separate_label(tmp_path: Path) -> None:
    """A tampered-signature envelope ticks the verdict='VIOLATED'
    series, not 'PROVEN'."""
    project = tmp_path / "agent-side"
    project.mkdir()
    envelope = _produce_signed_envelope(project)
    # Flip a hex char in the signature.
    sig = envelope["signature"]
    envelope["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]

    cp_evidence = tmp_path / "cp-evidence"
    cp_keys = project / ".lemma" / "keys"

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        status, _ = _post_json(f"http://127.0.0.1:{port}/v1/evidence", envelope)
        assert status == 422
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
            body = resp.read().decode()
    finally:
        server.shutdown()
        server.server_close()

    assert (
        'control_plane_envelopes_received_total{producer="Lemma",verdict="VIOLATED"} 1' in body
        or 'control_plane_envelopes_received_total{producer="Lemma",verdict="DEGRADED"} 1' in body
    ), f"VIOLATED/DEGRADED counter did not tick:\n{body}"


def test_metrics_evidence_total_reflects_disk_state(tmp_path: Path) -> None:
    """`control_plane_evidence_total` is derived from disk (so it
    survives restarts) — distinct from the live in-memory counters."""
    cp_evidence = tmp_path / "cp-evidence"
    (cp_evidence / "Lemma").mkdir(parents=True)
    (cp_evidence / "Lemma" / "2026-05-03.jsonl").write_text('{"a":1}\n{"b":2}\n{"c":3}\n')

    cp_keys = tmp_path / "cp-keys"
    cp_keys.mkdir()

    handler = make_handler_class(evidence_dir=cp_evidence, keys_dir=cp_keys)
    server, port = _start_server(handler)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
            body = resp.read().decode()
    finally:
        server.shutdown()
        server.server_close()

    assert "control_plane_evidence_total 3" in body, (
        f"expected disk-derived count of 3; got:\n{body}"
    )


# Topology graph tests --------------------------------------------------


def test_topology_empty_evidence_dir_has_just_root_node(tmp_path: Path) -> None:
    from lemma.services.control_plane import build_topology

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    topo = build_topology(cp_evidence)

    assert topo.producers == []
    assert topo.envelope_count == 0


def test_topology_walks_per_producer_chains(tmp_path: Path) -> None:
    """The topology graph captures the per-producer envelope chain so a
    Graphviz render shows producer → e1 → e2 → e3 lineage."""
    from lemma.services.control_plane import build_topology

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    keys_dir = cp_evidence.parent / "keys"

    # Sign three envelopes locally and copy them under the producer dir.
    log = EvidenceLog(log_dir=tmp_path / "agent-evidence", key_dir=keys_dir)
    for i in range(3):
        log.append(normalize(_compliance_event(f"chain-{i}")))
    envs = log.read_envelopes()
    target = cp_evidence / "Lemma"
    target.mkdir()
    day = envs[0].signed_at.strftime("%Y-%m-%d")
    (target / f"{day}.jsonl").write_text("\n".join(env.model_dump_json() for env in envs) + "\n")

    topo = build_topology(cp_evidence)
    assert len(topo.producers) == 1
    p = topo.producers[0]
    assert p.producer == "Lemma"
    assert len(p.chain) == 3
    # chain entries carry both prev_hash and entry_hash so the renderer
    # can draw the genesis link.
    assert p.chain[0].prev_hash == "0" * 64
    assert p.chain[0].entry_hash == envs[0].entry_hash
    assert p.chain[1].prev_hash == envs[0].entry_hash
    assert p.chain[1].entry_hash == envs[1].entry_hash
    assert p.chain[2].prev_hash == envs[1].entry_hash
    assert p.chain[2].entry_hash == envs[2].entry_hash
    assert topo.envelope_count == 3


def test_topology_two_producers_separate_chains(tmp_path: Path) -> None:
    from lemma.services import crypto as lemma_crypto
    from lemma.services.control_plane import build_topology

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    for producer in ("Lemma", "Okta"):
        lemma_crypto.generate_keypair(producer=producer, key_dir=keys_dir)

    cp_evidence = tmp_path / "cp-evidence"
    for producer in ("Lemma", "Okta"):
        log = EvidenceLog(log_dir=tmp_path / f"agent-{producer}", key_dir=keys_dir)
        evt = _compliance_event(f"{producer}-1")
        evt["metadata"]["product"]["name"] = producer
        log.append(normalize(evt))
        envs = log.read_envelopes()
        target = cp_evidence / producer
        target.mkdir(parents=True)
        day = envs[0].signed_at.strftime("%Y-%m-%d")
        (target / f"{day}.jsonl").write_text(envs[0].model_dump_json() + "\n")

    topo = build_topology(cp_evidence)
    by_name = {p.producer: p for p in topo.producers}
    assert set(by_name) == {"Lemma", "Okta"}
    assert len(by_name["Lemma"].chain) == 1
    assert len(by_name["Okta"].chain) == 1
    assert topo.envelope_count == 2


def test_render_topology_dot_outputs_valid_graphviz(tmp_path: Path) -> None:
    """The DOT renderer emits a well-formed digraph with one node per
    producer and one node per envelope, plus edges along the chain."""
    from lemma.services.control_plane import build_topology, render_topology_dot

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    keys_dir = cp_evidence.parent / "keys"
    log = EvidenceLog(log_dir=tmp_path / "agent-evidence", key_dir=keys_dir)
    log.append(normalize(_compliance_event("dot-1")))
    log.append(normalize(_compliance_event("dot-2")))
    envs = log.read_envelopes()
    target = cp_evidence / "Lemma"
    target.mkdir()
    day = envs[0].signed_at.strftime("%Y-%m-%d")
    (target / f"{day}.jsonl").write_text("\n".join(env.model_dump_json() for env in envs) + "\n")

    topo = build_topology(cp_evidence)
    dot = render_topology_dot(topo)

    # Must be a valid digraph header + matching close.
    assert dot.startswith("digraph LemmaControlPlane {")
    assert dot.rstrip().endswith("}")
    # Producer node + label.
    assert '"producer:Lemma"' in dot
    assert 'label="Lemma' in dot
    # Edges from producer to first envelope, then envelope-to-envelope.
    assert '"producer:Lemma" -> "envelope:' in dot
    assert dot.count('"envelope:') >= 2  # one node + one edge mention each
    # Both entry hashes are referenced.
    for env in envs:
        # The DOT escapes hashes with shorter prefixes, so just check
        # the first 12 chars surface somewhere.
        assert env.entry_hash[:12] in dot


def test_render_topology_dot_empty_topology_renders_root_only(tmp_path: Path) -> None:
    from lemma.services.control_plane import build_topology, render_topology_dot

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    topo = build_topology(cp_evidence)
    dot = render_topology_dot(topo)
    assert dot.startswith("digraph LemmaControlPlane {")
    assert dot.rstrip().endswith("}")
    assert "envelope:" not in dot
    assert "producer:" not in dot
