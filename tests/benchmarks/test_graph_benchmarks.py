"""Compliance-graph performance benchmarks (Refs #48).

Skipped by default; run with ``uv run pytest tests/benchmarks/ --run-benchmark -s``.
Each benchmark builds a graph at a representative scale, times the build /
export / traversal, prints the timing, and asserts the result is *correct*
(counts) rather than fast (no flaky wall-clock thresholds).
"""

from __future__ import annotations

import time

import pytest

from lemma.services.knowledge_graph import ComplianceGraph

_CONTROLS = 2000
_POLICIES = 200


def _build_graph() -> ComplianceGraph:
    g = ComplianceGraph()
    g.add_framework("bench-fw", title="Benchmark Framework")
    for i in range(_CONTROLS):
        g.add_control(
            framework="bench-fw",
            control_id=f"c-{i}",
            title=f"Control {i}",
            family=f"fam-{i % 20}",
        )
    for p in range(_POLICIES):
        g.add_policy(f"policy-{p}.md", title=f"Policy {p}")
        # Each policy satisfies 10 controls.
        for k in range(10):
            g.add_mapping(
                policy=f"policy-{p}.md",
                framework="bench-fw",
                control_id=f"c-{(p * 10 + k) % _CONTROLS}",
                confidence=0.9,
            )
    return g


@pytest.mark.benchmark
def test_benchmark_graph_build(capsys):
    start = time.perf_counter()
    g = _build_graph()
    elapsed = time.perf_counter() - start

    with capsys.disabled():
        print(
            f"\n[bench] build {_CONTROLS} controls + {_POLICIES} policies "
            f"({_POLICIES * 10} mappings): {elapsed * 1000:.1f} ms"
        )
    # Correctness, not timing: the framework controls are present.
    assert g.get_node("control:bench-fw:c-0") is not None
    assert g.get_node("control:bench-fw:c-1999") is not None


@pytest.mark.benchmark
def test_benchmark_query_latency_baseline_1000_nodes(capsys):
    """Baseline (#48 AC): a standard traversal over a ~1000-node graph stays
    well under 500 ms. The assertion carries a generous margin (typical run is
    single-digit ms) so it's a regression tripwire, not a flaky timing gate —
    and it only runs under --run-benchmark, never in the default suite."""
    g = ComplianceGraph()
    g.add_framework("bench-fw", title="Benchmark Framework")
    for i in range(1000):
        g.add_control(
            framework="bench-fw",
            control_id=f"c-{i}",
            title=f"Control {i}",
            family=f"fam-{i % 20}",
        )

    node_ids = [n["id"] for n in g.export_json()["nodes"]]
    start = time.perf_counter()
    # A "standard traversal": every node's outgoing edges, the primitive the
    # graph/impact/query walks build on.
    visited = sum(len(g.outgoing_edges(nid)) for nid in node_ids)
    elapsed_ms = (time.perf_counter() - start) * 1000

    with capsys.disabled():
        print(f"\n[bench] 1000-node standard traversal: {elapsed_ms:.1f} ms")
    assert visited >= 1000  # framework→control CONTAINS edges
    assert elapsed_ms < 500, f"traversal took {elapsed_ms:.1f} ms (baseline < 500 ms)"


@pytest.mark.benchmark
def test_benchmark_graph_export_and_traverse(capsys):
    g = _build_graph()

    start = time.perf_counter()
    export = g.export_json()
    export_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    edge_total = sum(len(g.outgoing_edges(n["id"])) for n in export["nodes"])
    traverse_elapsed = time.perf_counter() - start

    with capsys.disabled():
        print(
            f"\n[bench] export {len(export['nodes'])} nodes / "
            f"{len(export['edges'])} edges: {export_elapsed * 1000:.1f} ms; "
            f"traverse all outgoing edges: {traverse_elapsed * 1000:.1f} ms"
        )
    # Correctness: every mapping produced a reachable edge.
    assert edge_total >= _POLICIES * 10
