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
