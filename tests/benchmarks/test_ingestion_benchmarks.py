"""Framework-ingestion performance benchmark (Refs #48).

Establishes the baseline for the #48 acceptance criterion "framework ingestion
< 30s for a 500-control catalog". Benchmarks the *structural* ingestion path —
parsing an OSCAL catalog into control records and bulk-loading them into the
compliance graph (``parse_catalog`` + ``ComplianceGraph.populate_from_controls``).
Embedding/RAG indexing (``Indexer.index_controls``) is model-bound and excluded;
it is exercised by the eval suite, not this hermetic benchmark.

Skipped by default; run with ``uv run pytest tests/benchmarks/ --run-benchmark -s``.
Like the graph benchmarks, this asserts *correctness* (control counts / nodes
present), not a wall-clock threshold — the timing is printed for humans so the
suite stays deterministic and never flakes on CI timing noise.
"""

from __future__ import annotations

import time

import pytest

from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.parsers.oscal import parse_catalog

_FAMILIES = 25
_CONTROLS_PER_FAMILY = 20  # 25 x 20 = 500 controls


def _synthetic_oscal_catalog(families: int, per_family: int) -> dict:
    """Build a well-formed OSCAL catalog dict with ``families * per_family``
    controls, each carrying a statement part so the prose extractor runs."""
    groups = []
    for f in range(families):
        controls = []
        for c in range(per_family):
            cid = f"f{f}-c{c}"
            controls.append(
                {
                    "id": cid,
                    "title": f"Control {cid}",
                    "parts": [
                        {
                            "name": "statement",
                            "prose": (
                                f"The organization implements and enforces {cid} across "
                                "all in-scope systems, reviewing the control periodically."
                            ),
                        }
                    ],
                }
            )
        groups.append({"id": f"fam-{f}", "title": f"Family {f}", "controls": controls})
    return {"groups": groups}


@pytest.mark.benchmark
def test_benchmark_framework_ingestion_500_controls(capsys):
    catalog = _synthetic_oscal_catalog(_FAMILIES, _CONTROLS_PER_FAMILY)
    expected = _FAMILIES * _CONTROLS_PER_FAMILY

    start = time.perf_counter()
    controls = parse_catalog(catalog)
    graph = ComplianceGraph()
    graph.populate_from_controls("bench-fw", controls)
    elapsed = time.perf_counter() - start

    with capsys.disabled():
        print(
            f"\n[bench] ingest {expected}-control OSCAL catalog "
            f"(parse + graph populate): {elapsed * 1000:.1f} ms"
        )

    # Correctness, not timing: every control parsed and landed in the graph.
    assert len(controls) == expected
    last_id = f"f{_FAMILIES - 1}-c{_CONTROLS_PER_FAMILY - 1}"
    assert graph.get_node("control:bench-fw:f0-c0") is not None
    assert graph.get_node(f"control:bench-fw:{last_id}") is not None


@pytest.mark.benchmark
def test_benchmark_parse_handles_nested_enhancements(capsys):
    """Real catalogs (e.g. NIST 800-53) nest control enhancements; confirm the
    parser flattens them and time a catalog that mixes controls + enhancements."""
    groups = []
    for f in range(20):
        controls = []
        for c in range(20):
            cid = f"g{f}-c{c}"
            controls.append(
                {
                    "id": cid,
                    "title": f"Control {cid}",
                    "parts": [{"name": "statement", "prose": f"Base control {cid}."}],
                    "controls": [
                        {
                            "id": f"{cid}.1",
                            "title": f"Enhancement {cid}.1",
                            "parts": [{"name": "statement", "prose": f"Enhancement of {cid}."}],
                        }
                    ],
                }
            )
        groups.append({"id": f"g-{f}", "title": f"Group {f}", "controls": controls})
    catalog = {"groups": groups}
    expected = 20 * 20 * 2  # each base control + one enhancement

    start = time.perf_counter()
    controls = parse_catalog(catalog)
    elapsed = time.perf_counter() - start

    with capsys.disabled():
        print(f"\n[bench] parse {expected} controls+enhancements: {elapsed * 1000:.1f} ms")

    assert len(controls) == expected
    # Enhancements are flattened alongside their base control.
    assert any(ctrl["id"] == "g0-c0.1" for ctrl in controls)
