"""Performance-benchmark harness gating.

Adds a ``--run-benchmark`` pytest flag. Tests marked ``@pytest.mark.benchmark``
are skipped unless the flag is passed, so they never slow the default suite
(and never fail CI on timing noise). Run locally with::

    uv run pytest tests/benchmarks/ --run-benchmark -s

Benchmarks assert *correctness* (node/edge counts), not wall-clock thresholds —
the timing is printed for humans, not gated, so the suite stays deterministic.
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-benchmark",
        action="store_true",
        default=False,
        help="Run performance benchmarks.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-benchmark"):
        return
    skip_bench = pytest.mark.skip(reason="benchmarks require --run-benchmark")
    for item in items:
        if "benchmark" in item.keywords:
            item.add_marker(skip_bench)
