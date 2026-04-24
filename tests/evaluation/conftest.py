"""RAG evaluation harness gating.

Adds a ``--run-eval`` pytest flag. Tests marked with
``@pytest.mark.eval`` are skipped unless the flag is passed, because
they require a running Ollama instance with embedding models available
and take noticeably longer than the rest of the suite.

Run locally with::

    uv run pytest tests/evaluation/ --run-eval

CI deliberately does not pass the flag — it runs only the unit tests
that exercise the harness infrastructure itself.
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-eval",
        action="store_true",
        default=False,
        help="Run RAG evaluation tests (requires Ollama locally).",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-eval"):
        return

    skip_eval = pytest.mark.skip(reason="eval tests require --run-eval and a local Ollama instance")
    for item in items:
        if "eval" in item.keywords:
            item.add_marker(skip_eval)
