"""RAG evaluation harness — precision@k and MRR over a curated corpus.

Scope: Lemma maps policies to framework controls via vector retrieval.
This module measures how well that retrieval works against a curated
set of ``policy_text → expected_controls`` pairs. The harness is used
locally (with Ollama) for regression tracking as the embedding model
or prompts evolve; CI does not execute it by default (pytest.mark.eval
is skipped without --run-eval).

No LLM invocation here — the harness talks only to the
``ControlIndexer``. Faithfulness (does the rationale reference the
expected control?) would need LLM judge calls and is a future refinement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml


class _Indexer(Protocol):
    """Minimal protocol for anything that answers `query_similar`."""

    def query_similar(self, framework_name: str, text: str, n_results: int = 5) -> list[dict]: ...


@dataclass(frozen=True)
class CorpusPair:
    policy_text: str
    expected_controls: list[str]


@dataclass(frozen=True)
class Corpus:
    framework: str
    pairs: list[CorpusPair]


@dataclass(frozen=True)
class PairResult:
    policy_text: str
    expected: list[str]
    retrieved: list[str]
    matched: bool
    rank: int | None  # 1-indexed rank of the first matching retrieval, or None


@dataclass(frozen=True)
class EvalResult:
    framework: str
    total_pairs: int
    precision_at_k: float
    mean_reciprocal_rank: float
    k: int
    pair_results: list[PairResult] = field(default_factory=list)


def precision_at_k(retrieved: list[str], expected: list[str], k: int) -> float:
    """1.0 if any expected control appears in the top-k retrieved, else 0.0.

    Per-pair precision is binary rather than fractional because a
    policy typically has a single correct mapping — partial retrievals
    obscure the metric.
    """
    expected_set = set(expected)
    for control_id in retrieved[:k]:
        if control_id in expected_set:
            return 1.0
    return 0.0


def mean_reciprocal_rank(pairs: list[tuple[list[str], list[str]]]) -> float:
    """MRR across `(retrieved, expected)` pairs. Pairs that never match contribute 0."""
    if not pairs:
        return 0.0

    total = 0.0
    for retrieved, expected in pairs:
        expected_set = set(expected)
        for rank, control_id in enumerate(retrieved, start=1):
            if control_id in expected_set:
                total += 1.0 / rank
                break
    return total / len(pairs)


def load_corpus(path: Path) -> Corpus:
    """Parse a ground-truth YAML corpus.

    Schema::
        framework: <name>
        pairs:
          - policy_text: "..."
            expected_controls: [id1, id2]

    Raises:
        ValueError: Empty ``expected_controls`` on any pair — an empty
            list means nothing to measure, which is almost certainly a
            corpus authoring mistake rather than intentional.
    """
    raw: Any = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        msg = f"{path.name}: corpus root must be a mapping."
        raise ValueError(msg)

    framework = str(raw.get("framework", ""))
    pairs_raw = raw.get("pairs") or []
    pairs: list[CorpusPair] = []

    for i, pair in enumerate(pairs_raw):
        expected = pair.get("expected_controls") or []
        if not expected:
            msg = f"{path.name}: pair #{i + 1} has empty expected_controls."
            raise ValueError(msg)
        pairs.append(
            CorpusPair(
                policy_text=str(pair.get("policy_text", "")),
                expected_controls=list(expected),
            )
        )

    return Corpus(framework=framework, pairs=pairs)


def evaluate_corpus(
    indexer: _Indexer,
    *,
    corpus_path: Path,
    k: int = 5,
) -> EvalResult:
    """Run every corpus pair through the indexer and compute aggregate metrics."""
    corpus = load_corpus(corpus_path)

    retrieval_pairs: list[tuple[list[str], list[str]]] = []
    pair_results: list[PairResult] = []
    hits = 0

    for pair in corpus.pairs:
        results = indexer.query_similar(corpus.framework, pair.policy_text, n_results=k)
        retrieved_ids = [r["control_id"] for r in results]
        retrieval_pairs.append((retrieved_ids, pair.expected_controls))

        # Determine rank of first matching retrieval, if any.
        expected_set = set(pair.expected_controls)
        rank: int | None = None
        for r, cid in enumerate(retrieved_ids, start=1):
            if cid in expected_set:
                rank = r
                break

        matched = rank is not None
        if matched:
            hits += 1

        pair_results.append(
            PairResult(
                policy_text=pair.policy_text,
                expected=pair.expected_controls,
                retrieved=retrieved_ids,
                matched=matched,
                rank=rank,
            )
        )

    total = len(corpus.pairs)
    p_at_k = hits / total if total else 0.0
    mrr = mean_reciprocal_rank(retrieval_pairs)

    return EvalResult(
        framework=corpus.framework,
        total_pairs=total,
        precision_at_k=p_at_k,
        mean_reciprocal_rank=mrr,
        k=k,
        pair_results=pair_results,
    )
