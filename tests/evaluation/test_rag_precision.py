"""Real RAG evaluation — runs the curated corpus through a live indexer.

Skipped by default; run locally with:

    uv run pytest tests/evaluation/ --run-eval

Requires:
    - Ollama running locally (the embedding model the ControlIndexer
      points to must be available).
    - The target framework (``nist-csf-2.0``) indexed via
      ``lemma framework add nist-csf-2.0`` in a sandbox project, or
      equivalent in-process setup.

Baseline targets (informational — these are not CI gates):

    precision@5:             ≥ 0.70
    mean_reciprocal_rank:    ≥ 0.55

Results are printed to stdout for human review and, when the
``EVAL_OUT`` env var is set, appended to the named JSONL file for
offline tracking.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


@pytest.mark.eval
def test_rag_precision_on_nist_csf_corpus(tmp_path: Path):
    from lemma.services.indexer import ControlIndexer
    from lemma.services.rag_eval import evaluate_corpus

    corpus_path = Path(__file__).parent / "corpus_nist_csf_2_0.yaml"

    indexer = ControlIndexer()
    result = evaluate_corpus(indexer, corpus_path=corpus_path, k=5)

    # Human-readable summary.
    print(
        f"\nRAG eval on {result.framework}: "
        f"precision@{result.k}={result.precision_at_k:.2f}, "
        f"MRR={result.mean_reciprocal_rank:.2f} "
        f"({result.total_pairs} pairs)"
    )
    for pair in result.pair_results:
        status = f"rank {pair.rank}" if pair.matched else "MISS"
        print(f"  [{status}] expected={pair.expected} retrieved_top3={pair.retrieved[:3]}")

    # Optional JSONL logging for offline tracking.
    eval_out = os.environ.get("EVAL_OUT")
    if eval_out:
        Path(eval_out).parent.mkdir(parents=True, exist_ok=True)
        with Path(eval_out).open("a") as f:
            f.write(
                json.dumps(
                    {
                        "framework": result.framework,
                        "precision_at_k": result.precision_at_k,
                        "mean_reciprocal_rank": result.mean_reciprocal_rank,
                        "k": result.k,
                        "total_pairs": result.total_pairs,
                    }
                )
                + "\n"
            )

    # Soft assertions — the harness is a regression tracker, not a hard gate.
    # Failing here means the retrieval quality dropped sharply from baseline.
    assert result.total_pairs > 0, "corpus loaded no pairs"
    assert result.precision_at_k >= 0.5, (
        f"precision@{result.k} dropped below 0.5 — investigate the pair_results above."
    )
