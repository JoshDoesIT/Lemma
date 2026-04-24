"""Tests for the RAG evaluation harness service."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock


def _mock_indexer(results_by_text: dict[str, list[str]]) -> MagicMock:
    """Return a mock ControlIndexer whose query_similar returns the given control_ids."""
    indexer = MagicMock()

    def _query(framework_name: str, text: str, n_results: int = 5) -> list[dict]:
        ids = results_by_text.get(text, [])[:n_results]
        return [{"control_id": cid, "title": cid, "distance": 0.1, "document": ""} for cid in ids]

    indexer.query_similar.side_effect = _query
    return indexer


class TestMetrics:
    def test_precision_at_k_hits_when_expected_in_top_k(self):
        from lemma.services.rag_eval import precision_at_k

        assert precision_at_k(retrieved=["ac-2", "ac-3"], expected=["ac-2"], k=2) == 1.0
        assert precision_at_k(retrieved=["ac-3", "ac-2"], expected=["ac-2"], k=2) == 1.0

    def test_precision_at_k_misses_when_expected_outside_top_k(self):
        from lemma.services.rag_eval import precision_at_k

        # k=1, expected at position 2 → miss
        assert precision_at_k(retrieved=["ac-3", "ac-2"], expected=["ac-2"], k=1) == 0.0

    def test_precision_at_k_handles_any_expected_match(self):
        """A pair can have multiple valid expected controls (harmonized equivalents)."""
        from lemma.services.rag_eval import precision_at_k

        assert (
            precision_at_k(
                retrieved=["ac-2", "other"],
                expected=["gv.oc-1", "ac-2"],
                k=3,
            )
            == 1.0
        )

    def test_mean_reciprocal_rank_first_position(self):
        from lemma.services.rag_eval import mean_reciprocal_rank

        # Expected at rank 1 in both pairs → MRR = 1.0
        pairs = [
            (["ac-2", "ac-3"], ["ac-2"]),
            (["pr.aa-1", "gv.oc-1"], ["pr.aa-1"]),
        ]
        assert mean_reciprocal_rank(pairs) == 1.0

    def test_mean_reciprocal_rank_averages_positions(self):
        from lemma.services.rag_eval import mean_reciprocal_rank

        # First pair: rank 1 (1.0); second pair: rank 3 (1/3); average 2/3
        pairs = [
            (["ac-2", "ac-3"], ["ac-2"]),
            (["other1", "other2", "gv.oc-1"], ["gv.oc-1"]),
        ]
        assert mean_reciprocal_rank(pairs) == (1.0 + 1 / 3) / 2

    def test_mean_reciprocal_rank_zero_when_not_retrieved(self):
        from lemma.services.rag_eval import mean_reciprocal_rank

        pairs = [(["ac-3", "ac-4"], ["ac-2"])]
        assert mean_reciprocal_rank(pairs) == 0.0


class TestEvaluateCorpus:
    def test_computes_aggregate_metrics_across_corpus(self, tmp_path: Path):
        from lemma.services.rag_eval import evaluate_corpus

        corpus = tmp_path / "corpus.yaml"
        corpus.write_text(
            """\
framework: nist-csf-2.0
pairs:
  - policy_text: "Access control policy for all employees."
    expected_controls:
      - ac-2
  - policy_text: "Logs must be retained for 90 days."
    expected_controls:
      - au-2
"""
        )

        indexer = _mock_indexer(
            {
                "Access control policy for all employees.": ["ac-2", "ac-3"],
                "Logs must be retained for 90 days.": ["ac-4", "au-2", "au-3"],
            }
        )

        result = evaluate_corpus(indexer, corpus_path=corpus, k=3)

        assert result.total_pairs == 2
        assert result.framework == "nist-csf-2.0"
        assert result.precision_at_k == 1.0  # both hit within k=3
        # MRR = (1/1 + 1/2) / 2
        assert result.mean_reciprocal_rank == (1.0 + 0.5) / 2

    def test_records_per_pair_outcomes_for_post_hoc_inspection(self, tmp_path: Path):
        from lemma.services.rag_eval import evaluate_corpus

        corpus = tmp_path / "corpus.yaml"
        corpus.write_text(
            """\
framework: nist-csf-2.0
pairs:
  - policy_text: "Something specific"
    expected_controls: [ac-2]
"""
        )
        indexer = _mock_indexer({"Something specific": ["ac-2", "ac-3"]})

        result = evaluate_corpus(indexer, corpus_path=corpus, k=2)

        assert len(result.pair_results) == 1
        pair = result.pair_results[0]
        assert pair.matched is True
        assert pair.rank == 1
        assert pair.retrieved == ["ac-2", "ac-3"]
        assert pair.expected == ["ac-2"]


class TestCorpusLoader:
    def test_accepts_valid_corpus(self, tmp_path: Path):
        from lemma.services.rag_eval import load_corpus

        corpus = tmp_path / "c.yaml"
        corpus.write_text(
            """\
framework: nist-800-53
pairs:
  - policy_text: "foo"
    expected_controls: [ac-1]
"""
        )

        loaded = load_corpus(corpus)
        assert loaded.framework == "nist-800-53"
        assert len(loaded.pairs) == 1

    def test_rejects_empty_expected_controls(self, tmp_path: Path):
        import pytest

        from lemma.services.rag_eval import load_corpus

        corpus = tmp_path / "c.yaml"
        corpus.write_text(
            """\
framework: nist-800-53
pairs:
  - policy_text: "foo"
    expected_controls: []
"""
        )

        with pytest.raises(ValueError, match=r"(?i)expected_controls"):
            load_corpus(corpus)
