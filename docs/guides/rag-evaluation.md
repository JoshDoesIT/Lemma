# RAG Evaluation

Lemma maps organizational policies to framework controls by retrieving candidate controls from a vector index (via `ControlIndexer`) and ranking them. This guide describes how to **measure** the quality of that retrieval — precision@k and mean reciprocal rank (MRR) — against a curated ground-truth corpus so regressions caused by embedding-model changes, prompt edits, or indexer tweaks are detectable before they ship.

The harness is deliberately a **local-only** tool. CI doesn't run it; the evaluation requires a running Ollama instance with the embedding model the current `ControlIndexer` points at. Running it in CI would require a GPU-enabled runner — out of scope for this project today and explicitly deferred per issue #70's original scope.

## Running an evaluation

From the project root with Ollama available:

```bash
# Index the target framework first (if it isn't already)
lemma init sandbox && cd sandbox
lemma framework add nist-csf-2.0

# Run the eval (from the Lemma repo root, not the sandbox)
cd /path/to/lemma
uv run pytest tests/evaluation/ --run-eval
```

Passing `--run-eval` un-skips tests marked with `@pytest.mark.eval`. Without the flag those tests are skipped, so `uv run pytest` (what CI runs) stays fast and Ollama-free.

## Metrics

### `precision@k`

For each `(policy_text, expected_controls)` pair, precision@k is **1.0 if any expected control appears in the top k retrieved**, else 0.0. Per-pair precision is binary rather than fractional because a single policy typically has one correct mapping — partial retrievals obscure the signal.

The corpus-wide precision@k is the arithmetic mean across pairs. Interpretation:

- `1.0` — every policy's correct control showed up in the top k. Embedding model is doing its job.
- `0.5` — half the policies missed entirely. Check whether the embedding model changed or the corpus drifted from what the index contains.
- `< 0.5` — something broke. Look at `pair_results` for which pairs missed and what was retrieved instead.

### `mean_reciprocal_rank` (MRR)

For each pair, the reciprocal of the rank of the first matching control (`1 / rank`, or 0 if no match in any rank). Averaged across pairs. Ranges from 0 to 1; higher is better.

MRR is more sensitive to position than precision@k — a change that pushes a correct answer from rank 1 to rank 3 doesn't affect precision@5 but halves MRR. Use it to catch "retrieval still works but rank quality dropped."

## The corpus

`tests/evaluation/corpus_nist_csf_2_0.yaml` ships with 10 human-validated pairs covering NIST CSF 2.0 categories (Govern, Identify, Protect, Detect, Respond, Recover).

When adding a pair:

1. Pick a realistic policy excerpt. Paraphrase a real compliance document rather than copying — the text shouldn't be lifted from an indexed control's prose.
2. Identify one or more `expected_controls`. Multiple expected controls are acceptable when the policy could reasonably map to any of a small set of adjacent controls — the match is counted if **any** expected control is retrieved.
3. Keep the corpus small. 10–20 pairs is enough for regression tracking; larger corpora dilute the signal and slow runs.

## Tracking over time

Set `EVAL_OUT` to a JSONL path and each run appends its summary:

```bash
EVAL_OUT=~/lemma-eval.jsonl uv run pytest tests/evaluation/ --run-eval
```

The JSONL record includes framework, `precision_at_k`, `mean_reciprocal_rank`, `k`, and `total_pairs`. Diff across runs to spot regressions:

```bash
cat ~/lemma-eval.jsonl | jq -c '{p: .precision_at_k, mrr: .mean_reciprocal_rank}'
```

## Baseline targets

These are **informational**, not hard gates:

| Metric | Target |
|---|---|
| precision@5 | ≥ 0.70 |
| MRR | ≥ 0.55 |

The `test_rag_precision_on_nist_csf_corpus` test asserts `precision@5 ≥ 0.5` as a soft guardrail — if it fails, investigate the `pair_results` stdout rather than immediately relaxing the threshold.

## What's not here

- **Faithfulness scoring** — "does the LLM's mapping rationale actually reference the retrieved control?" needs LLM-judge calls and structured output parsing. Future refinement.
- **CI integration** — running on a GPU-enabled self-hosted runner. See issue #70 for historical context.
- **Multi-framework corpora** — `nist-800-53` is a bigger catalog (1,196 controls vs. 219 for CSF 2.0) and a second corpus there is worth adding once retrieval quality on CSF is measured.
