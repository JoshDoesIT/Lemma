# Testing Standards

Lemma treats tests as a first-class part of every change. This page is the
reference for how the suite is organized, what's expected of a contribution,
and the conventions that keep the suite fast, deterministic, and offline.

## The golden rule: no code without a test

Every behavioral change ships with a test that would fail without it. New
features are written test-first (TDD): write the failing test, implement until
it passes, then refactor. This is enforced in review, not just encouraged.

## Coverage gate

The project enforces a **minimum 90% line coverage** (`fail_under = 90` in
`pyproject.toml`). A change that drops coverage below the gate fails CI. Aim to
cover the branches your change introduces — not just the happy path, but the
error paths (missing config, rate limits, malformed input) that the codebase
is careful to handle loudly.

## Test layout

Tests live under `tests/`, mirroring the package structure:

| Directory | Covers |
|-----------|--------|
| `tests/models/` | Pydantic models and schema validation. |
| `tests/services/` | Service-layer logic (graph, evidence, scope matcher, connectors' backing services). |
| `tests/commands/` | CLI commands via Typer's `CliRunner`. |
| `tests/sdk/` | The connector SDK and first-party connectors, including the cross-connector [conformance suite](#cross-cutting-suites). |
| `tests/integration/` | End-to-end flows that span multiple layers (e.g. the scope-as-code lifecycle, agent ↔ verify). |
| `tests/tools/` | Repo guardrails (CLI-docs drift, doc-link integrity). |
| `tests/evaluation/` | RAG evaluation tests (see [markers](#markers)). |
| `tests/fixtures/` | Shared fixture data. |

Place a test next to the layer it exercises; reach for `tests/integration/`
only when the point of the test is the seam between layers.

## Conventions that keep the suite hermetic

- **No network, ever.** External HTTP is mocked with `httpx.MockTransport`
  injected through a connector's `client=` parameter; cloud SDKs are stubbed.
  A test that needs a real service is a bug.
- **Inject the clock and sleeps.** Time-dependent logic (dedupe UIDs, the
  connector scheduler) takes an injectable `now` / sleep seam so tests are
  deterministic and never actually sleep.
- **Inject filesystem roots.** Use `tmp_path` and `monkeypatch.chdir`; never
  write outside the test's temp dir.
- **Assert on behavior and error messages.** When a path is supposed to fail
  loudly, assert the exit code *and* that the message names the offending
  thing (the missing env var, the unmatched datacenter, the bad `.rego` file).

## Cross-cutting suites

Two suites assert contracts that span the codebase:

- **Connector conformance** (`tests/sdk/test_connector_conformance.py`) drives
  every httpx-based first-party connector through one harness and asserts the
  shared contract: valid OCSF output, a stable non-empty `metadata.uid`, and a
  populated manifest. A new connector that violates the contract fails here
  without needing the author to remember a checklist.
- **Documentation guardrails** (`tests/tools/`) assert that every CLI command
  has a doc section and that every doc nav page and cross-file link resolves.

## Running the suite

```bash
uv run pytest                       # full suite (markers strict)
uv run pytest tests/services -q     # one category
uv run pytest --run-eval            # include the RAG evaluation tests
uv run pytest --cov                 # with coverage (gate at 90%)
uv run ruff check && uv run ruff format --check   # lint + format must be clean
```

## Markers

| Marker | Meaning |
|--------|---------|
| `eval` | RAG evaluation tests that require a local Ollama; **skipped by default**, run with `--run-eval`. |

`--strict-markers` is on, so a typo'd or unregistered marker fails collection
rather than silently passing.

## Benchmarks

Performance benchmarks live under `tests/benchmarks/`, behind the `benchmark`
marker, and are **skipped by default** so they never slow the suite or fail CI
on timing noise:

```bash
uv run pytest tests/benchmarks/ --run-benchmark -s
```

Benchmarks assert **correctness** (node/edge counts), not wall-clock
thresholds — the timing is printed for humans, not gated. The initial set
covers compliance-graph build and export/traversal at scale (2,000 controls,
200 policies); add new benchmarks here as new hot paths emerge (embedding,
evidence verification at scale). Keep an eye on the runtime of regular tests
too — the default suite should stay fast enough to run on every change.
