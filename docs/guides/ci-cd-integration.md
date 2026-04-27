# CI/CD Integration

Lemma is designed to fail builds when compliance posture regresses. This guide gives you copy-paste-ready GitHub Actions and GitLab CI configurations that wire three commands into a typical pull-request pipeline:

- **`lemma check`** — fails the build if any control in scope has zero satisfying policies.
- **`lemma scope impact --plan <terraform.json>`** — fails the build if a Terraform plan moves a resource into or out of a compliance scope.
- **`lemma evidence verify <entry-hash>`** — sanity-check existing evidence integrity in CI scheduled jobs.

All three commands exit `0` when posture is good and non-zero when it isn't — the standard CI contract. Add them as steps and the pipeline turns red on regression.

## GitHub Actions

The minimal setup runs `lemma check` on every PR. Save as `.github/workflows/compliance.yml`:

```yaml
name: Compliance

on:
  pull_request:
  push:
    branches: [main]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Lemma
        run: pip install lemma-grc

      - name: Index frameworks
        run: |
          lemma init || true
          lemma framework add nist-csf-2.0
          lemma framework add nist-800-53

      - name: Map policies
        run: lemma map --framework nist-csf-2.0

      - name: Compliance gate
        run: lemma check --format json
```

Exit code `1` on any control with zero satisfying policies. The JSON output goes to stdout; pipe it to a file and upload as an artifact if you want to surface it in the PR check summary:

```yaml
      - name: Compliance gate
        run: lemma check --format json | tee compliance-report.json
      - uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: compliance-report.json
```

### Adding scope-impact gating for infrastructure PRs

If your repo has Terraform under `infra/`, add a job that runs `lemma scope impact --plan` so a PR that quietly puts a new S3 bucket into the prod compliance scope fails the build:

```yaml
  scope-impact:
    runs-on: ubuntu-latest
    if: contains(github.event.pull_request.changed_files, 'infra/')
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3

      - name: Generate plan
        working-directory: infra
        run: |
          terraform init -input=false
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Set up Python and Lemma
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install lemma-grc

      - name: Load scopes
        run: |
          lemma framework add nist-csf-2.0
          lemma scope load

      - name: Scope impact
        run: lemma scope impact --plan infra/tfplan.json
```

Exit code is `1` whenever a planned change moves a resource across a scope boundary. The Rich table output lists every affected resource with its entered/exited scopes — review the PR comments to see exactly what the change touches.

### Scheduled evidence integrity checks

Cron a job that walks your evidence log and verifies every entry weekly. Catches tampering, key rotation gone wrong, and storage corruption:

```yaml
  evidence-integrity:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install lemma-grc

      - name: Verify every entry in the log
        run: |
          for hash in $(jq -r '.entry_hash' .lemma/evidence/*.jsonl); do
            lemma evidence verify "$hash" || exit 1
          done
```

Drive it with the workflow's `schedule` trigger (e.g. weekly on Sunday at 06:00 UTC):

```yaml
on:
  schedule:
    - cron: "0 6 * * 0"
```

## GitLab CI

Equivalent shape in `.gitlab-ci.yml`:

```yaml
stages:
  - compliance

compliance:check:
  stage: compliance
  image: python:3.12-slim
  before_script:
    - pip install lemma-grc
    - lemma init || true
    - lemma framework add nist-csf-2.0
  script:
    - lemma map --framework nist-csf-2.0
    - lemma check --format json | tee compliance-report.json
  artifacts:
    paths:
      - compliance-report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

compliance:scope-impact:
  stage: compliance
  image: hashicorp/terraform:1.7
  before_script:
    - apk add --no-cache python3 py3-pip
    - pip install --break-system-packages lemma-grc
  script:
    - cd infra
    - terraform init -input=false
    - terraform plan -out=tfplan
    - terraform show -json tfplan > tfplan.json
    - cd ..
    - lemma framework add nist-csf-2.0
    - lemma scope load
    - lemma scope impact --plan infra/tfplan.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - infra/**/*

compliance:evidence-integrity:
  stage: compliance
  image: python:3.12-slim
  before_script:
    - pip install lemma-grc jq
  script:
    - |
      for hash in $(jq -r '.entry_hash' .lemma/evidence/*.jsonl); do
        lemma evidence verify "$hash" || exit 1
      done
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

## Exit code reference

| Command | Exit `0` | Exit `1` |
|---------|----------|----------|
| `lemma check` | Every control in scope has at least one satisfying policy | Any control unsatisfied, unknown framework, or run outside a Lemma project |
| `lemma scope impact --plan <file>` | The plan is scope-neutral (no resource enters or exits any scope) | Any change moves scope membership; malformed plan; missing scope load |
| `lemma evidence verify <hash>` | Hash, chain, signature, key lifecycle, and provenance all valid (PROVEN) | DEGRADED (signer key unavailable) or VIOLATED (tamper detected) |

All three follow the standard contract — `0` is the only success.

## SARIF + GitHub Code Scanning

`lemma check --format sarif` emits SARIF 2.1.0 JSON. Pipe it through GitHub's `upload-sarif` action and failures appear in the Security tab alongside SAST findings, with PR-aware diff annotations.

```yaml
name: lemma compliance gate
on: [pull_request]
permissions:
  contents: read
  security-events: write   # required for SARIF upload
jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - name: Run lemma check (SARIF)
        run: |
          uv run lemma init || true
          uv run lemma framework add nist-csf-2.0
          uv run lemma check --format sarif > lemma.sarif || true   # don't fail-fast; let upload-sarif annotate the PR
      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: lemma.sarif
          category: lemma-compliance
      - name: Re-run check to set the exit code
        run: uv run lemma check --format json
```

The `|| true` on the SARIF run ensures the upload step always executes — operators want PR annotations even on failures, and the final `lemma check` step sets the actual gate exit code. For GitLab, the same SARIF can be uploaded as a `report:sast` artifact:

```yaml
lemma_check:
  stage: test
  script:
    - uv run lemma check --format sarif > lemma.sarif
  artifacts:
    reports:
      sast: lemma.sarif
```

### Stricter gating with `--min-confidence`

```yaml
- name: Run strict gate (only high-confidence mappings count)
  run: uv run lemma check --format sarif --min-confidence 0.9 > lemma.sarif
```

`--min-confidence` is **orthogonal** to `ai.automation.thresholds.map` (which governs auto-accept of new mappings). Setting `--min-confidence 0.9` in CI lets `lemma map` keep auto-accepting at 0.85 (so mappings show up in `lemma ai audit` for human review) while gating the merge on a higher bar. Useful when you're fine with low-confidence mappings being recorded but don't want them counted toward CI's pass/fail.

## What's NOT here

- **Native GitHub Action** — a `lemma-ai/lemma-action` wrapper that posts results as PR comments (instead of via the SARIF upload path) is tracked at [#120](https://github.com/JoshDoesIT/Lemma/issues/120). The SARIF route above already covers Code Scanning ingestion; the wrapper adds PR-comment summaries on top.
- **Self-hosted runner setup for `--run-eval`** — running the RAG evaluation harness in CI requires a runner with Ollama installed. Out of scope for this guide; see [`docs/guides/rag-evaluation.md`](./rag-evaluation.md) for the local-only setup that exists today.
