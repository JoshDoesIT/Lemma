# `lemma-check` — GitHub Action

Run [`lemma check`](../../docs/reference/index.md) to gate a pull request on
compliance posture, and post the result as a PR comment. This is the reusable
wrapper referenced by [#120](https://github.com/JoshDoesIT/Lemma/issues/120) /
[#28](https://github.com/JoshDoesIT/Lemma/issues/28).

## Usage

```yaml
name: Compliance
on: [pull_request]

permissions:
  contents: read
  pull-requests: write   # required for the PR comment

jobs:
  lemma:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: joshdoesit/lemma/actions/lemma-check@main
        with:
          framework: nist-800-53
          min-confidence: "0.7"
```

The step exits non-zero when compliance violations are detected, failing the
job and blocking the PR.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `framework` | (all) | Restrict the check to a single framework. |
| `min-confidence` | `0.0` | Only count `SATISFIES` edges at or above this confidence. |
| `format` | `text` | `text`, `json`, or `sarif`. |
| `policy-dir` | (none) | Directory of `.rego` policies to evaluate alongside coverage. |
| `working-directory` | `.` | Directory containing the Lemma project (`.lemma/`). |
| `version` | `lemma-grc` | pip requirement to install (pin with `lemma-grc==<version>`). |
| `comment-on-pr` | `true` | Post the result as a PR comment. |
| `github-token` | `${{ github.token }}` | Token used to post the comment. |

## SARIF → Code Scanning

Set `format: sarif`, write to a file, and upload with
`github/codeql-action/upload-sarif` — see the
[CI/CD integration guide](../../docs/guides/ci-cd-integration.md#sarif--github-code-scanning).
