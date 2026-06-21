# OpenSSF Best Practices

Lemma tracks two distinct OpenSSF programs:

- **[Scorecard](https://securityscorecards.dev/)** — an automated scan of repo
  configuration (pinned dependencies, token permissions, branch protection,
  …). Run by `.github/workflows/scorecard.yml`; the ≥ 7/10 target lives in #47.
- **[Best Practices](https://www.bestpractices.dev/)** — a *self-attested*
  questionnaire across three tiers (passing → silver → gold).

This page is the reproducible record of the **passing-tier** answers, so the
questionnaire can be refiled if the project ID is ever lost or migrated. It is
not the badge itself — the live badge is earned by submitting these answers at
[bestpractices.dev](https://www.bestpractices.dev/projects/new).

> **Project ID:** _not yet registered_. After registering, record the ID here
> and add the badge to `README.md` sourced from
> `https://www.bestpractices.dev/projects/<id>/badge` (never a static
> shields.io placeholder — see #178 for why).

## Scorecard configuration (this repo)

The configuration-level Scorecard checks are enforced in code and guarded by a
regression test (`tests/tools/test_workflow_security.py`):

| Check | Status | Where |
|-------|--------|-------|
| Pinned-Dependencies | Met | every action in `.github/workflows/*.yml` is pinned to a full commit SHA |
| Token-Permissions | Met | every workflow declares an explicit `permissions:` block; jobs elevate only where needed |
| Dependency-Update-Tool | Met | `.github/dependabot.yml` monitors `uv` (Python), `github-actions`, and `npm` |
| Dangerous-Workflow | Met | no `pull_request_target` / untrusted-checkout patterns |
| SAST | Met | Snyk Code runs on every PR (`security.yml`) |
| Vulnerabilities | Met | Snyk SCA runs on every PR (`security.yml`) |
| License | Met | `LICENSE` (Apache-2.0) |
| Branch-Protection | **Repo setting** | enable on `main` in Settings → Branches (see below) |
| Signed-Releases | Met | keyless cosign signatures + SLSA build provenance on every release ([Verifying Releases](verifying-releases.md)) |
| Code-Review | Partial | structurally limited on a solo-maintainer repo; mitigated by mandatory PR + self-review |

### Repo settings that aren't a code change

These are configured in the GitHub UI / API, not a PR:

- **Branch protection on `main`** — require a PR before merge, require status
  checks (CI, Security Scans, Scorecard), and require linear history. Verify:
  `gh api repos/JoshDoesIT/Lemma/branches/main/protection`.
- **Dependabot security updates** — enable in Settings → Code security.

## Best Practices passing-tier questionnaire

Status of each criterion group; **Met** items cite the satisfying artifact,
**Open** items link the tracking issue.

### Basics
- **Project description / homepage** — Met (`README.md`).
- **Contribution process documented** — Met (`CONTRIBUTING.md`).
- **OSS license (OSI-approved, FLOSS)** — Met (`LICENSE`, Apache-2.0).
- **License location** — Met (`LICENSE` at repo root).
- **Documentation (basics + interface)** — Met (`docs/` site, MkDocs Material).
- **Code of conduct** — Met (`CODE_OF_CONDUCT.md`).

### Change control
- **Public version-controlled source** — Met (GitHub; full history).
- **Unique version numbering** — Met (semver; `pyproject.toml` / Git tags).
- **Release notes** — Met (`release.yml` generates GitHub Release notes per tag).

### Reporting
- **Bug-reporting process** — Met (GitHub Issues; templates under `.github/`).
- **Vulnerability-reporting process** — Met (`SECURITY.md`).
- **Vulnerability report response** — Met (`SECURITY.md` states the SLA).

### Quality
- **Working build system** — Met (`pyproject.toml`; `uv` / `hatch`).
- **Automated test suite** — Met (`pytest`, run in `ci.yml`).
- **Tests added for new functionality (policy)** — Met (TDD; see
  `docs/contributing/testing-standards.md`).
- **Warning flags / linters** — Met (`ruff check` + `ruff format --check` in CI).

### Security
- **Secure development knowledge** — Met (this page + `docs/security/`).
- **Good cryptographic practice** — Met (Ed25519 signing, Fernet/PBKDF2 for the
  secret store; no home-rolled primitives).
- **Secured delivery against MITM** — Met (HTTPS/TLS; mTLS for agent forward).
- **Publicly known vulnerabilities fixed** — Met (Snyk SCA + Dependabot).
- **No leaked credentials** — Met (secrets never committed; `${secret:NAME}`
  resolution + encrypted store, see `security/connector-secrets.md`).

### Analysis
- **Static analysis** — Met (Snyk Code; `ruff`).
- **Dynamic analysis** — Partial (test suite exercises runtime paths; dedicated
  fuzzing is a silver-tier stretch).

## Open items before the badge is fully green

- Register the project and record the ID above.
- Enable branch protection + Dependabot security updates (repo settings).
- ~~Signed releases / SLSA provenance~~ — done (#47): keyless cosign + SLSA
  build provenance, see [Verifying Releases](verifying-releases.md).

Silver and gold tiers (formal patch review by a second maintainer, multiple
unaffiliated maintainers) are structurally hard on a solo-maintainer project
and are deferred to Phase 4 community work.
