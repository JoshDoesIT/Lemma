# Verifying Releases

Every Lemma release is **signed** and carries **build provenance** so you can
prove an artifact came from this repository's release workflow and wasn't
tampered with in transit (Refs #47).

## What ships with a release

For each tagged release (`v*`), the workflow publishes:

- the Python distributions (`dist/*.whl`, `dist/*.tar.gz`),
- the SBOM (`sbom.json`) and AI BOM (`aibom.cdx.json`),
- the AI System Card (`ai-system-card.json` / `.md`),
- a **cosign signature bundle** (`*.cosign.bundle`) next to each signed artifact,
- a **SLSA build-provenance attestation** for the Python distributions.

Signing is **keyless** (sigstore): the signing identity is the release
workflow's GitHub OIDC token — there is no long-lived private key to leak.

## Verify a signature (cosign)

Download an artifact and its `.cosign.bundle`, then:

```bash
cosign verify-blob \
  --bundle lemma-<version>-py3-none-any.whl.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/JoshDoesIT/Lemma/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  lemma-<version>-py3-none-any.whl
```

A `Verified OK` means the artifact was signed by this repo's release workflow
on a tag. The same command works for `sbom.json`, `aibom.cdx.json`, and
`ai-system-card.json` against their respective bundles.

## Verify build provenance (SLSA)

The Python distributions carry a SLSA build-provenance attestation (generated
by `actions/attest-build-provenance`). Verify it with the GitHub CLI:

```bash
gh attestation verify lemma-<version>-py3-none-any.whl --repo JoshDoesIT/Lemma
```

This confirms the artifact was built by this repository's workflow and reports
the source commit and build parameters recorded in the attestation.

## Threat model

Signing + provenance protect against a tampered or spoofed artifact: a file
that wasn't produced by this repo's release workflow fails verification. They
do **not** vouch for the *correctness* of the code that was released — only its
origin and integrity. Always pin to a released version and verify before
deploying in a regulated environment.
