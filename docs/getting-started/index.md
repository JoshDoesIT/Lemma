# Getting Started

Get from zero to your first compliance mapping in under 15 minutes.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

```bash
pip install lemma-grc
```

For PDF and Excel framework import support:

```bash
pip install lemma-grc[ingest]
```

## 1. Initialize a Lemma Project

Create a new directory and initialize it:

```bash
mkdir my-compliance && cd my-compliance
lemma init
```

This creates a `.lemma/` directory containing your local index and configuration.

## 2. Add a Framework

Index a bundled compliance framework. Lemma ships with three public domain catalogs:

| Framework | Controls | Command |
|-----------|----------|---------|
| NIST SP 800-53 Rev 5 | 1,196 | `lemma framework add nist-800-53` |
| NIST CSF 2.0 | 219 | `lemma framework add nist-csf-2.0` |
| NIST SP 800-171 Rev 3 | 130 | `lemma framework add nist-800-171` |

```bash
lemma framework add nist-csf-2.0
```

```
✓ Indexed nist-csf-2.0 — 219 controls indexed.
```

## 3. Write Your Policy

Create a `policies/` directory with your organization's security policies as Markdown files:

```bash
mkdir policies
```

```markdown title="policies/access-control.md"
# Access Control Policy

All user accounts require multi-factor authentication (MFA).
Privileged accounts are reviewed quarterly.
Access is granted on a least-privilege basis with role-based access control (RBAC).
```

```markdown title="policies/incident-response.md"
# Incident Response Policy

Security incidents are reported within 1 hour of detection.
A formal incident response plan is maintained and tested annually.
Post-incident reviews are conducted for all severity-1 events.
```

## 4. Map Policies to Controls

Run the mapping engine to match your policies against the framework:

```bash
lemma map --framework nist-csf-2.0 --output json
```

Lemma uses local AI inference (via Ollama) to semantically match your policy statements to framework controls. The output shows which controls your policies satisfy, with confidence scores and rationale.

!!! tip "First run"
    The first mapping run downloads the embedding model (~100MB) and may take a minute. Subsequent runs are cached and fast.

## 5. View Results

Try different output formats:

```bash
# Styled HTML report for stakeholders
lemma map --framework nist-csf-2.0 --output html > report.html

# CSV for spreadsheet import
lemma map --framework nist-csf-2.0 --output csv > mapping.csv

# OSCAL-compliant JSON
lemma map --framework nist-csf-2.0 --output oscal > mapping.oscal.json
```

## 6. Check Coverage

See how much of the framework your policies cover:

```bash
lemma coverage
```

## 7. Find Gaps

Identify controls that aren't addressed by any policy:

```bash
lemma gaps --framework nist-csf-2.0
```

## Next Steps

- **Import your own frameworks:** `lemma framework import my-framework.pdf`
- **Cross-framework harmonization:** `lemma harmonize` maps controls across multiple frameworks
- **Compare framework versions:** `lemma diff --from nist-800-53 --to nist-csf-2.0`
- **Validate OSCAL files:** `lemma validate my-catalog.json`
