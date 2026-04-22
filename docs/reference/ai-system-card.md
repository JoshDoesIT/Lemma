# AI System Card

The AI System Card is Lemma's versioned transparency document. It names every AI model used in the platform, what each is used for, what it can and can't do, and what governance controls are in place around it.

The card is the authoritative answer to "which AI is responsible for this output?". It's versioned independently of the Lemma release so auditors can pin the exact AI configuration in force for any given evidence snapshot.

**How to consume this page:**

- The content below is the current card, rendered into Markdown. It's stamped into the docs at build time and is the same content `lemma ai system-card` produces from the CLI.
- For machine-readable JSON, run `lemma ai system-card --format json` from an initialized project.
- Automating the card's publication into every GitHub Release artifact alongside the SBOM and AIBOM is tracked as issue [#93](https://github.com/JoshDoesIT/Lemma/issues/93).

---

# Lemma AI Transparency Card

**Version:** 1.0.0

## Overview

This document describes every AI model used in the Lemma GRC platform, their capabilities, known limitations, and the governance controls in place to ensure trustworthy AI-assisted compliance.

## Intended Use

Lemma uses AI to accelerate compliance mapping by identifying semantic relationships between organizational policies and framework controls. AI outputs are always advisory — they require human review before becoming part of the compliance record.

## Out of Scope

The following uses are **explicitly out of scope** for Lemma's AI capabilities:

- Legal compliance determinations — Lemma does not provide legal advice
- Audit sign-off — AI outputs cannot substitute for qualified auditor judgment
- Regulatory enforcement decisions
- Autonomous control implementation without human review

## Risk Mitigations

- All AI outputs enter PROPOSED state requiring explicit human review
- Rejection requires a mandatory rationale (enforced programmatically)
- Append-only trace log captures every AI decision with full context
- Confidence thresholds flag uncertain results as LOW_CONFIDENCE
- Model provenance tracked via model_id and version in every trace
- No customer data is sent to external APIs when using local models (Ollama)

## Model Registry

### ollama/llama3.2

- **Provider:** Ollama (local)
- **Version:** 3.2
- **Purpose:** Control mapping — maps policy excerpts to framework controls with confidence scores and natural language rationales
- **Training Data:** Meta Llama 3.2 — trained on publicly available internet data. No Lemma-specific fine-tuning has been applied.

**Capabilities:**

- Semantic policy-to-control matching
- Confidence scoring (0.0-1.0) for mapping quality
- Natural language rationale generation
- Runs locally — no data leaves the machine

**Known Limitations:**

- May hallucinate control relationships not supported by policy text
- Not fine-tuned on domain-specific GRC/compliance data
- Performance degrades on highly technical or niche frameworks
- Context window limits may truncate long policy documents
- Confidence scores are self-reported and may not correlate with accuracy

### openai/gpt-4o-mini

- **Provider:** OpenAI (cloud)
- **Version:** 2024-07-18
- **Purpose:** Control mapping (optional cloud backend)
- **Training Data:** OpenAI proprietary training data (not disclosed)

**Capabilities:**

- Higher accuracy on complex policy language
- Larger context window for long documents
- Semantic policy-to-control matching with rationales

**Known Limitations:**

- Requires API key — data is sent to OpenAI servers
- Subject to OpenAI's data retention and usage policies
- API availability depends on external service
- Cost per token may be significant at scale
