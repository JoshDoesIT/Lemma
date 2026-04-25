"""AI-inferred control mapping for orphaned Evidence nodes (Refs #88).

Orchestrates the per-evidence inference pipeline:

1. Walk Evidence nodes that have zero outgoing ``EVIDENCES`` edges.
2. Look up each one's original event via the signed evidence log.
3. For each indexed framework, retrieve ``top_k`` candidate controls via
   the same vector index ``lemma map`` uses.
4. Prompt the LLM for ``{"confidence": float, "rationale": str}`` per
   (evidence, candidate) pair and emit one ``AITrace`` per call with
   ``operation="evidence-mapping"``.
5. Gate edge writes by ``automation.threshold_for("evidence-mapping")``;
   ``--accept-all`` bypasses gating and writes every parseable proposal.

The inference step is opt-in: ``lemma evidence load`` remains a fast,
deterministic graph sync. Operators run ``lemma evidence infer`` after
loading to enrich orphaned evidences with AI-proposed edges.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from lemma.models.trace import AITrace
from lemma.services.config import AutomationConfig
from lemma.services.evidence_log import EvidenceLog
from lemma.services.indexer import ControlIndexer
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.llm import LLMClient
from lemma.services.trace_log import TraceLog

_OPERATION = "evidence-mapping"

_INFER_PROMPT = """\
You are a GRC compliance analyst. Given an OCSF event description and a
candidate control, score how strongly this event provides evidence that the
control is in effect.

**Event:**
{event_summary}

**Control ({control_id}): {control_title}**
{control_prose}

Respond ONLY with a JSON object containing:
- "confidence": a float between 0.0 and 1.0 — how well the event evidences the control
- "rationale": a brief explanation (1-2 sentences)

Example: {{"confidence": 0.85, "rationale": "The event records continuous \
audit-log monitoring on a production resource, directly evidencing DE.CM-01."}}
"""


@dataclass(frozen=True)
class InferReport:
    """Summary of an `infer_mappings` run."""

    orphans_processed: int
    edges_written: int
    traces_proposed: int
    skipped_missing_envelope: int


def _get_model_id(llm_client: LLMClient) -> str:
    model = str(getattr(llm_client, "model", "unknown"))
    class_name = type(llm_client).__name__.lower()
    if "ollama" in class_name:
        return f"ollama/{model}"
    if "openai" in class_name:
        return f"openai/{model}"
    return model


def _orphaned_evidences(graph: ComplianceGraph) -> list[dict]:
    """Return Evidence node attribute dicts that have zero EVIDENCES edges."""
    export = graph.export_json()
    evidences = [n for n in export["nodes"] if n.get("type") == "Evidence"]
    has_edge: set[str] = set()
    for edge in export["edges"]:
        if edge.get("relationship") == "EVIDENCES":
            has_edge.add(edge["source"])
    return [n for n in evidences if n["id"] not in has_edge]


def _summarize_event(event) -> str:  # type: ignore[no-untyped-def]
    """Build the prompt-input string from an OCSF event.

    Empty `message` falls back to class_name + activity_id descriptor so
    the LLM never receives a vacuous context block.
    """
    product = ""
    metadata = getattr(event, "metadata", {}) or {}
    if isinstance(metadata, dict):
        product_block = metadata.get("product")
        if isinstance(product_block, dict):
            product = str(product_block.get("name", ""))

    message = getattr(event, "message", "") or ""
    fallback = f"{event.class_name} (activity_id={event.activity_id})"
    body = message if message.strip() else fallback

    return (
        f"class_name={event.class_name} class_uid={event.class_uid} "
        f"activity_id={event.activity_id} severity_id={int(event.severity_id)} "
        f"product={product}\n"
        f"{body}"
    )


def infer_mappings(
    *,
    project_dir: Path,
    llm_client: LLMClient,
    top_k: int = 3,
    accept_all: bool = False,
    automation: AutomationConfig | None = None,
) -> InferReport:
    """Run AI-inferred control mapping over orphaned Evidence nodes.

    Args:
        project_dir: Root of the Lemma project.
        llm_client: LLM client for confidence/rationale generation.
        top_k: Candidates retrieved per framework per evidence.
        accept_all: When True, every parseable proposal becomes an edge
            and the trace is auto-accepted at threshold=0.0.
        automation: Optional ``AutomationConfig`` carrying per-operation
            confidence thresholds. ``threshold_for("evidence-mapping")``
            gates auto-accept; ``None`` (or unset) means never auto-accept.

    Returns:
        ``InferReport`` with run-summary counts.
    """
    lemma_dir = project_dir / ".lemma"
    graph_path = lemma_dir / "graph.json"
    graph = ComplianceGraph.load(graph_path)
    log = EvidenceLog(log_dir=lemma_dir / "evidence")
    trace_log = TraceLog(log_dir=lemma_dir / "traces")
    indexer = ControlIndexer(index_dir=lemma_dir / "index")

    threshold = automation.threshold_for(_OPERATION) if automation is not None else None
    model_id = _get_model_id(llm_client)
    frameworks = indexer.list_indexed_frameworks()

    orphans = _orphaned_evidences(graph)
    edges_written = 0
    traces_proposed = 0
    skipped = 0

    for orphan in orphans:
        envelope = log.get_envelope(orphan["entry_hash"])
        if envelope is None:
            skipped += 1
            continue

        event_summary = _summarize_event(envelope.event)

        for framework in frameworks:
            candidates = indexer.query_similar(framework, event_summary, n_results=top_k)
            for candidate in candidates:
                control_id = candidate["control_id"]
                prompt = _INFER_PROMPT.format(
                    event_summary=event_summary,
                    control_id=control_id,
                    control_title=candidate.get("title", ""),
                    control_prose=candidate.get("document", ""),
                )

                try:
                    raw = llm_client.generate(prompt)
                    parsed = json.loads(raw)
                    confidence = float(parsed.get("confidence", 0.0))
                    rationale = parsed.get("rationale", "No rationale provided.")
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    confidence = 0.0
                    rationale = f"LLM response could not be parsed: {raw[:200]}"

                determination = (
                    "EVIDENCE_INFERRED"
                    if (accept_all or (threshold is not None and confidence >= threshold))
                    else "EVIDENCE_PROPOSED"
                )

                trace = AITrace(
                    operation=_OPERATION,
                    input_text=event_summary[:500],
                    prompt=prompt,
                    model_id=model_id,
                    model_version="",
                    raw_output=raw,
                    confidence=confidence,
                    determination=determination,
                    control_id=control_id,
                    framework=framework,
                    review_rationale=rationale,
                )
                trace_log.append(trace)

                if accept_all:
                    graph.add_evidence_mapping(
                        entry_hash=orphan["entry_hash"],
                        framework=framework,
                        control_id=control_id,
                        confidence=confidence,
                    )
                    trace_log.auto_accept(trace, threshold=0.0)
                    edges_written += 1
                elif threshold is not None and confidence >= threshold:
                    graph.add_evidence_mapping(
                        entry_hash=orphan["entry_hash"],
                        framework=framework,
                        control_id=control_id,
                        confidence=confidence,
                    )
                    trace_log.auto_accept(trace, threshold=threshold)
                    edges_written += 1
                else:
                    traces_proposed += 1

    graph.save(graph_path)

    return InferReport(
        orphans_processed=len(orphans),
        edges_written=edges_written,
        traces_proposed=traces_proposed,
        skipped_missing_envelope=skipped,
    )
