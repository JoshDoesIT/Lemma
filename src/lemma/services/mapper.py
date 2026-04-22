"""Control mapping engine — maps policy chunks to framework controls.

Orchestrates the full mapping pipeline:
1. Chunk policy documents
2. Retrieve similar controls via vector search
3. Enrich with LLM-generated rationales and confidence scores
4. Log every AI decision to the append-only trace log
5. Aggregate results into a MappingReport
"""

from __future__ import annotations

import json
from pathlib import Path

from lemma.models.mapping import MappingReport, MappingResult
from lemma.models.trace import AITrace
from lemma.services.chunker import chunk_policies
from lemma.services.config import AutomationConfig
from lemma.services.indexer import ControlIndexer
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.llm import LLMClient
from lemma.services.trace_log import TraceLog

_MAPPING_PROMPT = """\
You are a GRC compliance analyst. Given a policy excerpt and a security control, \
determine how well the policy satisfies the control requirement.

**Policy Excerpt:**
{chunk_text}

**Control ({control_id}): {control_title}**
{control_prose}

Respond ONLY with a JSON object containing:
- "confidence": a float between 0.0 and 1.0 indicating how well the policy maps
- "rationale": a brief explanation of the mapping (1-2 sentences)

Example: {{"confidence": 0.85, "rationale": "The policy directly addresses..."}}
"""


def _get_model_id(llm_client: LLMClient) -> str:
    """Extract model identifier from an LLM client.

    Args:
        llm_client: LLM client instance.

    Returns:
        Model identifier string (e.g., 'ollama/llama3.2').
    """
    model = str(getattr(llm_client, "model", "unknown"))
    # Determine provider from class name
    class_name = type(llm_client).__name__.lower()
    if "ollama" in class_name:
        return f"ollama/{model}"
    if "openai" in class_name:
        return f"openai/{model}"
    return model


def map_policies(
    *,
    framework: str,
    project_dir: Path,
    llm_client: LLMClient,
    threshold: float = 0.6,
    top_k: int = 3,
    output_format: str = "json",
    automation: AutomationConfig | None = None,
) -> MappingReport:
    """Run the full control mapping pipeline.

    Every AI call is automatically logged to the append-only trace log
    at ``<project_dir>/.lemma/traces/``.

    Args:
        framework: Name of the indexed framework to map against.
        project_dir: Root of the Lemma project.
        llm_client: LLM client for rationale generation.
        threshold: Confidence threshold for LOW_CONFIDENCE flagging.
        top_k: Number of candidate controls per chunk.
        output_format: Output format name (for future use).
        automation: Optional confidence-gated automation config. When a
            threshold is configured for the ``map`` operation, outputs
            at or above the threshold are auto-accepted; outputs below
            remain PROPOSED for human review.

    Returns:
        MappingReport with all mapping results.

    Raises:
        ValueError: If framework not indexed or no policies found.
    """
    # Validate framework is indexed
    indexer = ControlIndexer(index_dir=project_dir / ".lemma" / "index")
    stats = indexer.get_collection_stats(framework)
    if stats["count"] == 0:
        msg = f"Framework '{framework}' is not indexed. Run: lemma framework add {framework}"
        raise ValueError(msg)

    # Chunk policies
    policies_dir = project_dir / "policies"
    chunks = chunk_policies(policies_dir)
    if not chunks:
        msg = "No policy documents found in policies/. Add .md files and try again."
        raise ValueError(msg)

    # Initialize trace log
    trace_log = TraceLog(log_dir=project_dir / ".lemma" / "traces")
    model_id = _get_model_id(llm_client)

    # Resolve auto-accept threshold for the map operation (None = no gating)
    auto_accept_threshold = (
        automation.threshold_for("map") if automation is not None else None
    )

    # Map each chunk to controls
    results: list[MappingResult] = []

    for chunk in chunks:
        # Retrieve candidate controls via vector similarity
        candidates = indexer.query_similar(framework, chunk["text"], n_results=top_k)

        for candidate in candidates:
            # Enrich with LLM rationale
            prompt = _MAPPING_PROMPT.format(
                chunk_text=chunk["text"],
                control_id=candidate["control_id"],
                control_title=candidate["title"],
                control_prose=candidate.get("document", ""),
            )

            try:
                raw_response = llm_client.generate(prompt)
                parsed = json.loads(raw_response)
                confidence = float(parsed.get("confidence", 0.0))
                rationale = parsed.get("rationale", "No rationale provided.")
            except (json.JSONDecodeError, KeyError, TypeError):
                confidence = 0.0
                rationale = f"LLM response could not be parsed: {raw_response[:200]}"

            status = "MAPPED" if confidence >= threshold else "LOW_CONFIDENCE"

            # Log trace entry for this AI decision
            proposed_trace = AITrace(
                operation="map",
                input_text=chunk["text"][:500],
                prompt=prompt,
                model_id=model_id,
                model_version="",
                raw_output=raw_response,
                confidence=confidence,
                determination=status,
                control_id=candidate["control_id"],
                framework=framework,
            )
            trace_log.append(proposed_trace)

            # Confidence-gated automation: auto-accept at/above configured threshold.
            if (
                auto_accept_threshold is not None
                and confidence >= auto_accept_threshold
            ):
                trace_log.auto_accept(proposed_trace, threshold=auto_accept_threshold)

            results.append(
                MappingResult(
                    chunk_id=chunk["id"],
                    chunk_text=chunk["text"][:200],
                    control_id=candidate["control_id"],
                    control_title=candidate["title"],
                    confidence=confidence,
                    rationale=rationale,
                    status=status,
                )
            )

    # Populate knowledge graph with mapping results
    graph_path = project_dir / ".lemma" / "graph.json"
    graph = ComplianceGraph.load(graph_path)

    # Track unique policy sources to add as nodes
    seen_policies: set[str] = set()
    for result in results:
        # Extract policy filename from chunk_id (e.g., 'access-control.md#1')
        policy_path = result.chunk_id.split("#")[0]
        if policy_path not in seen_policies:
            graph.add_policy(policy_path, title=policy_path)
            seen_policies.add(policy_path)

        # Only add SATISFIES edges for MAPPED results
        if result.status == "MAPPED":
            graph.add_mapping(
                policy=policy_path,
                framework=framework,
                control_id=result.control_id,
                confidence=result.confidence,
            )

    graph.save(graph_path)

    return MappingReport(
        framework=framework,
        results=results,
        threshold=threshold,
    )
