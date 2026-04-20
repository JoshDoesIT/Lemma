"""Control mapping engine — maps policy chunks to framework controls.

Orchestrates the full mapping pipeline:
1. Chunk policy documents
2. Retrieve similar controls via vector search
3. Enrich with LLM-generated rationales and confidence scores
4. Aggregate results into a MappingReport
"""

from __future__ import annotations

import json
from pathlib import Path

from lemma.models.mapping import MappingReport, MappingResult
from lemma.services.chunker import chunk_policies
from lemma.services.indexer import ControlIndexer
from lemma.services.llm import LLMClient

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


def map_policies(
    *,
    framework: str,
    project_dir: Path,
    llm_client: LLMClient,
    threshold: float = 0.6,
    top_k: int = 3,
    output_format: str = "json",
) -> MappingReport:
    """Run the full control mapping pipeline.

    Args:
        framework: Name of the indexed framework to map against.
        project_dir: Root of the Lemma project.
        llm_client: LLM client for rationale generation.
        threshold: Confidence threshold for LOW_CONFIDENCE flagging.
        top_k: Number of candidate controls per chunk.
        output_format: Output format name (for future use).

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

    return MappingReport(
        framework=framework,
        results=results,
        threshold=threshold,
    )
