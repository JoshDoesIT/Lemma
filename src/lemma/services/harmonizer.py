"""Harmonization engine — cross-framework control clustering.

Implements single-linkage clustering using Union-Find to identify
semantically equivalent controls across indexed frameworks,
enabling 'Test Once, Comply Many'.
"""

from __future__ import annotations

import numpy as np

from lemma.models.harmonization import (
    CommonControl,
    HarmonizationReport,
    SourceControl,
)
from lemma.services.indexer import ControlIndexer
from lemma.services.union_find import UnionFind


def harmonize_frameworks(
    *,
    indexer: ControlIndexer,
    threshold: float = 0.85,
) -> HarmonizationReport:
    """Harmonize all indexed frameworks via semantic clustering.

    Steps:
    1. Extract all control embeddings from each framework.
    2. Compute pairwise cosine similarity across frameworks.
    3. Single-linkage clustering via Union-Find (threshold-gated).
    4. Build CommonControl clusters with deterministic ordering.

    Args:
        indexer: ControlIndexer with indexed frameworks.
        threshold: Cosine similarity threshold for merging (0.0-1.0).

    Returns:
        HarmonizationReport with clusters and metadata.

    Raises:
        ValueError: If no frameworks are indexed.
    """
    framework_names = indexer.list_indexed_frameworks()
    if not framework_names:
        msg = "No frameworks indexed. Run: lemma framework add <name>"
        raise ValueError(msg)

    # Step 1: Extract all controls with embeddings
    all_controls: dict[str, dict] = {}  # key → {framework, id, title, doc, embedding}
    for fw in sorted(framework_names):
        data = indexer.get_all_controls(fw)
        embeddings = data.get("embeddings")
        has_embeddings = embeddings is not None and len(embeddings) > 0
        for i, control_id in enumerate(data["ids"]):
            key = f"{fw}:{control_id}"
            metadatas = data.get("metadatas")
            documents = data.get("documents")
            all_controls[key] = {
                "framework": fw,
                "control_id": control_id,
                "title": metadatas[i].get("title", "") if metadatas else "",
                "document": documents[i] if documents else "",
                "embedding": (
                    np.array(embeddings[i]) if has_embeddings and i < len(embeddings) else None
                ),
            }

    # Step 2: Pairwise cosine similarity across different frameworks
    uf = UnionFind()
    keys = sorted(all_controls.keys())

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            ctrl_a = all_controls[keys[i]]
            ctrl_b = all_controls[keys[j]]

            # Only compare across different frameworks
            if ctrl_a["framework"] == ctrl_b["framework"]:
                continue

            emb_a = ctrl_a["embedding"]
            emb_b = ctrl_b["embedding"]
            if emb_a is None or emb_b is None:
                continue

            similarity = _cosine_similarity(emb_a, emb_b)
            if similarity >= threshold:
                uf.union(keys[i], keys[j])

    # Step 3: Build clusters
    groups = uf.clusters(keys)

    clusters = []
    for cluster_id_key in sorted(groups.keys()):
        members = sorted(groups[cluster_id_key])
        controls = []
        longest_doc = ""

        for member_key in members:
            ctrl = all_controls[member_key]
            controls.append(
                SourceControl(
                    framework=ctrl["framework"],
                    control_id=ctrl["control_id"],
                    title=ctrl["title"],
                    similarity=1.0,  # Will be refined in future
                )
            )
            if len(ctrl["document"]) > len(longest_doc):
                longest_doc = ctrl["document"]

        # Deterministic label: first control's title
        primary_label = controls[0].title if controls else "Unknown"

        clusters.append(
            CommonControl(
                cluster_id=cluster_id_key,
                controls=controls,
                primary_label=primary_label,
                primary_description=longest_doc,
            )
        )

    return HarmonizationReport(
        frameworks=sorted(framework_names),
        clusters=clusters,
        threshold=threshold,
    )


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors.

    Args:
        a: First vector.
        b: Second vector.

    Returns:
        Cosine similarity in range [-1.0, 1.0].
    """
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))
