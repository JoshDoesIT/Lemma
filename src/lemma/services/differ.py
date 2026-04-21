"""Framework version differ.

Compares control IDs and text between two indexed framework versions
to identify added, removed, and modified controls.
"""

from __future__ import annotations

from lemma.models.harmonization import DiffResult
from lemma.services.indexer import ControlIndexer


def diff_frameworks(
    indexer: ControlIndexer,
    from_name: str,
    to_name: str,
) -> DiffResult:
    """Compare two indexed framework versions.

    Args:
        indexer: ControlIndexer with both frameworks indexed.
        from_name: Source framework collection name.
        to_name: Target framework collection name.

    Returns:
        DiffResult with added, removed, and modified control lists.
    """
    from_data = indexer.get_all_controls(from_name)
    to_data = indexer.get_all_controls(to_name)

    # Build ID → document maps
    from_docs = dict(zip(from_data["ids"], from_data["documents"], strict=True))
    to_docs = dict(zip(to_data["ids"], to_data["documents"], strict=True))

    from_ids = set(from_docs.keys())
    to_ids = set(to_docs.keys())

    added = sorted(to_ids - from_ids)
    removed = sorted(from_ids - to_ids)

    # Modified: same ID, different text
    modified = []
    for control_id in sorted(from_ids & to_ids):
        if from_docs[control_id] != to_docs[control_id]:
            modified.append(
                {
                    "control_id": control_id,
                    "change_summary": "Control text changed",
                }
            )

    return DiffResult(
        from_framework=from_name,
        to_framework=to_name,
        added=added,
        removed=removed,
        modified=modified,
    )
