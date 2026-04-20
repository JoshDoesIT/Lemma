"""OSCAL catalog parser — extracts controls and prose for indexing.

Walks the catalog's group→control→enhancement hierarchy,
flattening all controls into a list of indexable records with
prose text extracted from 'statement' parts.
"""

from __future__ import annotations


def parse_catalog(catalog_data: dict) -> list[dict]:
    """Parse an OSCAL catalog dict into a flat list of control records.

    Each record contains:
        - id: Control identifier (e.g., 'ac-1', 'ac-2(1)')
        - title: Control title
        - prose: Concatenated prose from statement parts
        - family: Parent group title (e.g., 'Access Control')

    Args:
        catalog_data: Raw OSCAL catalog dict (the value under "catalog" key).

    Returns:
        List of control record dicts ready for indexing.
    """
    controls: list[dict] = []

    for group in catalog_data.get("groups", []):
        family_title = group.get("title", "")
        _extract_controls(group.get("controls", []), family_title, controls)

    return controls


def _extract_controls(
    control_list: list[dict],
    family_title: str,
    accumulator: list[dict],
) -> None:
    """Recursively extract controls and their enhancements."""
    for control in control_list:
        prose = _extract_prose(control.get("parts", []))

        accumulator.append(
            {
                "id": control["id"],
                "title": control.get("title", ""),
                "prose": prose,
                "family": family_title,
            }
        )

        # Recurse into nested enhancements (e.g., AC-2(1))
        for enhancement in control.get("controls", []):
            enhancement_prose = _extract_prose(enhancement.get("parts", []))
            accumulator.append(
                {
                    "id": enhancement["id"],
                    "title": enhancement.get("title", ""),
                    "prose": enhancement_prose,
                    "family": family_title,
                }
            )

            # Handle deeply nested enhancements
            _extract_controls(enhancement.get("controls", []), family_title, accumulator)


def _extract_prose(parts: list[dict]) -> str:
    """Extract and concatenate prose text from OSCAL parts.

    Targets 'statement' parts first, falls back to any part with prose.
    Recursively walks nested parts.
    """
    prose_segments: list[str] = []

    for part in parts:
        if part.get("prose"):
            prose_segments.append(part["prose"])

        # Recurse into nested parts
        nested = part.get("parts", [])
        if nested:
            nested_prose = _extract_prose(nested)
            if nested_prose:
                prose_segments.append(nested_prose)

    return " ".join(prose_segments)
