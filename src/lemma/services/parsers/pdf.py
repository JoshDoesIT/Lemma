"""PDF parser — extracts framework controls from PDF documents via Docling.

Uses IBM's Docling library for layout-aware document intelligence,
extracting sections/headings as control boundaries and paragraphs
as control prose.

Requires the [ingest] optional extras:
    pip install lemma-grc[ingest]
"""

from __future__ import annotations

from pathlib import Path


def _get_converter():
    """Create a Docling DocumentConverter.

    Raises:
        ImportError: If Docling is not installed.
    """
    try:
        from docling.document_converter import DocumentConverter
    except ImportError as e:
        msg = "PDF import requires the [ingest] extras. Install with: pip install lemma-grc[ingest]"
        raise ImportError(msg) from e

    return DocumentConverter()


def parse_pdf(file_path: Path) -> list[dict]:
    """Parse a PDF file into a flat list of control records.

    Walks the Docling document hierarchy, treating section headers
    as control boundaries and subsequent paragraphs/tables as prose.

    Each record contains:
        - id: Generated from section index (e.g., 'ctrl-1', 'ctrl-2')
        - title: Section heading text
        - prose: Concatenated paragraph and table text
        - family: Top-level section heading (if nested)

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of control record dicts ready for indexing.

    Raises:
        ImportError: If Docling is not installed.
    """
    converter = _get_converter()
    result = converter.convert(str(file_path))
    doc = result.document

    controls: list[dict] = []
    current_title = ""
    current_family = ""
    current_prose_parts: list[str] = []
    control_index = 0

    def _flush_control() -> None:
        nonlocal control_index
        if current_title and current_prose_parts:
            control_index += 1
            controls.append(
                {
                    "id": f"ctrl-{control_index}",
                    "title": current_title,
                    "prose": " ".join(current_prose_parts),
                    "family": current_family or current_title,
                }
            )

    for item in doc.iterate_items():
        label = getattr(item, "label", "")
        text = getattr(item, "text", "")

        if not text or not text.strip():
            continue

        if label in {"section_header", "title", "heading"}:
            # Flush the previous control before starting a new one
            _flush_control()

            level = getattr(item, "level", 1)
            if level <= 1:
                current_family = text.strip()

            current_title = text.strip()
            current_prose_parts = []
        elif label in {"paragraph", "text", "list_item", "table"}:
            current_prose_parts.append(text.strip())

    # Flush the last accumulated control
    _flush_control()

    return controls
