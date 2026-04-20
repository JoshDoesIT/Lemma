"""Policy document chunker — splits markdown into semantic chunks.

Reads markdown files from a policies directory and splits them
into sentence-aware chunks with source tracking for downstream
vector embedding and mapping.
"""

from __future__ import annotations

import re
from pathlib import Path


def chunk_policies(policies_dir: Path, max_chunk_size: int = 500) -> list[dict]:
    """Split all markdown policy files into semantic chunks.

    Args:
        policies_dir: Path to the policies directory.
        max_chunk_size: Maximum characters per chunk.

    Returns:
        List of chunk dicts with 'id', 'source', and 'text' keys.
    """
    chunks: list[dict] = []

    md_files = sorted(policies_dir.glob("*.md"))
    for md_file in md_files:
        content = md_file.read_text().strip()
        if not content:
            continue

        file_chunks = _split_into_chunks(content, max_chunk_size)
        for i, text in enumerate(file_chunks):
            chunks.append(
                {
                    "id": f"{md_file.name}#{i + 1}",
                    "source": md_file.name,
                    "text": text,
                }
            )

    return chunks


def _split_into_chunks(text: str, max_size: int) -> list[str]:
    """Split text into sentence-aware chunks.

    Splits on section boundaries (## headings) first, then
    further splits long sections at sentence boundaries.
    """
    # Split on markdown headings to get logical sections
    sections = re.split(r"\n(?=##?\s)", text)
    chunks: list[str] = []

    for section in sections:
        section = section.strip()
        if not section:
            continue

        # Remove heading-only sections with no body
        lines = section.split("\n", 1)
        if len(lines) == 1 and lines[0].startswith("#"):
            continue

        if len(section) <= max_size:
            chunks.append(section)
        else:
            # Split long sections at sentence boundaries
            chunks.extend(_split_at_sentences(section, max_size))

    return chunks


def _split_at_sentences(text: str, max_size: int) -> list[str]:
    """Split text at sentence boundaries, keeping chunks under max_size."""
    # Split on sentence-terminal punctuation followed by space
    sentences = re.split(r"(?<=[.!?:])\s+", text)
    current_chunk: list[str] = []
    current_size = 0
    result: list[str] = []

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue

        if current_size + len(sentence) > max_size and current_chunk:
            result.append(" ".join(current_chunk))
            current_chunk = []
            current_size = 0

        current_chunk.append(sentence)
        current_size += len(sentence)

    if current_chunk:
        result.append(" ".join(current_chunk))

    return result
