"""Mapping domain models — structured output types for control mapping.

Defines the data structures for mapping results, including
individual chunk-to-control mappings and aggregated reports.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field


class MappingResult(BaseModel):
    """A single chunk-to-control mapping result.

    Attributes:
        chunk_id: Source policy chunk identifier (e.g., 'access-control.md#1').
        chunk_text: The policy text that was mapped.
        control_id: Target framework control identifier (e.g., 'ac-2').
        control_title: Human-readable control title.
        confidence: AI-generated confidence score (0.0-1.0).
        rationale: AI-generated explanation of the mapping.
        status: MAPPED, LOW_CONFIDENCE, or UNMAPPED.
    """

    chunk_id: str
    chunk_text: str
    control_id: str
    control_title: str
    confidence: float
    rationale: str
    status: str


class MappingReport(BaseModel):
    """Aggregated mapping report with metadata.

    Attributes:
        framework: Framework name that was mapped against.
        results: List of individual mapping results.
        threshold: Confidence threshold used for flagging.
    """

    framework: str
    results: list[MappingResult] = Field(default_factory=list)
    threshold: float = 0.6

    @computed_field
    @property
    def mapped_count(self) -> int:
        """Number of results with MAPPED status."""
        return sum(1 for r in self.results if r.status == "MAPPED")

    @computed_field
    @property
    def low_confidence_count(self) -> int:
        """Number of results with LOW_CONFIDENCE status."""
        return sum(1 for r in self.results if r.status == "LOW_CONFIDENCE")

    @computed_field
    @property
    def total_count(self) -> int:
        """Total number of mapping results."""
        return len(self.results)
