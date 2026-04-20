"""Harmonization domain models — structured output types for cross-framework analysis.

Defines the data structures for harmonization results, including
common controls, coverage reports, gap analysis, and framework diffs.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field


class SourceControl(BaseModel):
    """A reference to a framework-specific control within a cluster.

    Attributes:
        framework: Framework name (e.g., 'nist-800-53').
        control_id: Control identifier within the framework.
        title: Human-readable control title.
        similarity: Cosine similarity score to the cluster head (1.0 = identical).
    """

    framework: str
    control_id: str
    title: str
    similarity: float


class CommonControl(BaseModel):
    """A cluster of semantically equivalent controls from multiple frameworks.

    Attributes:
        cluster_id: Unique identifier for this cluster.
        controls: All source controls grouped in this cluster.
        primary_label: Human-readable label from the cluster head.
        primary_description: Longest prose from any member control.
    """

    cluster_id: str
    controls: list[SourceControl]
    primary_label: str
    primary_description: str

    @computed_field
    @property
    def frameworks(self) -> list[str]:
        """List of unique frameworks represented in this cluster."""
        return sorted({c.framework for c in self.controls})


class HarmonizationReport(BaseModel):
    """Aggregated harmonization report with computed statistics.

    Attributes:
        frameworks: List of framework names that were harmonized.
        clusters: List of common control clusters.
        threshold: Cosine similarity threshold used for clustering.
    """

    frameworks: list[str]
    clusters: list[CommonControl] = Field(default_factory=list)
    threshold: float = 0.85

    @computed_field
    @property
    def cluster_count(self) -> int:
        """Total number of clusters."""
        return len(self.clusters)

    @computed_field
    @property
    def total_controls(self) -> int:
        """Total number of controls across all clusters."""
        return sum(len(c.controls) for c in self.clusters)


class CoverageReport(BaseModel):
    """Per-framework coverage percentages.

    Attributes:
        frameworks: Dict mapping framework name to coverage percentage (0.0-1.0).
    """

    frameworks: dict[str, float]


class GapReport(BaseModel):
    """Controls with no cross-framework match for a specific framework.

    Attributes:
        framework: Framework name being analyzed.
        unmapped_controls: List of controls that are isolated singletons.
        total_controls: Total number of controls from this framework.
    """

    framework: str
    unmapped_controls: list[dict]
    total_controls: int

    @computed_field
    @property
    def gap_percentage(self) -> float:
        """Percentage of controls that are unmapped."""
        if self.total_controls == 0:
            return 0.0
        return (len(self.unmapped_controls) / self.total_controls) * 100


class DiffResult(BaseModel):
    """Changes between two versions of a framework.

    Attributes:
        from_framework: Source framework name/version.
        to_framework: Target framework name/version.
        added: Control IDs present in target but not source.
        removed: Control IDs present in source but not target.
        modified: Controls with same ID but changed content.
    """

    from_framework: str
    to_framework: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    modified: list[dict] = Field(default_factory=list)
