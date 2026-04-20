"""Tests for the mapping Pydantic models.

Follows TDD: tests written BEFORE the implementation.
"""


class TestMappingModels:
    """Tests for mapping result and report models."""

    def test_mapping_result_creation(self):
        """MappingResult holds chunk, control, confidence, rationale, status."""
        from lemma.models.mapping import MappingResult

        result = MappingResult(
            chunk_id="access-control.md#1",
            chunk_text="All users must authenticate via SSO.",
            control_id="ac-2",
            control_title="Account Management",
            confidence=0.87,
            rationale="Policy requires SSO, which maps to account management.",
            status="MAPPED",
        )

        assert result.chunk_id == "access-control.md#1"
        assert result.control_id == "ac-2"
        assert result.confidence == 0.87
        assert result.status == "MAPPED"

    def test_mapping_result_low_confidence_status(self):
        """MappingResult can have LOW_CONFIDENCE status."""
        from lemma.models.mapping import MappingResult

        result = MappingResult(
            chunk_id="policy.md#2",
            chunk_text="We do things.",
            control_id="ac-1",
            control_title="Policy and Procedures",
            confidence=0.3,
            rationale="Weak semantic match.",
            status="LOW_CONFIDENCE",
        )

        assert result.status == "LOW_CONFIDENCE"

    def test_mapping_report_creation(self):
        """MappingReport aggregates results with metadata."""
        from lemma.models.mapping import MappingReport, MappingResult

        results = [
            MappingResult(
                chunk_id="p.md#1",
                chunk_text="Encrypt data at rest.",
                control_id="sc-28",
                control_title="Protection of Information at Rest",
                confidence=0.92,
                rationale="Direct encryption requirement.",
                status="MAPPED",
            ),
        ]

        report = MappingReport(
            framework="nist-800-53",
            results=results,
            threshold=0.6,
        )

        assert report.framework == "nist-800-53"
        assert len(report.results) == 1
        assert report.threshold == 0.6
        assert report.mapped_count == 1
        assert report.low_confidence_count == 0
