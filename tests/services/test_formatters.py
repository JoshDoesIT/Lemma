"""Tests for output formatters.

Follows TDD: tests written BEFORE the implementation.
"""

import json

import pytest


class TestFormatters:
    """Tests for mapping output format registry."""

    def test_format_json(self):
        """JSON formatter produces valid JSON string."""
        from lemma.models.mapping import MappingReport, MappingResult
        from lemma.services.formatters import format_json

        report = MappingReport(
            framework="nist-800-53",
            results=[
                MappingResult(
                    chunk_id="p.md#1",
                    chunk_text="Encrypt data.",
                    control_id="sc-28",
                    control_title="Protection of Information at Rest",
                    confidence=0.9,
                    rationale="Direct match.",
                    status="MAPPED",
                ),
            ],
            threshold=0.6,
        )

        output = format_json(report)
        parsed = json.loads(output)

        assert parsed["framework"] == "nist-800-53"
        assert len(parsed["results"]) == 1
        assert parsed["results"][0]["control_id"] == "sc-28"

    def test_format_oscal(self):
        """OSCAL formatter produces valid Assessment Results structure."""
        from lemma.models.mapping import MappingReport, MappingResult
        from lemma.services.formatters import format_oscal

        report = MappingReport(
            framework="nist-800-53",
            results=[
                MappingResult(
                    chunk_id="p.md#1",
                    chunk_text="Encrypt data.",
                    control_id="sc-28",
                    control_title="Protection of Information at Rest",
                    confidence=0.9,
                    rationale="Direct match.",
                    status="MAPPED",
                ),
            ],
            threshold=0.6,
        )

        output = format_oscal(report)
        parsed = json.loads(output)

        # OSCAL Assessment Results structure
        assert "assessment-results" in parsed
        ar = parsed["assessment-results"]
        assert "uuid" in ar
        assert "metadata" in ar
        assert "results" in ar

    def test_get_formatter_json(self):
        """Registry returns JSON formatter for 'json' key."""
        from lemma.services.formatters import get_formatter

        formatter = get_formatter("json")
        assert callable(formatter)

    def test_get_formatter_oscal(self):
        """Registry returns OSCAL formatter for 'oscal' key."""
        from lemma.services.formatters import get_formatter

        formatter = get_formatter("oscal")
        assert callable(formatter)

    def test_get_formatter_unknown_errors(self):
        """Unknown format name raises ValueError."""
        from lemma.services.formatters import get_formatter

        with pytest.raises(ValueError, match=r"[Uu]nsupported"):
            get_formatter("xml")

    def test_format_csv(self):
        """CSV formatter produces valid CSV mapping."""
        import csv
        import io

        from lemma.models.mapping import MappingReport, MappingResult
        from lemma.services.formatters import format_csv

        report = MappingReport(
            framework="nist-800-53",
            results=[
                MappingResult(
                    chunk_id="policy.md#1",
                    chunk_text="Encrypt data.",
                    control_id="sc-28",
                    control_title="Protection of Information at Rest",
                    confidence=0.9,
                    rationale="Direct match.",
                    status="MAPPED",
                ),
            ],
            threshold=0.6,
        )

        output = format_csv(report)
        lines = output.strip().split("\n")
        assert len(lines) == 2  # header + 1 row

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        header = rows[0]
        assert header == [
            "Chunk ID",
            "Control ID",
            "Control Title",
            "Confidence",
            "Status",
            "Rationale",
        ]

        data = rows[1]
        assert data[0] == "policy.md#1"
        assert data[1] == "sc-28"
        assert data[3] == "0.9"

    def test_format_html(self):
        """HTML formatter produces a styled HTML document."""
        from lemma.models.mapping import MappingReport, MappingResult
        from lemma.services.formatters import format_html

        report = MappingReport(
            framework="nist-800-53",
            results=[
                MappingResult(
                    chunk_id="policy.md#1",
                    chunk_text="Encrypt data.",
                    control_id="sc-28",
                    control_title="Protection of Information at Rest",
                    confidence=0.9,
                    rationale="Direct match.",
                    status="MAPPED",
                ),
            ],
            threshold=0.6,
        )

        output = format_html(report)

        assert "<html>" in output.lower()
        assert "<table>" in output.lower()
        assert "policy.md#1" in output
        assert "sc-28" in output
        assert "Protection of Information at Rest" in output

    def test_get_formatter_csv(self):
        """Registry returns CSV formatter."""
        from lemma.services.formatters import get_formatter

        formatter = get_formatter("csv")
        assert callable(formatter)

    def test_get_formatter_html(self):
        """Registry returns HTML formatter."""
        from lemma.services.formatters import get_formatter

        formatter = get_formatter("html")
        assert callable(formatter)
