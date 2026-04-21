"""Tests for the PDF parser (Docling integration).

Follows TDD: tests written BEFORE the implementation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


class TestPdfParser:
    """Tests for PDF framework ingestion via Docling."""

    def test_parse_pdf_returns_controls(self, tmp_path: Path):
        """parse_pdf returns a list of control dicts from a PDF file."""
        mock_heading = MagicMock()
        mock_heading.label = "section_header"
        mock_heading.text = "AC-1 Access Control Policy"
        mock_heading.level = 2

        mock_paragraph = MagicMock()
        mock_paragraph.label = "paragraph"
        mock_paragraph.text = (
            "Organizations must define access control policies "
            "that restrict system access to authorized users."
        )

        mock_table = MagicMock()
        mock_table.label = "table"
        mock_table.text = "Control: AC-1 | Family: Access Control"

        # Build the mock document with iterate_items
        mock_doc = MagicMock()
        mock_doc.iterate_items.return_value = [
            mock_heading,
            mock_paragraph,
            mock_table,
        ]

        # Build the mock conversion result
        mock_result = MagicMock()
        mock_result.document = mock_doc

        mock_converter = MagicMock()
        mock_converter.convert.return_value = mock_result

        with patch(
            "lemma.services.parsers.pdf._get_converter",
            return_value=mock_converter,
        ):
            from lemma.services.parsers.pdf import parse_pdf

            dummy_pdf = tmp_path / "test.pdf"
            dummy_pdf.write_bytes(b"%PDF-1.4 dummy")

            controls = parse_pdf(dummy_pdf)

        assert isinstance(controls, list)
        assert len(controls) == 1

        control = controls[0]
        assert control["id"] == "ctrl-1"
        assert control["title"] == "AC-1 Access Control Policy"
        assert "access control policies" in control["prose"]
        assert "family" in control

    def test_parse_pdf_multiple_sections(self, tmp_path: Path):
        """parse_pdf handles multiple section headings correctly."""
        items = []
        for _section_id, title, prose in [
            ("AC-1", "AC-1 Access Control Policy", "Define access policies."),
            ("AC-2", "AC-2 Account Management", "Manage system accounts."),
        ]:
            heading = MagicMock()
            heading.label = "section_header"
            heading.text = title
            heading.level = 2

            paragraph = MagicMock()
            paragraph.label = "paragraph"
            paragraph.text = prose

            items.extend([heading, paragraph])

        mock_doc = MagicMock()
        mock_doc.iterate_items.return_value = items

        mock_result = MagicMock()
        mock_result.document = mock_doc

        mock_converter = MagicMock()
        mock_converter.convert.return_value = mock_result

        with patch(
            "lemma.services.parsers.pdf._get_converter",
            return_value=mock_converter,
        ):
            from lemma.services.parsers.pdf import parse_pdf

            dummy_pdf = tmp_path / "test.pdf"
            dummy_pdf.write_bytes(b"%PDF-1.4 dummy")

            controls = parse_pdf(dummy_pdf)

        assert len(controls) == 2
        assert controls[0]["title"] == "AC-1 Access Control Policy"
        assert controls[1]["title"] == "AC-2 Account Management"

    def test_parse_pdf_import_error_without_docling(self, tmp_path: Path):
        """parse_pdf raises ImportError with helpful message when Docling is missing."""

        with patch(
            "lemma.services.parsers.pdf._get_converter",
            side_effect=ImportError(
                "PDF import requires the [ingest] extras. "
                "Install with: pip install lemma-grc[ingest]"
            ),
        ):
            from lemma.services.parsers.pdf import parse_pdf

            dummy_pdf = tmp_path / "test.pdf"
            dummy_pdf.write_bytes(b"%PDF-1.4 dummy")

            try:
                parse_pdf(dummy_pdf)
                msg = "Expected ImportError"
                raise AssertionError(msg)
            except ImportError as e:
                assert "ingest" in str(e).lower()
