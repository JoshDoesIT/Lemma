"""Tests for the Excel/CSV parser.

Follows TDD: tests written BEFORE the implementation.
"""

from __future__ import annotations

import csv
from pathlib import Path


class TestExcelParser:
    """Tests for Excel/CSV framework ingestion."""

    def test_parse_excel_xlsx_named_columns(self, tmp_path: Path):
        """parse_excel extracts controls from XLSX with named headers."""
        import openpyxl

        from lemma.services.parsers.excel import parse_excel

        # Create a test XLSX with named columns
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Control ID", "Title", "Description", "Family"])
        ws.append(["AC-1", "Access Control Policy", "Define access policies.", "Access Control"])
        ws.append(["AC-2", "Account Management", "Manage system accounts.", "Access Control"])

        xlsx_path = tmp_path / "framework.xlsx"
        wb.save(xlsx_path)

        controls = parse_excel(xlsx_path)

        assert len(controls) == 2
        assert controls[0]["id"] == "AC-1"
        assert controls[0]["title"] == "Access Control Policy"
        assert controls[0]["prose"] == "Define access policies."
        assert controls[0]["family"] == "Access Control"
        assert controls[1]["id"] == "AC-2"

    def test_parse_excel_csv_named_columns(self, tmp_path: Path):
        """parse_excel extracts controls from CSV with named headers."""
        from lemma.services.parsers.excel import parse_excel

        csv_path = tmp_path / "framework.csv"
        with csv_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "title", "prose", "family"])
            writer.writerow(["SC-1", "System Protection", "Protect systems.", "System Comms"])
            writer.writerow(["SC-2", "Application Partitioning", "Separate apps.", "System Comms"])

        controls = parse_excel(csv_path)

        assert len(controls) == 2
        assert controls[0]["id"] == "SC-1"
        assert controls[0]["title"] == "System Protection"
        assert controls[0]["prose"] == "Protect systems."
        assert controls[0]["family"] == "System Comms"

    def test_parse_excel_positional_fallback(self, tmp_path: Path):
        """parse_excel falls back to positional columns when headers don't match."""
        from lemma.services.parsers.excel import parse_excel

        csv_path = tmp_path / "framework.csv"
        with csv_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Col A", "Col B", "Col C", "Col D"])
            writer.writerow(["IR-1", "Incident Response", "Respond to incidents.", "Incident"])

        controls = parse_excel(csv_path)

        assert len(controls) == 1
        assert controls[0]["id"] == "IR-1"
        assert controls[0]["title"] == "Incident Response"
        assert controls[0]["prose"] == "Respond to incidents."
        assert controls[0]["family"] == "Incident"

    def test_parse_excel_empty_rows_skipped(self, tmp_path: Path):
        """parse_excel skips rows where the ID column is empty."""
        from lemma.services.parsers.excel import parse_excel

        csv_path = tmp_path / "framework.csv"
        with csv_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "title", "prose", "family"])
            writer.writerow(["AC-1", "Access Control Policy", "Define access.", "Access Control"])
            writer.writerow(["", "", "", ""])
            writer.writerow(["AC-2", "Account Mgmt", "Manage accounts.", "Access Control"])

        controls = parse_excel(csv_path)

        assert len(controls) == 2

    def test_parse_excel_unsupported_extension(self, tmp_path: Path):
        """parse_excel raises ValueError for unsupported file extensions."""
        import pytest

        from lemma.services.parsers.excel import parse_excel

        bad_file = tmp_path / "framework.txt"
        bad_file.write_text("not a spreadsheet")

        with pytest.raises(ValueError, match=r"[Uu]nsupported"):
            parse_excel(bad_file)
