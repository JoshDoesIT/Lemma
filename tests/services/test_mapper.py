"""Tests for the control mapping service.

Follows TDD: tests written BEFORE the implementation.
All LLM calls mocked — no running LLM required for tests.
"""

import json
from unittest.mock import MagicMock

import pytest


class TestRetrieveControls:
    """Tests for vector retrieval from indexed frameworks."""

    def test_query_similar_returns_ranked_results(self, tmp_path):
        """Indexer query returns controls ranked by similarity."""
        from lemma.services.indexer import ControlIndexer

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        controls = [
            {
                "id": "ac-2",
                "title": "Account Management",
                "prose": "Manage system accounts including creating and disabling.",
                "family": "Access Control",
            },
            {
                "id": "sc-28",
                "title": "Protection of Information at Rest",
                "prose": "Protect the confidentiality of information at rest.",
                "family": "System and Communications Protection",
            },
        ]
        indexer.index_controls("test-fw", controls)

        results = indexer.query_similar(
            "test-fw",
            "All data must be encrypted at rest.",
            n_results=2,
        )

        assert len(results) >= 1
        assert all("control_id" in r for r in results)
        assert all("distance" in r for r in results)


class TestMapper:
    """Tests for the mapping pipeline."""

    def test_map_policies_produces_results(self, tmp_path):
        """Full pipeline produces mapping results with mocked LLM."""
        from lemma.models.mapping import MappingReport
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies

        # Setup: init project, add policies, index framework
        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "access.md").write_text(
            "# Access Control\n\nAll users must authenticate via SSO before accessing systems.\n"
        )

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-2",
                    "title": "Account Management",
                    "prose": "Manage system accounts.",
                    "family": "AC",
                },
            ],
        )

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {
                "confidence": 0.85,
                "rationale": "Policy requires SSO which maps to account management.",
            }
        )

        report = map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
        )

        assert isinstance(report, MappingReport)
        assert len(report.results) >= 1
        assert report.framework == "nist-800-53"

    def test_map_flags_low_confidence(self, tmp_path):
        """Results below threshold are flagged LOW_CONFIDENCE."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "vague.md").write_text("# General Policy\n\nWe do security things.\n")

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-1",
                    "title": "Policy and Procedures",
                    "prose": "Develop access control policy.",
                    "family": "AC",
                },
            ],
        )

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {
                "confidence": 0.3,
                "rationale": "Weak semantic match.",
            }
        )

        report = map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.6,
        )

        low_conf = [r for r in report.results if r.status == "LOW_CONFIDENCE"]
        assert len(low_conf) >= 1

    def test_map_no_framework_errors(self, tmp_path):
        """Mapping without an indexed framework raises an error."""
        from lemma.services.mapper import map_policies

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "test.md").write_text("# Test\n\nTest policy.\n")

        mock_llm = MagicMock()

        with pytest.raises(ValueError, match="not indexed"):
            map_policies(
                framework="nonexistent-fw",
                project_dir=tmp_path,
                llm_client=mock_llm,
            )

    def test_map_no_policies_errors(self, tmp_path):
        """Mapping without policy files raises an error."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        # Empty policies dir — but framework IS indexed

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-1",
                    "title": "Policy",
                    "prose": "Test.",
                    "family": "AC",
                },
            ],
        )

        mock_llm = MagicMock()

        with pytest.raises(ValueError, match=r"[Nn]o polic"):
            map_policies(
                framework="nist-800-53",
                project_dir=tmp_path,
                llm_client=mock_llm,
            )
