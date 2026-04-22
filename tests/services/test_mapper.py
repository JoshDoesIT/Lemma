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


class TestMapperTraceIntegration:
    """Tests for automatic trace logging during mapping."""

    def test_map_writes_trace_entries(self, tmp_path):
        """map_policies writes an AITrace entry for each AI call."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "access.md").write_text("# Access Control\n\nAll users must use MFA.\n")

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-7",
                    "title": "Unsuccessful Logon Attempts",
                    "prose": "Enforce lockout after failed logon attempts.",
                    "family": "AC",
                },
            ],
        )

        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.9, "rationale": "MFA maps to logon controls."}
        )

        map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
        )

        # Verify trace entries were written
        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        traces = trace_log.read_all()

        assert len(traces) >= 1
        trace = traces[0]
        assert trace.operation == "map"
        assert trace.model_id != ""
        assert trace.confidence == 0.9
        assert trace.control_id == "ac-7"
        assert trace.framework == "nist-800-53"
        assert trace.status.value == "PROPOSED"

    def test_trace_contains_prompt_and_output(self, tmp_path):
        """Trace entries include the full prompt and raw model output."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "test.md").write_text("# Test Policy\n\nEncrypt all data at rest.\n")

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "test-fw",
            [
                {
                    "id": "sc-28",
                    "title": "Protection of Information at Rest",
                    "prose": "Protect confidentiality of data at rest.",
                    "family": "SC",
                },
            ],
        )

        raw_response = '{"confidence": 0.92, "rationale": "Direct encryption match."}'
        mock_llm = MagicMock()
        mock_llm.generate.return_value = raw_response

        map_policies(
            framework="test-fw",
            project_dir=tmp_path,
            llm_client=mock_llm,
        )

        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        traces = trace_log.read_all()

        assert len(traces) >= 1
        trace = traces[0]
        # Prompt should contain the policy text and control info
        assert "Encrypt all data" in trace.input_text
        assert "sc-28" in trace.prompt.lower() or "SC-28" in trace.prompt
        assert trace.raw_output == raw_response

    def test_trace_records_llm_parse_failure(self, tmp_path):
        """When LLM returns unparseable output, trace still records it."""
        from lemma.services.indexer import ControlIndexer
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "test.md").write_text("# Test\n\nSome policy.\n")

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "test-fw",
            [{"id": "c-1", "title": "C1", "prose": "Test.", "family": "F"}],
        )

        mock_llm = MagicMock()
        mock_llm.generate.return_value = "NOT VALID JSON"

        map_policies(
            framework="test-fw",
            project_dir=tmp_path,
            llm_client=mock_llm,
        )

        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        traces = trace_log.read_all()

        assert len(traces) >= 1
        trace = traces[0]
        assert trace.confidence == 0.0
        assert trace.raw_output == "NOT VALID JSON"


class TestMapperConfidenceGate:
    """Tests for confidence-gated automation in the mapping pipeline."""

    def _setup_project(self, tmp_path):
        from lemma.services.indexer import ControlIndexer

        (tmp_path / ".lemma").mkdir()
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "access.md").write_text(
            "# Access Control\n\nAll users must use MFA to authenticate.\n"
        )

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-7",
                    "title": "Unsuccessful Logon Attempts",
                    "prose": "Enforce lockout after failed logon attempts.",
                    "family": "AC",
                },
            ],
        )

    def test_high_confidence_is_auto_accepted(self, tmp_path):
        from lemma.services.config import AutomationConfig
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        self._setup_project(tmp_path)
        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.92, "rationale": "Strong match."}
        )

        map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
            automation=AutomationConfig(thresholds={"map": 0.85}),
        )

        traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
        # One PROPOSED plus one auto-accepted review per candidate
        accepted = [t for t in traces if t.status.value == "ACCEPTED"]
        assert len(accepted) >= 1
        review = accepted[0]
        assert review.auto_accepted is True
        assert review.parent_trace_id != ""

    def test_below_threshold_remains_proposed(self, tmp_path):
        from lemma.services.config import AutomationConfig
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        self._setup_project(tmp_path)
        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.70, "rationale": "Moderate match."}
        )

        map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
            automation=AutomationConfig(thresholds={"map": 0.95}),
        )

        traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
        accepted = [t for t in traces if t.status.value == "ACCEPTED"]
        proposed = [t for t in traces if t.status.value == "PROPOSED"]
        assert accepted == []
        assert len(proposed) >= 1

    def test_without_automation_config_never_auto_accepts(self, tmp_path):
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        self._setup_project(tmp_path)
        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.99, "rationale": "Very strong."}
        )

        map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
        )

        traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
        assert all(t.status.value == "PROPOSED" for t in traces)

    def test_missing_operation_threshold_never_auto_accepts(self, tmp_path):
        """Thresholds for other operations must not affect 'map'."""
        from lemma.services.config import AutomationConfig
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        self._setup_project(tmp_path)
        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.99, "rationale": "Very strong."}
        )

        map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
            automation=AutomationConfig(thresholds={"harmonize": 0.5}),
        )

        traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
        assert all(t.status.value == "PROPOSED" for t in traces)

    def test_threshold_boundary_auto_accepts(self, tmp_path):
        """Confidence exactly at the threshold auto-accepts (inclusive)."""
        from lemma.services.config import AutomationConfig
        from lemma.services.mapper import map_policies
        from lemma.services.trace_log import TraceLog

        self._setup_project(tmp_path)
        mock_llm = MagicMock()
        mock_llm.generate.return_value = json.dumps(
            {"confidence": 0.8, "rationale": "Exact threshold."}
        )

        map_policies(
            framework="nist-800-53",
            project_dir=tmp_path,
            llm_client=mock_llm,
            threshold=0.5,
            automation=AutomationConfig(thresholds={"map": 0.8}),
        )

        traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
        accepted = [t for t in traces if t.status.value == "ACCEPTED"]
        assert len(accepted) >= 1
        assert accepted[0].auto_accepted is True
