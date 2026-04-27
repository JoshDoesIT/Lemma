"""Tests for the AI trace log — append-only audit trail for AI decisions.

Follows TDD: tests written BEFORE the implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lemma.models.trace import AITrace, TraceStatus
from lemma.services.trace_log import TraceLog


class TestAITraceModel:
    """Tests for the AITrace Pydantic model."""

    def test_trace_has_required_fields(self):
        """AITrace model has all required schema fields."""
        trace = AITrace(
            operation="map",
            input_text="MFA is required for all users",
            prompt="You are a GRC compliance analyst...",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output='{"confidence": 0.85, "rationale": "..."}',
            confidence=0.85,
            determination="MAPPED",
            control_id="ac-7",
            framework="nist-800-53",
        )

        assert trace.operation == "map"
        assert trace.model_id == "ollama/llama3.2"
        assert trace.confidence == 0.85
        assert trace.determination == "MAPPED"
        assert trace.timestamp is not None

    def test_trace_defaults_to_proposed_status(self):
        """Traces default to PROPOSED review status."""
        trace = AITrace(
            operation="map",
            input_text="test",
            prompt="test",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output="test",
            confidence=0.5,
            determination="LOW_CONFIDENCE",
            control_id="ac-1",
            framework="nist-800-53",
        )

        assert trace.status == TraceStatus.PROPOSED

    def test_pair_event_fields_default_empty_and_round_trip(self):
        """AITrace carries optional related_* fields for pair events like harmonize."""
        trace = AITrace(
            operation="harmonize",
            input_text="",
            prompt="",
            model_id="sentence-transformers/all-MiniLM-L6-v2",
            model_version="",
            raw_output="",
            confidence=0.92,
            determination="HARMONIZED",
            control_id="ac-7",
            framework="nist-800-53",
            related_control_id="pr.aa-07",
            related_framework="nist-csf-2.0",
        )

        assert trace.related_control_id == "pr.aa-07"
        assert trace.related_framework == "nist-csf-2.0"

        data = json.loads(trace.model_dump_json())
        assert data["related_control_id"] == "pr.aa-07"
        assert data["related_framework"] == "nist-csf-2.0"

    def test_pair_event_fields_default_to_empty_strings(self):
        """Map traces (non-pair) default related_* fields to empty strings."""
        trace = AITrace(
            operation="map",
            input_text="text",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.8,
            determination="MAPPED",
            control_id="c-1",
            framework="fw",
        )
        assert trace.related_control_id == ""
        assert trace.related_framework == ""

    def test_trace_serializes_to_json(self):
        """AITrace can be serialized to JSON."""
        trace = AITrace(
            operation="map",
            input_text="test input",
            prompt="test prompt",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output='{"confidence": 0.9}',
            confidence=0.9,
            determination="MAPPED",
            control_id="ac-1",
            framework="nist-800-53",
        )

        data = json.loads(trace.model_dump_json())
        assert data["operation"] == "map"
        assert data["model_id"] == "ollama/llama3.2"
        assert "timestamp" in data
        assert "trace_id" in data


class TestTraceLog:
    """Tests for the append-only trace log."""

    def test_append_writes_trace_to_file(self, tmp_path: Path):
        """append() writes a trace entry as a JSON line."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        trace = AITrace(
            operation="map",
            input_text="test",
            prompt="test prompt",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output="output",
            confidence=0.8,
            determination="MAPPED",
            control_id="ac-1",
            framework="nist-800-53",
        )

        log.append(trace)

        log_files = list((tmp_path / ".lemma" / "traces").glob("*.jsonl"))
        assert len(log_files) == 1
        lines = log_files[0].read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["operation"] == "map"

    def test_append_is_additive(self, tmp_path: Path):
        """Multiple appends add lines without overwriting."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        for i in range(3):
            trace = AITrace(
                operation="map",
                input_text=f"policy {i}",
                prompt="prompt",
                model_id="ollama/llama3.2",
                model_version="3.2",
                raw_output="output",
                confidence=0.5 + i * 0.1,
                determination="MAPPED",
                control_id=f"ac-{i}",
                framework="nist-800-53",
            )
            log.append(trace)

        log_files = list((tmp_path / ".lemma" / "traces").glob("*.jsonl"))
        lines = log_files[0].read_text().strip().splitlines()
        assert len(lines) == 3

    def test_read_all_returns_all_traces(self, tmp_path: Path):
        """read_all() returns all trace entries from the log."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        for i in range(2):
            trace = AITrace(
                operation="map",
                input_text=f"text {i}",
                prompt="prompt",
                model_id="ollama/llama3.2",
                model_version="3.2",
                raw_output="out",
                confidence=0.7,
                determination="MAPPED",
                control_id=f"c-{i}",
                framework="fw",
            )
            log.append(trace)

        all_traces = log.read_all()
        assert len(all_traces) == 2
        assert all(isinstance(t, AITrace) for t in all_traces)

    def test_filter_by_model(self, tmp_path: Path):
        """filter_by_model() returns only traces from a specific model."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        log.append(
            AITrace(
                operation="map",
                input_text="a",
                prompt="p",
                model_id="ollama/llama3.2",
                model_version="3.2",
                raw_output="o",
                confidence=0.8,
                determination="MAPPED",
                control_id="c-1",
                framework="fw",
            )
        )
        log.append(
            AITrace(
                operation="map",
                input_text="b",
                prompt="p",
                model_id="openai/gpt-4o-mini",
                model_version="2024-07-18",
                raw_output="o",
                confidence=0.9,
                determination="MAPPED",
                control_id="c-2",
                framework="fw",
            )
        )

        ollama_traces = log.filter_by_model("ollama/llama3.2")
        assert len(ollama_traces) == 1
        assert ollama_traces[0].model_id == "ollama/llama3.2"

    def test_filter_by_operation(self, tmp_path: Path):
        """filter_by_operation() returns only traces of a specific type."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        log.append(
            AITrace(
                operation="map",
                input_text="a",
                prompt="p",
                model_id="m",
                model_version="1",
                raw_output="o",
                confidence=0.8,
                determination="MAPPED",
                control_id="c-1",
                framework="fw",
            )
        )
        log.append(
            AITrace(
                operation="evaluate",
                input_text="b",
                prompt="p",
                model_id="m",
                model_version="1",
                raw_output="o",
                confidence=0.9,
                determination="PASS",
                control_id="c-2",
                framework="fw",
            )
        )

        map_traces = log.filter_by_operation("map")
        assert len(map_traces) == 1
        assert map_traces[0].operation == "map"

    def test_trace_log_is_immutable(self, tmp_path: Path):
        """Existing trace entries cannot be modified via the TraceLog API."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        trace = AITrace(
            operation="map",
            input_text="original",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.8,
            determination="MAPPED",
            control_id="c-1",
            framework="fw",
        )
        log.append(trace)

        # TraceLog has no update/delete methods
        assert not hasattr(log, "update")
        assert not hasattr(log, "delete")
        assert not hasattr(log, "clear")

    def test_review_trace_transitions_status(self, tmp_path: Path):
        """review() appends a new trace entry with updated status."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        trace = AITrace(
            operation="map",
            input_text="text",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.9,
            determination="MAPPED",
            control_id="c-1",
            framework="fw",
        )
        log.append(trace)

        log.review(trace.trace_id, status=TraceStatus.ACCEPTED)

        all_traces = log.read_all()
        # Original + review entry
        assert len(all_traces) == 2
        review_entry = all_traces[-1]
        assert review_entry.status == TraceStatus.ACCEPTED

    def test_review_rejected_requires_rationale(self, tmp_path: Path):
        """Rejecting a trace without a rationale raises ValueError."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        trace = AITrace(
            operation="map",
            input_text="text",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.5,
            determination="LOW_CONFIDENCE",
            control_id="c-1",
            framework="fw",
        )
        log.append(trace)

        with pytest.raises(ValueError, match=r"[Rr]ationale"):
            log.review(trace.trace_id, status=TraceStatus.REJECTED)

    def test_review_rejected_with_rationale_succeeds(self, tmp_path: Path):
        """Rejecting a trace with a rationale succeeds."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        trace = AITrace(
            operation="map",
            input_text="text",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.5,
            determination="LOW_CONFIDENCE",
            control_id="c-1",
            framework="fw",
        )
        log.append(trace)

        log.review(
            trace.trace_id,
            status=TraceStatus.REJECTED,
            rationale="Control is not relevant to this policy scope.",
        )

        all_traces = log.read_all()
        rejection = all_traces[-1]
        assert rejection.status == TraceStatus.REJECTED
        assert "not relevant" in rejection.review_rationale


class TestAutoAccept:
    """Tests for confidence-gated automatic acceptance."""

    def _proposed(self, confidence: float = 0.9) -> AITrace:
        return AITrace(
            operation="map",
            input_text="text",
            prompt="p",
            model_id="ollama/llama3.2",
            model_version="3.2",
            raw_output="o",
            confidence=confidence,
            determination="MAPPED",
            control_id="ac-1",
            framework="nist-800-53",
        )

    def test_auto_accept_appends_accepted_review_entry(self, tmp_path: Path):
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        original = self._proposed(confidence=0.92)
        log.append(original)

        log.auto_accept(original, threshold=0.85)

        all_traces = log.read_all()
        assert len(all_traces) == 2
        review = all_traces[-1]
        assert review.status == TraceStatus.ACCEPTED
        assert review.auto_accepted is True
        assert review.parent_trace_id == original.trace_id

    def test_auto_accept_rationale_records_threshold(self, tmp_path: Path):
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        original = self._proposed(confidence=0.97)
        log.append(original)

        log.auto_accept(original, threshold=0.95)

        review = log.read_all()[-1]
        assert "0.970" in review.review_rationale
        assert "0.950" in review.review_rationale
        assert "map" in review.review_rationale

    def test_human_reviews_default_to_not_auto_accepted(self, tmp_path: Path):
        """Manual review() entries must not carry auto_accepted=True."""
        log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")
        original = self._proposed(confidence=0.5)
        log.append(original)

        log.review(original.trace_id, status=TraceStatus.ACCEPTED)

        review = log.read_all()[-1]
        assert review.status == TraceStatus.ACCEPTED
        assert review.auto_accepted is False


class TestOperationKind:
    """`operation_kind` discriminator separates decision ops from read ops (#104)."""

    def test_default_is_decision(self):
        trace = AITrace(
            operation="map",
            input_text="t",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.9,
            determination="MAPPED",
            control_id="ac-1",
            framework="fw",
        )
        assert trace.operation_kind == "decision"

    def test_read_value_round_trips_through_json(self):
        trace = AITrace(
            operation="query",
            input_text="t",
            prompt="p",
            model_id="m",
            model_version="1",
            raw_output="o",
            confidence=0.0,
            determination="QUERY_EXECUTED",
            control_id="",
            framework="",
            operation_kind="read",
        )
        rebuilt = AITrace.model_validate_json(trace.model_dump_json())
        assert rebuilt.operation_kind == "read"

    def test_legacy_jsonl_without_field_defaults_to_decision(self, tmp_path: Path):
        """JSONL records written before #104 deserialize to operation_kind='decision'."""
        log_dir = tmp_path / ".lemma" / "traces"
        log_dir.mkdir(parents=True)
        legacy_line = json.dumps(
            {
                "trace_id": "legacy",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "operation": "map",
                "input_text": "x",
                "prompt": "x",
                "model_id": "m",
                "model_version": "1",
                "raw_output": "x",
                "confidence": 0.8,
                "determination": "MAPPED",
                "control_id": "ac-1",
                "framework": "fw",
            }
        )
        (log_dir / "2026-01-01.jsonl").write_text(legacy_line + "\n")

        log = TraceLog(log_dir=log_dir)
        traces = log.read_all()
        assert len(traces) == 1
        assert traces[0].operation_kind == "decision"

    def test_invalid_operation_kind_rejected(self):
        with pytest.raises(ValueError, match=r"(?i)operation_kind"):
            AITrace(
                operation="map",
                input_text="t",
                prompt="p",
                model_id="m",
                model_version="1",
                raw_output="o",
                confidence=0.9,
                determination="MAPPED",
                control_id="ac-1",
                framework="fw",
                operation_kind="invalid",  # type: ignore[arg-type]
            )
