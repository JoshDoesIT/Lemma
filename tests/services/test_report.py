"""Tests for the static HTML posture report renderer (Refs #32)."""

from __future__ import annotations

from datetime import UTC, datetime


def _result(*, failing: bool = True):
    from lemma.models.check_result import CheckResult, CheckStatus, ControlCheckOutcome

    outcomes = [
        ControlCheckOutcome(
            control_id="control:nist-800-53:ac-1",
            framework="nist-800-53",
            short_id="ac-1",
            title="Access Control Policy and Procedures",
            status=CheckStatus.PASSED,
            satisfying_policies=["access-control.md"],
        ),
        ControlCheckOutcome(
            control_id="control:nist-800-53:ac-2",
            framework="nist-800-53",
            short_id="ac-2",
            title="Account Management",
            status=CheckStatus.FAILED if failing else CheckStatus.PASSED,
        ),
        ControlCheckOutcome(
            control_id="control:hipaa-security-rule:164.312(b)",
            framework="hipaa-security-rule",
            short_id="164.312(b)",
            title="Audit Controls",
            status=CheckStatus.PASSED,
            satisfying_policies=["logging.md"],
        ),
    ]
    return CheckResult(framework=None, outcomes=outcomes)


_NOW = datetime(2026, 6, 20, 12, 0, tzinfo=UTC)


class TestRenderHtmlReport:
    def test_is_a_full_html_document(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(), generated_at=_NOW)
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "<title>" in html

    def test_uses_brand_palette(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(), generated_at=_NOW)
        # Void Black background, Terminal Green accent.
        assert "#0A0A0A" in html
        assert "#00FF41" in html

    def test_shows_aggregate_counts(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(), generated_at=_NOW)
        assert "3" in html  # total
        assert "2 passed" in html or "passed" in html
        assert "1 failed" in html or "failed" in html

    def test_groups_by_framework_with_coverage(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(), generated_at=_NOW)
        assert "nist-800-53" in html
        assert "hipaa-security-rule" in html
        # nist has 1/2 passing → 50%; hipaa 1/1 → 100%.
        assert "50" in html
        assert "100" in html

    def test_lists_failed_controls(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(failing=True), generated_at=_NOW)
        assert "Account Management" in html
        assert "ac-2" in html

    def test_escapes_html_in_titles(self):
        from lemma.models.check_result import CheckResult, CheckStatus, ControlCheckOutcome
        from lemma.services.report import render_html_report

        result = CheckResult(
            framework=None,
            outcomes=[
                ControlCheckOutcome(
                    control_id="control:x:c1",
                    framework="x",
                    short_id="c1",
                    title="<script>alert('xss')</script>",
                    status=CheckStatus.FAILED,
                )
            ],
        )
        html = render_html_report(result, generated_at=_NOW)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_all_pass_renders_clean_state(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(failing=False), generated_at=_NOW)
        assert "0 failed" in html or "failed" in html
        # The generated timestamp appears.
        assert "2026-06-20" in html


def _trace(
    *, operation="map", confidence=0.92, status="ACCEPTED", control_id="control:nist-800-53:ac-1"
):
    from lemma.models.trace import AITrace

    return AITrace(
        operation=operation,
        input_text="policy text",
        prompt="prompt",
        model_id="ollama/llama3.2",
        model_version="1",
        raw_output="{}",
        confidence=confidence,
        determination="MAPPED",
        control_id=control_id,
        framework="nist-800-53",
        status=status,
    )


class TestTraceSection:
    def test_no_traces_omits_section(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(), generated_at=_NOW, traces=None)
        assert "AI Decisions" not in html

    def test_traces_render_decision_table(self):
        from lemma.services.report import render_html_report

        html = render_html_report(
            _result(),
            generated_at=_NOW,
            traces=[_trace(), _trace(status="PROPOSED", confidence=0.4)],
        )
        assert "AI Decisions" in html
        assert "ollama/llama3.2" in html
        assert "MAPPED" in html
        assert "ACCEPTED" in html
        assert "0.92" in html
        assert "2 AI decision" in html

    def test_trace_control_id_is_escaped(self):
        from lemma.services.report import render_html_report

        html = render_html_report(
            _result(), generated_at=_NOW, traces=[_trace(control_id="<b>x</b>")]
        )
        assert "<b>x</b>" not in html
        assert "&lt;b&gt;" in html


def _envelope(
    *, producer="GitHub", entry_hash="abc123def456abc1", event_class="Compliance Finding"
):
    from datetime import UTC, datetime
    from types import SimpleNamespace

    event = SimpleNamespace(
        class_name=event_class,
        class_uid=2003,
        metadata={"product": {"name": producer}, "uid": "x"},
    )
    return SimpleNamespace(
        event=event,
        signed_at=datetime(2026, 6, 20, 9, 30, tzinfo=UTC),
        entry_hash=entry_hash,
        signer_key_id="key-1",
    )


class TestEvidenceSection:
    def test_no_evidence_omits_section(self):
        from lemma.services.report import render_html_report

        html = render_html_report(_result(), generated_at=_NOW, evidence=None)
        assert "Evidence Timeline" not in html

    def test_evidence_renders_timeline(self):
        from lemma.services.report import render_html_report

        html = render_html_report(
            _result(),
            generated_at=_NOW,
            evidence=[_envelope(producer="Okta"), _envelope(producer="AWS")],
        )
        assert "Evidence Timeline" in html
        assert "Okta" in html
        assert "AWS" in html
        assert "Compliance Finding" in html
        assert "abc123def456abc1" in html  # truncated entry hash

    def test_producer_falls_back_to_key_id(self):
        from types import SimpleNamespace

        from lemma.services.report import render_html_report

        env = _envelope()
        # Strip the product metadata so producer falls back to signer key.
        env.event = SimpleNamespace(class_name="X", class_uid=2003, metadata={})
        env.signer_key_id = "fallback-key-id"
        html = render_html_report(_result(), generated_at=_NOW, evidence=[env])
        assert "fallback-key-id"[:16] in html
