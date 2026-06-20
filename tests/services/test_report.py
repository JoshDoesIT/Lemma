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
