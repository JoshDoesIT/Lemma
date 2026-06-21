"""Static HTML posture report renderer (Refs #32, Web Dashboard).

The first slice of the engineer-first dashboard: a self-contained, static
HTML posture report rendered straight from a ``CheckResult`` — no JavaScript
framework, no server, no build step. ``lemma report`` writes a single file an
engineer can open locally, attach to an audit, or publish behind any static
host.

The aesthetic follows the Lemma brand (Void Black ``#0A0A0A`` background,
Terminal Green ``#00FF41`` accents). Everything is inlined so the file is
portable. All upstream text (control titles, framework names) is HTML-escaped.
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime

from lemma.models.check_result import CheckResult, CheckStatus

_VOID_BLACK = "#0A0A0A"
_TERMINAL_GREEN = "#00FF41"
_THEOREM_YELLOW = "#EAB308"
_CHALK = "#E6E6E6"
_FAIL_RED = "#FF4136"

_CSS = f"""
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 2.5rem 1.5rem;
    background: {_VOID_BLACK}; color: {_CHALK};
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
  h1 .dot {{ color: {_TERMINAL_GREEN}; }}
  .meta {{ color: #888; font-size: .85rem; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2.5rem; flex-wrap: wrap; }}
  .stat {{
    border: 1px solid #222; border-radius: 6px; padding: 1rem 1.25rem;
    min-width: 120px; background: #050505;
  }}
  .stat .num {{ font-size: 1.9rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
  .stat .lbl {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; color: #888; }}
  .pass .num {{ color: {_TERMINAL_GREEN}; }}
  .fail .num {{ color: {_FAIL_RED}; }}
  h2 {{
    font-size: 1.05rem; margin: 2rem 0 .75rem;
    border-bottom: 1px solid #222; padding-bottom: .4rem;
  }}
  .fw {{ margin-bottom: 1.75rem; }}
  .fw-head {{ display: flex; justify-content: space-between; align-items: baseline; }}
  .fw-name {{ font-family: 'JetBrains Mono', monospace; color: {_TERMINAL_GREEN}; }}
  .bar {{
    height: 8px; background: #1a1a1a; border-radius: 4px;
    overflow: hidden; margin: .4rem 0 .2rem;
  }}
  .bar > span {{ display: block; height: 100%; background: {_TERMINAL_GREEN}; }}
  .cov {{ font-family: 'JetBrains Mono', monospace; font-size: .85rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: .5rem; font-size: .9rem; }}
  th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #1a1a1a; }}
  th {{
    color: #888; font-weight: 600; font-size: .75rem;
    text-transform: uppercase; letter-spacing: .06em;
  }}
  td.id {{
    font-family: 'JetBrains Mono', monospace;
    color: {_THEOREM_YELLOW}; white-space: nowrap;
  }}
  .badge-fail {{ color: {_FAIL_RED}; font-family: 'JetBrains Mono', monospace; }}
  .clean {{ color: {_TERMINAL_GREEN}; }}
  footer {{ margin-top: 3rem; color: #555; font-size: .75rem; }}
"""


def _escape(text: str) -> str:
    return html.escape(text or "")


def _freshness_label(evidence: list | None, now: datetime) -> str:
    """Data-freshness indicator: when evidence was last collected (Refs #40).

    Returns an empty string when there is no evidence, so the header degrades
    cleanly. The relative age is best-effort — a naive/aware timestamp mismatch
    falls back to the absolute timestamp without an "ago" suffix.
    """
    if not evidence:
        return ""
    latest = max(env.signed_at for env in evidence)
    label = f" · evidence as of {latest:%Y-%m-%d %H:%M UTC}"
    try:
        seconds = max(0, int((now - latest).total_seconds()))
    except TypeError:
        return label
    if seconds < 3600:
        ago = f"{seconds // 60}m ago"
    elif seconds < 86400:
        ago = f"{seconds // 3600}h ago"
    else:
        ago = f"{seconds // 86400}d ago"
    return f"{label} ({ago})"


def render_html_report(
    result: CheckResult,
    *,
    generated_at: datetime,
    traces: list | None = None,
    evidence: list | None = None,
) -> str:
    """Render a ``CheckResult`` into a standalone HTML posture report.

    When ``traces`` (a list of ``AITrace``) is supplied, an "AI Decisions"
    section is appended — the dashboard's AI-trace viewer, surfacing every
    logged AI determination with its model, confidence, and review status.

    When ``evidence`` (a list of ``SignedEvidence`` envelopes) is supplied, an
    "Evidence Timeline" section is appended — the auditor-portal view, listing
    signed evidence chronologically with producer, event, and entry hash.
    """
    scope_label = f"framework {_escape(result.framework)}" if result.framework else "all frameworks"
    by_fw: dict[str, list] = defaultdict(list)
    for outcome in result.outcomes:
        by_fw[outcome.framework].append(outcome)

    fw_sections = "\n".join(
        _framework_section(name, outcomes) for name, outcomes in sorted(by_fw.items())
    )

    failed = [o for o in result.outcomes if o.status == CheckStatus.FAILED]
    failed_section = (
        _failed_table(failed)
        if failed
        else (f'<p class="clean">∴ All {result.total} checked controls are satisfied.</p>')
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lemma Compliance Posture</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>Lemma Compliance Posture <span class="dot">∴</span></h1>
  <div class="meta">{scope_label} · generated {generated_at:%Y-%m-%d %H:%M UTC}\
{_freshness_label(evidence, generated_at)}</div>

  <div class="summary">
    <div class="stat">
      <div class="num">{result.total}</div><div class="lbl">Checked</div>
    </div>
    <div class="stat pass">
      <div class="num">{result.passed}</div><div class="lbl">{result.passed} passed</div>
    </div>
    <div class="stat fail">
      <div class="num">{result.failed}</div><div class="lbl">{result.failed} failed</div>
    </div>
  </div>

  <h2>Coverage by framework</h2>
  {fw_sections}

  <h2>Findings</h2>
  {failed_section}
{_traces_block(traces)}{_evidence_block(evidence)}
  <footer>Generated by Lemma · provable compliance, no black boxes.</footer>
</div>
</body>
</html>
"""


_MAX_TRACE_ROWS = 100


def _traces_block(traces: list | None) -> str:
    """Render the AI Decisions section, or empty string when no traces."""
    if not traces:
        return ""
    ordered = sorted(traces, key=lambda t: t.timestamp, reverse=True)
    shown = ordered[:_MAX_TRACE_ROWS]
    extra = len(ordered) - len(shown)
    rows = "\n".join(_trace_row(t) for t in shown)
    note = (
        f'<p class="meta">Showing the {len(shown)} most recent of {len(ordered)} AI decisions.</p>'
        if extra > 0
        else f'<p class="meta">{len(shown)} AI decision(s) logged.</p>'
    )
    return f"""
  <h2>AI Decisions</h2>
  {note}
  <table>
    <thead><tr>
      <th>Time</th><th>Operation</th><th>Model</th><th>Confidence</th>
      <th>Determination</th><th>Status</th><th>Control</th>
    </tr></thead>
    <tbody>
    {rows}
    </tbody>
  </table>
"""


def _trace_row(t) -> str:
    conf = getattr(t, "confidence", 0.0) or 0.0
    conf_color = (
        _TERMINAL_GREEN if conf >= 0.85 else (_THEOREM_YELLOW if conf >= 0.5 else _FAIL_RED)
    )
    status = str(getattr(t, "status", "") or "")
    status_color = {
        "ACCEPTED": _TERMINAL_GREEN,
        "PROPOSED": _THEOREM_YELLOW,
        "REJECTED": _FAIL_RED,
    }.get(status, _CHALK)
    control = _escape(getattr(t, "control_id", "") or "")
    return f"""<tr>
      <td class="id">{_escape(f"{t.timestamp:%Y-%m-%d %H:%M}")}</td>
      <td>{_escape(getattr(t, "operation", ""))}</td>
      <td class="id">{_escape(getattr(t, "model_id", ""))}</td>
      <td style="color:{conf_color};font-family:'JetBrains Mono',monospace">{conf:.2f}</td>
      <td>{_escape(getattr(t, "determination", ""))}</td>
      <td style="color:{status_color};font-family:'JetBrains Mono',monospace">{_escape(status)}</td>
      <td class="id">{control}</td>
    </tr>"""


_MAX_EVIDENCE_ROWS = 200


def _env_producer(env) -> str:
    md = getattr(env.event, "metadata", None) or {}
    product = md.get("product") if isinstance(md, dict) else None
    if isinstance(product, dict) and product.get("name"):
        return str(product["name"])
    return (getattr(env, "signer_key_id", "") or "unknown")[:16]


def _env_event_label(env) -> str:
    name = getattr(env.event, "class_name", "") or ""
    if name:
        return name
    return f"class_uid {getattr(env.event, 'class_uid', '?')}"


def _evidence_block(evidence: list | None) -> str:
    """Render the Evidence Timeline section, or empty string when no evidence."""
    if not evidence:
        return ""
    ordered = sorted(evidence, key=lambda e: e.signed_at)  # chronological
    shown = ordered[-_MAX_EVIDENCE_ROWS:]
    extra = len(ordered) - len(shown)
    rows = "\n".join(_evidence_row(env) for env in shown)
    note = (
        f'<p class="meta">Showing the {len(shown)} most recent of {len(ordered)} '
        f"signed evidence entries.</p>"
        if extra > 0
        else f'<p class="meta">{len(shown)} signed evidence entr(y/ies) in the log.</p>'
    )
    return f"""
  <h2>Evidence Timeline</h2>
  {note}
  <table>
    <thead><tr>
      <th>Signed</th><th>Producer</th><th>Event</th><th>Entry hash</th>
    </tr></thead>
    <tbody>
    {rows}
    </tbody>
  </table>
"""


def _evidence_row(env) -> str:
    entry_hash = _escape((getattr(env, "entry_hash", "") or "")[:16])
    return f"""<tr>
      <td class="id">{_escape(f"{env.signed_at:%Y-%m-%d %H:%M}")}</td>
      <td class="id">{_escape(_env_producer(env))}</td>
      <td>{_escape(_env_event_label(env))}</td>
      <td class="id">{entry_hash}…</td>
    </tr>"""


def _framework_section(name: str, outcomes: list) -> str:
    total = len(outcomes)
    passed = sum(1 for o in outcomes if o.status == CheckStatus.PASSED)
    pct = round(100 * passed / total) if total else 0
    return f"""<div class="fw">
    <div class="fw-head">
      <span class="fw-name">{_escape(name)}</span>
      <span class="cov">{passed}/{total} · {pct}%</span>
    </div>
    <div class="bar"><span style="width:{pct}%"></span></div>
  </div>"""


def _failed_table(failed: list) -> str:
    rows = "\n".join(
        f"""<tr>
      <td class="id">{_escape(o.short_id)}</td>
      <td class="id">{_escape(o.framework)}</td>
      <td>{_escape(o.title)}</td>
      <td class="badge-fail">FAILED</td>
    </tr>"""
        for o in failed
    )
    return f"""<table>
    <thead><tr><th>Control</th><th>Framework</th><th>Title</th><th>Status</th></tr></thead>
    <tbody>
    {rows}
    </tbody>
  </table>"""
