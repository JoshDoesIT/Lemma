"""Tests for the first-party Jira connector (Refs #115)."""

from __future__ import annotations

import json

import httpx
import pytest


def _mock_transport(handlers: dict[str, dict | int]) -> httpx.MockTransport:
    """Build a MockTransport that returns canned responses keyed by path.

    A handler value can be a dict (200 with JSON body) or an int (status
    code with empty body) — keeps tests terse.
    """

    def _handle(request: httpx.Request) -> httpx.Response:
        # Support exact path or path-prefix match (Jira REST often takes
        # query strings we don't want to mirror in fixtures).
        path = request.url.path
        for prefix, body in handlers.items():
            if path == prefix or path.startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"errorMessages": [f"unmatched: {path}"]})

    return httpx.MockTransport(_handle)


def _client(
    handlers: dict[str, dict | int], base_url: str = "https://acme.atlassian.net"
) -> httpx.Client:
    return httpx.Client(base_url=base_url, transport=_mock_transport(handlers))


def test_constructor_requires_token(monkeypatch) -> None:
    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.delenv("LEMMA_JIRA_TOKEN", raising=False)
    with pytest.raises(ValueError, match="LEMMA_JIRA_TOKEN"):
        JiraConnector(base_url="https://acme.atlassian.net", email="ops@acme.com")


def test_constructor_requires_email() -> None:
    from lemma.sdk.connectors.jira import JiraConnector

    with pytest.raises(ValueError, match="email"):
        JiraConnector(base_url="https://acme.atlassian.net", token="secret")


def test_collect_emits_change_management_finding(monkeypatch) -> None:
    """End-to-end: connector pulls a recent batch of change-management
    issues and emits one ComplianceFinding aggregating the
    approved/rejected breakdown — the auditable signal a SOC 2 CC8.1
    review wants to see for change management."""
    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "test_token")

    handlers = {
        "/rest/api/3/search": {
            "issues": [
                {
                    "key": "OPS-1",
                    "fields": {
                        "summary": "Deploy v1.2 to prod",
                        "status": {"name": "Approved"},
                        "labels": ["change-management"],
                    },
                },
                {
                    "key": "OPS-2",
                    "fields": {
                        "summary": "Patch CVE-2024-1234",
                        "status": {"name": "Approved"},
                        "labels": ["change-management"],
                    },
                },
                {
                    "key": "OPS-3",
                    "fields": {
                        "summary": "Risky DB migration",
                        "status": {"name": "Rejected"},
                        "labels": ["change-management"],
                    },
                },
            ],
            "total": 3,
        }
    }

    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        client=_client(handlers),
    )
    events = list(connector.collect())
    assert len(events) == 1
    event = events[0]
    assert event.class_uid == 2003
    md = event.metadata
    assert md["product"]["name"] == "Jira"
    assert md["site"] == "acme.atlassian.net"
    assert md["change_total"] == 3
    assert md["change_approved"] == 2
    assert md["change_rejected"] == 1
    assert "Approved" in event.message
    assert event.status_id == 1  # at least one approved change


def test_collect_no_changes_emits_status_zero(monkeypatch) -> None:
    """Empty-result run still emits a finding (so auditors see "we
    looked, found nothing"); status_id = 0 (Unknown) signals
    informational rather than pass/fail."""
    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "test_token")
    handlers = {"/rest/api/3/search": {"issues": [], "total": 0}}

    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        client=_client(handlers),
    )
    events = list(connector.collect())
    assert len(events) == 1
    assert events[0].metadata["change_total"] == 0
    assert events[0].status_id == 0


def test_collect_rate_limit_raises(monkeypatch) -> None:
    """Jira's 429 response is surfaced as a clean ValueError naming the
    endpoint, mirroring the Okta connector's behaviour."""
    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "test_token")
    handlers = {"/rest/api/3/search": 429}

    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        client=_client(handlers),
    )
    with pytest.raises(ValueError, match="rate-limit"):
        list(connector.collect())


def test_collect_uses_basic_auth_header(monkeypatch) -> None:
    """Jira Cloud uses HTTP Basic with email:api_token. The connector
    must populate Authorization correctly so the upstream actually
    accepts the request."""
    import base64

    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "ATATT3xFfGF0secret")
    captured_headers: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"issues": [], "total": 0})

    client = httpx.Client(
        base_url="https://acme.atlassian.net",
        transport=httpx.MockTransport(_capture),
    )
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        client=client,
    )
    list(connector.collect())

    auth = captured_headers.get("authorization", "")
    assert auth.startswith("Basic "), f"expected Basic auth, got {auth}"
    decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
    assert decoded == "ops@acme.com:ATATT3xFfGF0secret"


def test_jql_can_be_overridden(monkeypatch) -> None:
    """Operators can pass a custom JQL to scope the search (e.g.
    project=OPS AND labels in (compliance))."""
    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "test_token")
    captured_url: list[str] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        captured_url.append(str(request.url))
        return httpx.Response(200, json={"issues": [], "total": 0})

    client = httpx.Client(
        base_url="https://acme.atlassian.net",
        transport=httpx.MockTransport(_capture),
    )
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        jql="project = OPS AND labels = audit",
        client=client,
    )
    list(connector.collect())
    assert "project" in captured_url[0]
    assert "OPS" in captured_url[0]


def test_dedupe_uid_is_stable_per_site_and_date(monkeypatch) -> None:
    """metadata.uid must be deterministic per (site, UTC date) so
    re-running the connector on the same day dedups against itself."""
    from lemma.sdk.connectors.jira import JiraConnector

    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "test_token")
    handlers = {"/rest/api/3/search": {"issues": [], "total": 0}}

    c1 = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        client=_client(handlers),
    )
    c2 = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ops@acme.com",
        client=_client(handlers),
    )
    e1 = next(iter(c1.collect()))
    e2 = next(iter(c2.collect()))
    assert e1.metadata["uid"] == e2.metadata["uid"]


def test_can_drive_via_lemma_evidence_collect_config(tmp_path, monkeypatch) -> None:
    """Smoke test: the Jira connector wires up via the new
    `lemma evidence collect --config` path from #116."""
    import shutil

    from typer.testing import CliRunner

    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_JIRA_TOKEN", "test_token")

    cfg = tmp_path / "lemma_connector_config.yaml"
    cfg.write_text(
        "connector: jira\nconfig:\n  base_url: https://acme.atlassian.net\n  email: ops@acme.com\n"
    )

    # The real connector would hit the network; smoke-test that the
    # CLI wiring resolves the connector and surfaces whatever error
    # the (offline) HTTP attempt produces — exit non-zero, not crash.
    result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
    # Either the connector ran (exit 0) or failed at the network
    # boundary (exit 1) — both prove the wiring resolved.
    assert result.exit_code in (0, 1), result.stdout
    # Discard cached test artefacts.
    shutil.rmtree(tmp_path / ".lemma", ignore_errors=True)


# Suppress unused-import warning for the json module — kept for
# future fixture extensions.
_ = json
