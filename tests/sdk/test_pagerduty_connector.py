"""Tests for the first-party PagerDuty connector (Refs #41)."""

from __future__ import annotations

import httpx
import pytest


def _mock_transport(handlers: dict[str, dict | int]) -> httpx.MockTransport:
    """Return canned responses keyed by path prefix (a dict body → 200,
    an int → that status with an empty body)."""

    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, body in handlers.items():
            if path == prefix or path.startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": {"message": f"unmatched: {path}"}})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, dict | int]) -> httpx.Client:
    return httpx.Client(base_url="https://api.pagerduty.com", transport=_mock_transport(handlers))


def test_constructor_requires_token(monkeypatch) -> None:
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    monkeypatch.delenv("LEMMA_PAGERDUTY_TOKEN", raising=False)
    with pytest.raises(ValueError, match="LEMMA_PAGERDUTY_TOKEN"):
        PagerDutyConnector(subdomain="acme")


def test_collect_emits_incident_response_finding(monkeypatch) -> None:
    """The connector pulls escalation policies + active on-calls and emits one
    ComplianceFinding — the auditable signal a SOC 2 CC7.x incident-response
    review wants."""
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    monkeypatch.setenv("LEMMA_PAGERDUTY_TOKEN", "tok")
    handlers = {
        "/escalation_policies": {
            "escalation_policies": [{"id": "EP1", "name": "Primary"}, {"id": "EP2"}],
            "total": 2,
        },
        "/oncalls": {"oncalls": [{"user": {"id": "U1"}}, {"user": {"id": "U2"}}]},
    }

    connector = PagerDutyConnector(subdomain="acme", client=_client(handlers))
    events = list(connector.collect())

    assert len(events) == 1
    event = events[0]
    assert event.class_uid == 2003
    md = event.metadata
    assert md["product"]["name"] == "PagerDuty"
    assert md["subdomain"] == "acme"
    assert md["escalation_policy_count"] == 2
    assert md["active_oncall_count"] == 2
    assert event.status_id == 1  # policies defined + active coverage


def test_collect_no_escalation_policies_is_failed(monkeypatch) -> None:
    """No escalation policies → an IR process gap, surfaced as status_id 2."""
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    monkeypatch.setenv("LEMMA_PAGERDUTY_TOKEN", "tok")
    handlers = {
        "/escalation_policies": {"escalation_policies": [], "total": 0},
        "/oncalls": {"oncalls": []},
    }

    connector = PagerDutyConnector(subdomain="acme", client=_client(handlers))
    events = list(connector.collect())
    assert len(events) == 1
    assert events[0].metadata["escalation_policy_count"] == 0
    assert events[0].status_id == 2


def test_collect_rate_limit_raises(monkeypatch) -> None:
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    monkeypatch.setenv("LEMMA_PAGERDUTY_TOKEN", "tok")
    connector = PagerDutyConnector(subdomain="acme", client=_client({"/escalation_policies": 429}))
    with pytest.raises(ValueError, match="rate-limit"):
        list(connector.collect())


def test_uses_token_auth_header(monkeypatch) -> None:
    """PagerDuty REST uses `Authorization: Token token=<API_TOKEN>`."""
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    monkeypatch.setenv("LEMMA_PAGERDUTY_TOKEN", "secret-tok")
    captured: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.headers))
        return httpx.Response(200, json={})

    client = httpx.Client(
        base_url="https://api.pagerduty.com", transport=httpx.MockTransport(_capture)
    )
    connector = PagerDutyConnector(subdomain="acme", client=client)
    list(connector.collect())

    assert captured.get("authorization") == "Token token=secret-tok"


def test_dedupe_uid_stable_per_subdomain_and_date(monkeypatch) -> None:
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    monkeypatch.setenv("LEMMA_PAGERDUTY_TOKEN", "tok")
    handlers = {"/escalation_policies": {"escalation_policies": []}, "/oncalls": {"oncalls": []}}
    e1 = next(iter(PagerDutyConnector(subdomain="acme", client=_client(handlers)).collect()))
    e2 = next(iter(PagerDutyConnector(subdomain="acme", client=_client(handlers)).collect()))
    assert e1.metadata["uid"] == e2.metadata["uid"]


def test_token_never_appears_in_emitted_event(monkeypatch) -> None:
    """The API token is used only for auth, never serialized into evidence."""
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    token = "SUPER_SECRET_PD_TOKEN"
    monkeypatch.setenv("LEMMA_PAGERDUTY_TOKEN", token)
    handlers = {
        "/escalation_policies": {"escalation_policies": [{"id": "EP1"}]},
        "/oncalls": {"oncalls": [{"user": {"id": "U1"}}]},
    }
    event = next(iter(PagerDutyConnector(subdomain="acme", client=_client(handlers)).collect()))
    assert token not in event.model_dump_json()
