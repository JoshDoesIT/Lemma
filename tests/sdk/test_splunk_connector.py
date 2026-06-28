"""Tests for the first-party Splunk connector (Refs #41)."""

from __future__ import annotations

import httpx
import pytest

_BASE = "https://splunk.acme.com:8089"


def _mock_transport(handlers: dict[str, dict | int]) -> httpx.MockTransport:
    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, body in handlers.items():
            if path == prefix or path.startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"messages": [{"text": f"unmatched: {path}"}]})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, dict | int]) -> httpx.Client:
    return httpx.Client(base_url=_BASE, transport=_mock_transport(handlers))


def _searches(*entries: dict) -> dict:
    return {"entry": list(entries)}


def _search(name: str, *, scheduled: bool = True, disabled: bool = False) -> dict:
    return {"name": name, "content": {"is_scheduled": scheduled, "disabled": disabled}}


def test_constructor_requires_token(monkeypatch) -> None:
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.delenv("LEMMA_SPLUNK_TOKEN", raising=False)
    with pytest.raises(ValueError, match="LEMMA_SPLUNK_TOKEN"):
        SplunkConnector(base_url=_BASE)


def test_collect_emits_monitoring_finding(monkeypatch) -> None:
    """Counts enabled scheduled saved searches — the auditable signal that
    security monitoring is configured (SOC 2 CC7.2)."""
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", "tok")
    handlers = {
        "/services/saved/searches": _searches(
            _search("Failed Logins", scheduled=True, disabled=False),
            _search("Privilege Escalation", scheduled=True, disabled=False),
            _search("Ad-hoc report", scheduled=False, disabled=False),  # not an alert
            _search("Old rule", scheduled=True, disabled=True),  # disabled
        )
    }
    connector = SplunkConnector(base_url=_BASE, client=_client(handlers))
    events = list(connector.collect())

    assert len(events) == 1
    event = events[0]
    assert event.class_uid == 2003
    md = event.metadata
    assert md["product"]["name"] == "Splunk"
    assert md["site"] == "splunk.acme.com:8089"
    assert md["saved_search_total"] == 4
    assert md["scheduled_alert_count"] == 2  # only enabled + scheduled
    assert event.status_id == 1


def test_collect_no_enabled_alerts_is_failed(monkeypatch) -> None:
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", "tok")
    handlers = {"/services/saved/searches": _searches(_search("Old", disabled=True))}
    connector = SplunkConnector(base_url=_BASE, client=_client(handlers))
    events = list(connector.collect())
    assert len(events) == 1
    assert events[0].metadata["scheduled_alert_count"] == 0
    assert events[0].status_id == 2


def test_uses_bearer_auth_header(monkeypatch) -> None:
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", "secret-tok")
    captured: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.headers))
        return httpx.Response(200, json={"entry": []})

    client = httpx.Client(base_url=_BASE, transport=httpx.MockTransport(_capture))
    list(SplunkConnector(base_url=_BASE, client=client).collect())
    assert captured.get("authorization") == "Bearer secret-tok"


def test_requests_json_output_mode(monkeypatch) -> None:
    """Splunk REST defaults to XML; the connector must ask for JSON."""
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", "tok")
    captured: list[str] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(200, json={"entry": []})

    client = httpx.Client(base_url=_BASE, transport=httpx.MockTransport(_capture))
    list(SplunkConnector(base_url=_BASE, client=client).collect())
    assert "output_mode=json" in captured[0]


def test_collect_rate_limit_raises(monkeypatch) -> None:
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", "tok")
    connector = SplunkConnector(base_url=_BASE, client=_client({"/services/saved/searches": 429}))
    with pytest.raises(ValueError, match="rate-limit"):
        list(connector.collect())


def test_dedupe_uid_stable_per_site_and_date(monkeypatch) -> None:
    from lemma.sdk.connectors.splunk import SplunkConnector

    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", "tok")
    handlers = {"/services/saved/searches": _searches()}
    e1 = next(iter(SplunkConnector(base_url=_BASE, client=_client(handlers)).collect()))
    e2 = next(iter(SplunkConnector(base_url=_BASE, client=_client(handlers)).collect()))
    assert e1.metadata["uid"] == e2.metadata["uid"]


def test_token_never_appears_in_emitted_event(monkeypatch) -> None:
    from lemma.sdk.connectors.splunk import SplunkConnector

    token = "SUPER_SECRET_SPLUNK_TOKEN"
    monkeypatch.setenv("LEMMA_SPLUNK_TOKEN", token)
    handlers = {"/services/saved/searches": _searches(_search("Alert"))}
    event = next(iter(SplunkConnector(base_url=_BASE, client=_client(handlers)).collect()))
    assert token not in event.model_dump_json()
