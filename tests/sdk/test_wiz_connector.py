"""Tests for the first-party Wiz CSPM connector (Refs #41)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

_AUTH_PREFIX = "https://auth.app.wiz.io/oauth/token"
_API_URL = "https://api.test.app.wiz.io/graphql"


def _token_response(token: str = "wiz_access_token") -> dict[str, Any]:
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


def _issues(*severities: str) -> dict[str, Any]:
    nodes = [{"id": f"i{i}", "severity": s} for i, s in enumerate(severities)]
    return {"data": {"issues": {"nodes": nodes, "totalCount": len(nodes)}}}


def _mock_transport(handlers: dict[str, Any], capture: list[httpx.Request] | None = None):
    def _handle(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(request)
        url = str(request.url)
        for prefix, body in handlers.items():
            if url.startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"errors": [{"message": f"unmatched: {url}"}]})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, Any], capture: list[httpx.Request] | None = None) -> httpx.Client:
    return httpx.Client(transport=_mock_transport(handlers, capture))


def _conn(handlers, capture=None, **kw):
    from lemma.sdk.connectors.wiz import WizConnector

    return WizConnector(
        api_url=_API_URL,
        client_id="cid",
        client_secret="csecret",
        client=_client(handlers, capture),
        **kw,
    )


def test_constructor_requires_client_secret(monkeypatch) -> None:
    from lemma.sdk.connectors.wiz import WizConnector

    monkeypatch.delenv("LEMMA_WIZ_CLIENT_SECRET", raising=False)
    with pytest.raises(ValueError, match="LEMMA_WIZ_CLIENT_SECRET"):
        WizConnector(api_url=_API_URL, client_id="cid")


def test_constructor_requires_api_url() -> None:
    from lemma.sdk.connectors.wiz import WizConnector

    with pytest.raises(ValueError, match="api_url"):
        WizConnector(api_url="", client_id="cid", client_secret="s")


def test_collect_emits_posture_finding_with_open_criticals() -> None:
    """Open CRITICAL/HIGH cloud-posture issues → a failing ComplianceFinding."""
    handlers = {
        _AUTH_PREFIX: _token_response(),
        _API_URL: _issues("CRITICAL", "HIGH", "HIGH", "LOW"),
    }
    events = list(_conn(handlers).collect())
    assert len(events) == 1
    event = events[0]
    assert event.class_uid == 2003
    md = event.metadata
    assert md["product"]["name"] == "Wiz"
    assert md["site"] == "api.test.app.wiz.io"
    assert md["open_critical_count"] == 1
    assert md["open_high_count"] == 2
    assert md["open_issue_total"] == 4
    assert event.status_id == 2  # open criticals → fail


def test_collect_no_open_criticals_is_pass() -> None:
    handlers = {_AUTH_PREFIX: _token_response(), _API_URL: _issues("LOW", "INFORMATIONAL")}
    events = list(_conn(handlers).collect())
    assert events[0].metadata["open_critical_count"] == 0
    assert events[0].metadata["open_high_count"] == 0
    assert events[0].status_id == 1


def test_exchanges_token_then_queries_graphql_with_bearer() -> None:
    capture: list[httpx.Request] = []
    handlers = {_AUTH_PREFIX: _token_response("tok-123"), _API_URL: _issues()}
    list(_conn(handlers, capture=capture).collect())

    # First the token exchange, then the GraphQL call carrying the bearer token.
    assert str(capture[0].url).startswith(_AUTH_PREFIX)
    graphql_req = next(r for r in capture if str(r.url) == _API_URL)
    assert graphql_req.method == "POST"
    assert graphql_req.headers.get("authorization") == "Bearer tok-123"


def test_collect_rate_limit_raises() -> None:
    handlers = {_AUTH_PREFIX: _token_response(), _API_URL: 429}
    with pytest.raises(ValueError, match="rate-limit"):
        list(_conn(handlers).collect())


def test_dedupe_uid_stable_per_site_and_date() -> None:
    handlers = {_AUTH_PREFIX: _token_response(), _API_URL: _issues()}
    e1 = next(iter(_conn(handlers).collect()))
    e2 = next(iter(_conn(handlers).collect()))
    assert e1.metadata["uid"] == e2.metadata["uid"]


def test_secret_never_appears_in_emitted_event(monkeypatch) -> None:
    secret = "SUPER_SECRET_WIZ"
    monkeypatch.setenv("LEMMA_WIZ_CLIENT_SECRET", secret)
    handlers = {_AUTH_PREFIX: _token_response("tok"), _API_URL: _issues("CRITICAL")}
    from lemma.sdk.connectors.wiz import WizConnector

    conn = WizConnector(api_url=_API_URL, client_id="cid", client=_client(handlers))
    event = next(iter(conn.collect()))
    dumped = event.model_dump_json()
    assert secret not in dumped
    assert "tok" not in dumped
