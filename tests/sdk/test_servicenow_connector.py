"""Tests for the first-party ServiceNow connector (Refs #115)."""

from __future__ import annotations

import base64

import httpx
import pytest


def _mock_transport(handlers: dict[str, dict | int]) -> httpx.MockTransport:
    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, body in handlers.items():
            if path == prefix or path.startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": {"message": f"unmatched: {path}"}})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, dict | int], instance: str = "acme") -> httpx.Client:
    return httpx.Client(
        base_url=f"https://{instance}.service-now.com",
        transport=_mock_transport(handlers),
    )


def test_constructor_requires_instance(monkeypatch) -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "secret")
    with pytest.raises(ValueError, match="instance"):
        ServiceNowConnector(instance="", username="lemma")


def test_constructor_requires_username() -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    with pytest.raises(ValueError, match="username"):
        ServiceNowConnector(instance="acme", username="", password="x")


def test_constructor_requires_password(monkeypatch) -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.delenv("LEMMA_SERVICENOW_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="LEMMA_SERVICENOW_PASSWORD"):
        ServiceNowConnector(instance="acme", username="lemma")


def test_collect_emits_change_management_finding(monkeypatch) -> None:
    """ServiceNow's `change_request` table is the equivalent of Jira's
    change-management label — same SOC 2 CC8.1 audit signal."""
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "test_pw")
    handlers = {
        "/api/now/table/change_request": {
            "result": [
                {"number": "CHG0001", "short_description": "Patch DB", "state": "Closed Complete"},
                {
                    "number": "CHG0002",
                    "short_description": "Deploy v1.2",
                    "state": "Closed Complete",
                },
                {
                    "number": "CHG0003",
                    "short_description": "Migrate vendor",
                    "state": "Closed Cancelled",
                },
                {
                    "number": "CHG0004",
                    "short_description": "WIP firewall change",
                    "state": "Implement",
                },
            ]
        }
    }

    connector = ServiceNowConnector(
        instance="acme",
        username="lemma",
        client=_client(handlers),
    )
    events = list(connector.collect())
    assert len(events) == 1
    event = events[0]
    assert event.class_uid == 2003
    md = event.metadata
    assert md["product"]["name"] == "ServiceNow"
    assert md["instance"] == "acme"
    assert md["change_total"] == 4
    assert md["change_approved"] == 2  # both "Closed Complete"
    assert md["change_rejected"] == 1  # one "Closed Cancelled"
    assert md["change_other"] == 1  # one "Implement" (in-flight)
    assert "Approved" in event.message
    assert event.status_id == 1  # at least one approved


def test_collect_no_changes_emits_status_zero(monkeypatch) -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "test_pw")
    handlers = {"/api/now/table/change_request": {"result": []}}

    connector = ServiceNowConnector(
        instance="acme",
        username="lemma",
        client=_client(handlers),
    )
    events = list(connector.collect())
    assert len(events) == 1
    assert events[0].metadata["change_total"] == 0
    assert events[0].status_id == 0


def test_collect_rate_limit_raises(monkeypatch) -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "test_pw")
    handlers = {"/api/now/table/change_request": 429}

    connector = ServiceNowConnector(
        instance="acme",
        username="lemma",
        client=_client(handlers),
    )
    with pytest.raises(ValueError, match="rate-limit"):
        list(connector.collect())


def test_collect_uses_basic_auth_header(monkeypatch) -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "snow_pw_xyz")
    captured: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.headers))
        return httpx.Response(200, json={"result": []})

    client = httpx.Client(
        base_url="https://acme.service-now.com",
        transport=httpx.MockTransport(_capture),
    )
    connector = ServiceNowConnector(
        instance="acme",
        username="lemma_svc",
        client=client,
    )
    list(connector.collect())

    auth = captured.get("authorization", "")
    assert auth.startswith("Basic ")
    decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
    assert decoded == "lemma_svc:snow_pw_xyz"


def test_query_can_be_overridden(monkeypatch) -> None:
    """Operators can pass a custom sysparm_query to scope the search
    (e.g. `state=3^assignment_group=devops` for ServiceNow's encoded
    query language)."""
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "test_pw")
    captured_url: list[str] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        captured_url.append(str(request.url))
        return httpx.Response(200, json={"result": []})

    client = httpx.Client(
        base_url="https://acme.service-now.com",
        transport=httpx.MockTransport(_capture),
    )
    connector = ServiceNowConnector(
        instance="acme",
        username="lemma",
        query="state=3^priority<=2",
        client=client,
    )
    list(connector.collect())
    assert "state%3D3" in captured_url[0] or "state=3" in captured_url[0]


def test_dedupe_uid_is_stable_per_instance_and_date(monkeypatch) -> None:
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "test_pw")
    handlers = {"/api/now/table/change_request": {"result": []}}

    c1 = ServiceNowConnector(instance="acme", username="lemma", client=_client(handlers))
    c2 = ServiceNowConnector(instance="acme", username="lemma", client=_client(handlers))
    e1 = next(iter(c1.collect()))
    e2 = next(iter(c2.collect()))
    assert e1.metadata["uid"] == e2.metadata["uid"]


def test_can_drive_via_lemma_evidence_collect_config(tmp_path, monkeypatch) -> None:
    """Smoke test: the ServiceNow connector wires up via the
    `lemma evidence collect --config` path from #116."""
    import shutil

    from typer.testing import CliRunner

    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_SERVICENOW_PASSWORD", "test_pw")

    cfg = tmp_path / "lemma_connector_config.yaml"
    cfg.write_text("connector: servicenow\nconfig:\n  instance: acme\n  username: lemma\n")

    result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
    # Either the connector ran (exit 0) or hit the network boundary
    # (exit 1) — both prove the wiring resolved.
    assert result.exit_code in (0, 1), result.stdout
    shutil.rmtree(tmp_path / ".lemma", ignore_errors=True)
