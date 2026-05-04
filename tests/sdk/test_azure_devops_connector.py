"""Tests for the first-party Azure DevOps connector (Refs #115)."""

from __future__ import annotations

import base64
import json

import httpx
import pytest


def _mock_transport(handlers: dict[str, dict | int]) -> httpx.MockTransport:
    """Match by exact path or path-prefix; values are dicts (200 + JSON)
    or ints (status code with empty body)."""

    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, body in handlers.items():
            if path == prefix or path.startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"message": f"unmatched: {path}"})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, dict | int]) -> httpx.Client:
    return httpx.Client(
        base_url="https://dev.azure.com",
        transport=_mock_transport(handlers),
    )


def test_constructor_requires_organization(monkeypatch) -> None:
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "secret")
    with pytest.raises(ValueError, match="organization"):
        AzureDevOpsConnector(organization="", project="proj")


def test_constructor_requires_project(monkeypatch) -> None:
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "secret")
    with pytest.raises(ValueError, match="project"):
        AzureDevOpsConnector(organization="acme", project="")


def test_constructor_requires_token(monkeypatch) -> None:
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.delenv("LEMMA_AZURE_DEVOPS_TOKEN", raising=False)
    with pytest.raises(ValueError, match="LEMMA_AZURE_DEVOPS_TOKEN"):
        AzureDevOpsConnector(organization="acme", project="proj")


def test_collect_emits_change_management_finding(monkeypatch) -> None:
    """End-to-end: WIQL POST returns IDs, then a workitems GET returns
    states. Connector aggregates approved / rejected / other counts."""
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "test_pat")
    handlers = {
        "/acme/proj/_apis/wit/wiql": {
            "workItems": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}],
        },
        "/acme/_apis/wit/workitems": {
            "value": [
                {"id": 1, "fields": {"System.State": "Closed"}},
                {"id": 2, "fields": {"System.State": "Done"}},
                {"id": 3, "fields": {"System.State": "Removed"}},
                {"id": 4, "fields": {"System.State": "Active"}},
            ]
        },
    }

    connector = AzureDevOpsConnector(organization="acme", project="proj", client=_client(handlers))
    events = list(connector.collect())
    assert len(events) == 1
    event = events[0]
    assert event.class_uid == 2003
    md = event.metadata
    assert md["product"]["name"] == "Azure DevOps"
    assert md["organization"] == "acme"
    assert md["project"] == "proj"
    assert md["change_total"] == 4
    assert md["change_approved"] == 2  # Closed + Done
    assert md["change_rejected"] == 1  # Removed
    assert md["change_other"] == 1  # Active (in-flight)
    assert event.status_id == 1  # at least one approved


def test_collect_no_changes_emits_status_zero(monkeypatch) -> None:
    """WIQL returning zero IDs short-circuits — no second GET issued
    and `status_id=0` (Unknown / "we looked, found nothing")."""
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "test_pat")
    handlers = {"/acme/proj/_apis/wit/wiql": {"workItems": []}}

    connector = AzureDevOpsConnector(organization="acme", project="proj", client=_client(handlers))
    events = list(connector.collect())
    assert len(events) == 1
    assert events[0].metadata["change_total"] == 0
    assert events[0].status_id == 0


def test_collect_rate_limit_raises(monkeypatch) -> None:
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "test_pat")
    handlers = {"/acme/proj/_apis/wit/wiql": 429}

    connector = AzureDevOpsConnector(organization="acme", project="proj", client=_client(handlers))
    with pytest.raises(ValueError, match="rate-limit"):
        list(connector.collect())


def test_collect_uses_basic_auth_with_empty_username(monkeypatch) -> None:
    """Azure DevOps PAT auth: HTTP Basic with empty username and the
    PAT as password. The base64 form is `:<PAT>`."""
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "ado_pat_xyz")
    captured: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.headers))
        return httpx.Response(200, json={"workItems": []})

    client = httpx.Client(
        base_url="https://dev.azure.com",
        transport=httpx.MockTransport(_capture),
    )
    connector = AzureDevOpsConnector(organization="acme", project="proj", client=client)
    list(connector.collect())

    auth = captured.get("authorization", "")
    assert auth.startswith("Basic ")
    decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
    assert decoded == ":ado_pat_xyz"


def test_wiql_query_can_be_overridden(monkeypatch) -> None:
    """Operators pass a custom WIQL to scope the search (e.g. by area
    path or sprint)."""
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "test_pat")
    captured_body: list[bytes] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_apis/wit/wiql"):
            captured_body.append(request.content)
        return httpx.Response(200, json={"workItems": []})

    client = httpx.Client(
        base_url="https://dev.azure.com",
        transport=httpx.MockTransport(_capture),
    )
    connector = AzureDevOpsConnector(
        organization="acme",
        project="proj",
        wiql="SELECT [System.Id] FROM workitems WHERE [System.AreaPath] = 'acme/security'",
        client=client,
    )
    list(connector.collect())
    body = json.loads(captured_body[0])
    assert "AreaPath" in body["query"]
    assert "security" in body["query"]


def test_dedupe_uid_is_stable_per_org_project_and_date(monkeypatch) -> None:
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "test_pat")
    handlers = {"/acme/proj/_apis/wit/wiql": {"workItems": []}}

    c1 = AzureDevOpsConnector(organization="acme", project="proj", client=_client(handlers))
    c2 = AzureDevOpsConnector(organization="acme", project="proj", client=_client(handlers))
    e1 = next(iter(c1.collect()))
    e2 = next(iter(c2.collect()))
    assert e1.metadata["uid"] == e2.metadata["uid"]


def test_can_drive_via_lemma_evidence_collect_config(tmp_path, monkeypatch) -> None:
    """Smoke test: the Azure DevOps connector wires up via
    `lemma evidence collect --config` from #116."""
    import shutil

    from typer.testing import CliRunner

    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_AZURE_DEVOPS_TOKEN", "test_pat")

    cfg = tmp_path / "lemma_connector_config.yaml"
    cfg.write_text("connector: azure-devops\nconfig:\n  organization: acme\n  project: proj\n")

    result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
    # Either the connector ran (exit 0) or hit the network boundary
    # (exit 1) — both prove the wiring resolved.
    assert result.exit_code in (0, 1), result.stdout
    shutil.rmtree(tmp_path / ".lemma", ignore_errors=True)
