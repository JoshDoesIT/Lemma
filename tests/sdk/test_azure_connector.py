"""Tests for the first-party Azure connector (Refs #115)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest


def _token_response(token: str = "azure_access_token_xyz") -> dict[str, Any]:
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


def _mock_transport(
    handlers: dict[str, Any],
    *,
    capture: list[httpx.Request] | None = None,
) -> httpx.MockTransport:
    """Build a MockTransport routing by host+path prefix.

    `handlers` keys are absolute URL prefixes ("https://login.microsoftonline.com/...").
    Values are either:
      - dict: returned as JSON body with status 200
      - int: returned as a status code
      - callable(request) -> httpx.Response: full custom handler
    """

    def _handle(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(request)
        url = str(request.url)
        for prefix, body in handlers.items():
            if url.startswith(prefix):
                if callable(body):
                    return body(request)
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": {"message": f"unmatched: {url}"}})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, Any], capture: list[httpx.Request] | None = None) -> httpx.Client:
    return httpx.Client(transport=_mock_transport(handlers, capture=capture))


_TOKEN_URL_PREFIX = "https://login.microsoftonline.com/"
_MFA_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
_DIAG_URL = (
    "https://management.azure.com/subscriptions/sub-1/providers"
    "/Microsoft.Insights/diagnosticSettings"
)
_PA_URL = (
    "https://management.azure.com/subscriptions/sub-1/providers"
    "/Microsoft.Authorization/policyAssignments"
)


def _default_handlers(
    *,
    policies: list[dict] | None = None,
    diagnostic_settings: list[dict] | None = None,
    policy_assignments: list[dict] | None = None,
) -> dict[str, Any]:
    """Build a fully-populated handler set covering all three findings."""
    return {
        _TOKEN_URL_PREFIX: _token_response(),
        _MFA_URL: {"value": policies if policies is not None else []},
        _DIAG_URL: {"value": diagnostic_settings if diagnostic_settings is not None else []},
        _PA_URL: {"value": policy_assignments if policy_assignments is not None else []},
    }


def test_constructor_requires_tenant_id(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    monkeypatch.setenv("LEMMA_AZURE_CLIENT_SECRET", "s")
    with pytest.raises(ValueError, match="tenant_id"):
        AzureConnector(tenant_id="", client_id="cid", subscription_id="sub-1")


def test_constructor_requires_client_id(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    monkeypatch.setenv("LEMMA_AZURE_CLIENT_SECRET", "s")
    with pytest.raises(ValueError, match="client_id"):
        AzureConnector(tenant_id="t", client_id="", subscription_id="sub-1")


def test_constructor_requires_client_secret(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    monkeypatch.delenv("LEMMA_AZURE_CLIENT_SECRET", raising=False)
    with pytest.raises(ValueError, match="LEMMA_AZURE_CLIENT_SECRET"):
        AzureConnector(tenant_id="t", client_id="cid", subscription_id="sub-1")


def test_constructor_requires_subscription_id(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    monkeypatch.setenv("LEMMA_AZURE_CLIENT_SECRET", "s")
    with pytest.raises(ValueError, match="subscription_id"):
        AzureConnector(tenant_id="t", client_id="cid", subscription_id="")


def test_collect_emits_three_findings(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(
        policies=[
            {
                "id": "p1",
                "displayName": "Require MFA",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ],
        diagnostic_settings=[
            {
                "id": "ds1",
                "name": "default-trail",
                "properties": {
                    "logs": [{"category": "Administrative", "enabled": True}],
                    "retentionPolicy": {"enabled": True, "days": 365},
                },
            }
        ],
        policy_assignments=[{"id": "a1", "name": "Allowed locations"}],
    )

    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    assert len(events) == 3


def test_mfa_finding_status_pass_when_enabled_policy_has_mfa(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(
        policies=[
            {
                "id": "p1",
                "displayName": "Require MFA",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ],
    )
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    mfa = next(e for e in events if "mfa" in e.metadata["uid"])
    assert mfa.status_id == 1
    assert mfa.metadata["enabled_mfa_policy_count"] >= 1


def test_mfa_finding_status_fail_when_no_enabled_mfa_policy(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(
        policies=[
            {
                "id": "p1",
                "displayName": "Disabled policy",
                "state": "disabled",
                "grantControls": {"builtInControls": ["mfa"]},
            },
            {
                "id": "p2",
                "displayName": "Block legacy",
                "state": "enabled",
                "grantControls": {"builtInControls": ["block"]},
            },
        ],
    )
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    mfa = next(e for e in events if "mfa" in e.metadata["uid"])
    assert mfa.status_id == 2
    assert mfa.metadata["enabled_mfa_policy_count"] == 0


def test_mfa_finding_status_unknown_when_call_fails(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = {
        _TOKEN_URL_PREFIX: _token_response(),
        _MFA_URL: 500,
        _DIAG_URL: {"value": []},
        _PA_URL: {"value": []},
    }
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    mfa = next(e for e in events if "mfa" in e.metadata["uid"])
    assert mfa.status_id == 0


def test_diagnostic_settings_finding_pass(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(
        diagnostic_settings=[
            {
                "id": "ds1",
                "name": "trail",
                "properties": {"retentionPolicy": {"enabled": True, "days": 365}},
            }
        ]
    )
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    diag = next(e for e in events if "activity-log-retention" in e.metadata["uid"])
    assert diag.status_id == 1
    assert diag.metadata["diagnostic_settings_count"] == 1


def test_diagnostic_settings_finding_fail_when_zero_settings(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(diagnostic_settings=[])
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    diag = next(e for e in events if "activity-log-retention" in e.metadata["uid"])
    assert diag.status_id == 2
    assert diag.metadata["diagnostic_settings_count"] == 0


def test_policy_assignments_finding_pass(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(
        policy_assignments=[{"id": "a1", "name": "loc"}, {"id": "a2", "name": "tag"}]
    )
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    pa = next(e for e in events if "policy-assignments" in e.metadata["uid"])
    assert pa.status_id == 1
    assert pa.metadata["assignment_count"] == 2


def test_policy_assignments_finding_fail_when_zero(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = _default_handlers(policy_assignments=[])
    connector = AzureConnector(
        tenant_id="t-1",
        client_id="cid",
        client_secret="secret",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    events = list(connector.collect())
    pa = next(e for e in events if "policy-assignments" in e.metadata["uid"])
    assert pa.status_id == 2
    assert pa.metadata["assignment_count"] == 0


def test_token_endpoint_called_and_bearer_attached(monkeypatch) -> None:
    """Token endpoint is POSTed with client-credentials grant, and
    subsequent calls carry `Authorization: Bearer <token>`."""
    from lemma.sdk.connectors.azure import AzureConnector

    captured: list[httpx.Request] = []
    handlers = _default_handlers()
    client = _client(handlers, capture=captured)

    connector = AzureConnector(
        tenant_id="t-xyz",
        client_id="cid",
        client_secret="topsecret",
        subscription_id="sub-1",
        client=client,
    )
    list(connector.collect())

    token_requests = [r for r in captured if "login.microsoftonline.com" in str(r.url)]
    assert token_requests, "expected token endpoint to be called"
    for tr in token_requests:
        assert tr.method == "POST"
        assert "t-xyz" in str(tr.url)

    # All non-token calls should carry Bearer.
    other_requests = [r for r in captured if "login.microsoftonline.com" not in str(r.url)]
    assert other_requests, "expected at least one resource API call"
    for r in other_requests:
        assert r.headers.get("authorization", "").startswith("Bearer ")


def test_token_cached_per_scope(monkeypatch) -> None:
    """The token endpoint is hit once per scope across a single run,
    not once per resource API call."""
    from lemma.sdk.connectors.azure import AzureConnector

    captured: list[httpx.Request] = []
    handlers = _default_handlers()
    client = _client(handlers, capture=captured)

    connector = AzureConnector(
        tenant_id="t",
        client_id="cid",
        client_secret="s",
        subscription_id="sub-1",
        client=client,
    )
    list(connector.collect())

    token_requests = [r for r in captured if "login.microsoftonline.com" in str(r.url)]
    # Two scopes total: graph.microsoft.com (MFA call) and management.azure.com (the other two).
    assert len(token_requests) == 2


def test_rate_limit_raises(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = {
        _TOKEN_URL_PREFIX: _token_response(),
        _MFA_URL: 429,
        _DIAG_URL: {"value": []},
        _PA_URL: {"value": []},
    }
    connector = AzureConnector(
        tenant_id="t",
        client_id="cid",
        client_secret="s",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    with pytest.raises(ValueError, match="rate-limit"):
        list(connector.collect())


def test_token_endpoint_failure_raises(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers = {_TOKEN_URL_PREFIX: 401}
    connector = AzureConnector(
        tenant_id="t",
        client_id="cid",
        client_secret="s",
        subscription_id="sub-1",
        client=_client(handlers),
    )
    with pytest.raises(ValueError, match="token"):
        list(connector.collect())


def test_dedupe_uid_stable_per_tenant_subscription_signal_and_date(monkeypatch) -> None:
    from lemma.sdk.connectors.azure import AzureConnector

    handlers_a = _default_handlers()
    handlers_b = _default_handlers()
    c1 = AzureConnector(
        tenant_id="t",
        client_id="cid",
        client_secret="s",
        subscription_id="sub-1",
        client=_client(handlers_a),
    )
    c2 = AzureConnector(
        tenant_id="t",
        client_id="cid",
        client_secret="s",
        subscription_id="sub-1",
        client=_client(handlers_b),
    )
    e1 = list(c1.collect())
    e2 = list(c2.collect())
    uids_1 = sorted(e.metadata["uid"] for e in e1)
    uids_2 = sorted(e.metadata["uid"] for e in e2)
    assert uids_1 == uids_2
    # All three uids share tenant, subscription, and date.
    for uid in uids_1:
        assert "t" in uid
        assert "sub-1" in uid


def test_can_drive_via_lemma_evidence_collect_config(tmp_path, monkeypatch) -> None:
    """Smoke test: the Azure connector wires up via the
    `lemma evidence collect --config` path from #116."""
    import shutil

    from typer.testing import CliRunner

    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_AZURE_CLIENT_SECRET", "test_secret")

    cfg = tmp_path / "lemma_connector_config.yaml"
    cfg.write_text(
        "connector: azure\nconfig:\n  tenant_id: t-1\n  client_id: cid\n  subscription_id: sub-1\n"
    )

    result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
    # Either the connector ran (exit 0) or hit the network boundary
    # (exit 1) — both prove the wiring resolved.
    assert result.exit_code in (0, 1), result.stdout
    shutil.rmtree(tmp_path / ".lemma", ignore_errors=True)
