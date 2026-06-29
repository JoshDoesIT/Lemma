"""Connector SDK conformance suite (Refs #30).

A single parametrized harness that drives every httpx-based first-party
connector with a benign mock transport and asserts the **shared contract**
every connector must honor, independent of its platform-specific behavior:

- ``collect()`` yields at least one ``OcsfBaseEvent``.
- every emitted event validates as OCSF (round-trips through Pydantic JSON).
- every event carries a non-empty ``metadata.uid`` (the dedupe key the
  evidence log relies on).

The AWS connector is intentionally excluded — it drives boto3, not httpx, and
is covered by its own dedicated test (`tests/sdk/test_aws_connector.py`).
"""

from __future__ import annotations

import httpx
import pytest

from lemma.models.ocsf import OcsfBaseEvent


def _benign(request: httpx.Request) -> httpx.Response:
    """A response that lets every connector complete a run offline.

    OAuth2 token endpoints get a usable token; every other endpoint gets an
    empty JSON object. Connectors are written defensively (missing/empty data
    → a status_id=0 "no data" finding), so this exercises the emit path
    without tailoring a fixture per connector.
    """
    url = str(request.url)
    if "oauth2" in url or "login.microsoftonline" in url or url.endswith("/token"):
        return httpx.Response(
            200, json={"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}
        )
    return httpx.Response(200, json={})


def _client(base_url: str) -> httpx.Client:
    return httpx.Client(base_url=base_url, transport=httpx.MockTransport(_benign))


def _github():
    from lemma.sdk.connectors.github import GitHubConnector

    return GitHubConnector(
        repo="octocat/Hello-World", token="t", client=_client("https://api.github.com")
    )


def _okta():
    from lemma.sdk.connectors.okta import OktaConnector

    return OktaConnector(domain="acme.okta.com", token="t", client=_client("https://acme.okta.com"))


def _jira():
    from lemma.sdk.connectors.jira import JiraConnector

    return JiraConnector(
        base_url="https://acme.atlassian.net",
        email="ci@acme.test",
        token="t",
        client=_client("https://acme.atlassian.net"),
    )


def _servicenow():
    from lemma.sdk.connectors.servicenow import ServiceNowConnector

    return ServiceNowConnector(
        instance="acme",
        username="u",
        password="p",
        client=_client("https://acme.service-now.com"),
    )


def _azure_devops():
    from lemma.sdk.connectors.azure_devops import AzureDevOpsConnector

    return AzureDevOpsConnector(
        organization="acme",
        project="payments",
        token="t",
        client=_client("https://dev.azure.com"),
    )


def _azure():
    from lemma.sdk.connectors.azure import AzureConnector

    return AzureConnector(
        tenant_id="t",
        client_id="c",
        subscription_id="s",
        client_secret="x",
        client=_client("https://management.azure.com"),
    )


def _pagerduty():
    from lemma.sdk.connectors.pagerduty import PagerDutyConnector

    return PagerDutyConnector(
        subdomain="acme", token="t", client=_client("https://api.pagerduty.com")
    )


def _splunk():
    from lemma.sdk.connectors.splunk import SplunkConnector

    return SplunkConnector(
        base_url="https://splunk.acme.com:8089",
        token="t",
        client=_client("https://splunk.acme.com:8089"),
    )


def _wiz():
    from lemma.sdk.connectors.wiz import WizConnector

    return WizConnector(
        api_url="https://api.test.app.wiz.io/graphql",
        client_id="c",
        client_secret="s",
        client=_client("https://api.test.app.wiz.io"),
    )


_FACTORIES = {
    "github": _github,
    "okta": _okta,
    "jira": _jira,
    "servicenow": _servicenow,
    "azure-devops": _azure_devops,
    "azure": _azure,
    "pagerduty": _pagerduty,
    "splunk": _splunk,
    "wiz": _wiz,
}


@pytest.mark.parametrize("name", sorted(_FACTORIES))
def test_connector_emits_valid_ocsf_events(name: str):
    connector = _FACTORIES[name]()
    events = list(connector.collect())

    assert events, f"{name} connector emitted no events on a benign run"
    for event in events:
        assert isinstance(event, OcsfBaseEvent)
        # OCSF schema conformance: a typed event must round-trip through JSON.
        rebuilt = type(event).model_validate_json(event.model_dump_json())
        assert rebuilt.class_uid == event.class_uid
        # Dedupe contract: a stable, non-empty metadata.uid.
        assert isinstance(event.metadata, dict)
        assert event.metadata.get("uid"), f"{name} event missing metadata.uid"


@pytest.mark.parametrize("name", sorted(_FACTORIES))
def test_connector_has_valid_manifest(name: str):
    connector = _FACTORIES[name]()
    assert connector.manifest.name
    assert connector.manifest.producer
    assert connector.manifest.version


def test_dedupe_uid_stable_across_two_runs():
    """Same connector + same day → identical UIDs, so the evidence log dedupes
    a same-day re-run instead of double-counting."""
    uids_first = [e.metadata["uid"] for e in _jira().collect()]
    uids_second = [e.metadata["uid"] for e in _jira().collect()]
    assert uids_first == uids_second
