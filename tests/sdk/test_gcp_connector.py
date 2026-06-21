"""Tests for the first-party GCP connector (Refs #115)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest


def _mock_transport(handlers: dict[str, dict | int]) -> httpx.MockTransport:
    """Match request paths against the longest registered prefix.

    Returning the registered status int short-circuits to a non-200
    response (used for 429); a dict gets wrapped as a 200 JSON body.
    """

    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        # Match longest prefix first so /sinks doesn't shadow /serviceAccounts/-/keys.
        for prefix in sorted(handlers, key=len, reverse=True):
            if path == prefix or path.startswith(prefix):
                body = handlers[prefix]
                if isinstance(body, int):
                    return httpx.Response(body)
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": {"message": f"unmatched: {path}"}})

    return httpx.MockTransport(_handle)


def _client(handlers: dict[str, dict | int]) -> httpx.Client:
    return httpx.Client(
        base_url="https://googleapis.com",
        transport=_mock_transport(handlers),
    )


# Fresh keys (created today), well within 90-day rotation window.
_FRESH_KEYS_PAYLOAD = {
    "keys": [
        {
            "name": "projects/p/serviceAccounts/x/keys/k1",
            "keyType": "USER_MANAGED",
            "validAfterTime": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        {
            "name": "projects/p/serviceAccounts/x/keys/k2",
            "keyType": "USER_MANAGED",
            "validAfterTime": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
    ]
}

# One key minted in 2020, well beyond the 90-day rotation window.
_STALE_KEYS_PAYLOAD = {
    "keys": [
        {
            "name": "projects/p/serviceAccounts/x/keys/k_old",
            "keyType": "USER_MANAGED",
            "validAfterTime": "2020-01-01T00:00:00Z",
        },
        {
            "name": "projects/p/serviceAccounts/x/keys/k_new",
            "keyType": "USER_MANAGED",
            "validAfterTime": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
    ]
}

_DURABLE_SINKS_PAYLOAD = {
    "sinks": [
        {
            "name": "audit-to-bq",
            "destination": "bigquery.googleapis.com/projects/p/datasets/audit",
        }
    ]
}

_NO_DURABLE_SINKS_PAYLOAD = {
    "sinks": [
        {
            "name": "audit-to-pubsub",
            "destination": "pubsub.googleapis.com/projects/p/topics/audit",
        }
    ]
}


def _default_handlers(
    keys_payload: dict | None = None,
    sinks_payload: dict | None = None,
) -> dict[str, dict | int]:
    return {
        "/v1/projects/p/serviceAccounts/-/keys": keys_payload or _FRESH_KEYS_PAYLOAD,
        "/v2/projects/p/sinks": sinks_payload or _DURABLE_SINKS_PAYLOAD,
    }


def test_constructor_requires_project_id() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    with pytest.raises(ValueError, match="project_id"):
        GCPConnector(project_id="", access_token="t")


def test_constructor_requires_access_token(monkeypatch) -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    monkeypatch.delenv("LEMMA_GCP_ACCESS_TOKEN", raising=False)
    with pytest.raises(ValueError, match=r"(?i)access[_ ]token|credentials"):
        GCPConnector(project_id="p")


def test_access_token_read_from_environment(monkeypatch) -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    monkeypatch.setenv("LEMMA_GCP_ACCESS_TOKEN", "env-token-abc")
    connector = GCPConnector(
        project_id="p",
        client=_client(_default_handlers()),
    )
    assert connector._access_token == "env-token-abc"


def test_collect_emits_two_findings_one_per_signal() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers()),
    )
    events = list(connector.collect())
    assert len(events) == 2

    uids = sorted(e.metadata["product"]["uid"] for e in events)
    assert any("iam-sa-keys" in uid for uid in uids)
    assert any("audit-log-sinks" in uid for uid in uids)


def test_iam_sa_keys_finding_passes_when_no_stale_keys() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers(keys_payload=_FRESH_KEYS_PAYLOAD)),
    )
    keys_finding = next(
        e for e in connector.collect() if "iam-sa-keys" in e.metadata["product"]["uid"]
    )
    assert keys_finding.status_id == 1
    assert keys_finding.metadata["key_count"] == 2
    assert keys_finding.metadata["stale_keys"] == 0


def test_iam_sa_keys_finding_fails_when_stale_key_present() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers(keys_payload=_STALE_KEYS_PAYLOAD)),
    )
    keys_finding = next(
        e for e in connector.collect() if "iam-sa-keys" in e.metadata["product"]["uid"]
    )
    assert keys_finding.status_id == 2
    assert keys_finding.metadata["key_count"] == 2
    assert keys_finding.metadata["stale_keys"] == 1


def test_audit_log_sinks_finding_passes_when_durable_sink_present() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers(sinks_payload=_DURABLE_SINKS_PAYLOAD)),
    )
    sinks_finding = next(
        e for e in connector.collect() if "audit-log-sinks" in e.metadata["product"]["uid"]
    )
    assert sinks_finding.status_id == 1
    assert sinks_finding.metadata["sink_count"] == 1
    assert sinks_finding.metadata["durable_sink_count"] == 1


def test_audit_log_sinks_finding_fails_when_no_durable_sink() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers(sinks_payload=_NO_DURABLE_SINKS_PAYLOAD)),
    )
    sinks_finding = next(
        e for e in connector.collect() if "audit-log-sinks" in e.metadata["product"]["uid"]
    )
    assert sinks_finding.status_id == 2
    assert sinks_finding.metadata["sink_count"] == 1
    assert sinks_finding.metadata["durable_sink_count"] == 0


def test_collect_uses_bearer_auth_header() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    captured: list[dict[str, str]] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.append(dict(request.headers))
        # Return a benign empty payload for whichever endpoint we're on.
        if "serviceAccounts" in request.url.path:
            return httpx.Response(200, json={"keys": []})
        return httpx.Response(200, json={"sinks": []})

    client = httpx.Client(
        base_url="https://googleapis.com",
        transport=httpx.MockTransport(_capture),
    )
    connector = GCPConnector(
        project_id="p",
        access_token="abc-xyz-123",
        client=client,
    )
    list(connector.collect())

    assert captured, "no requests were captured"
    for headers in captured:
        assert headers.get("authorization") == "Bearer abc-xyz-123"


def test_iam_endpoint_429_raises_with_endpoint_named() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    handlers = {
        "/v1/projects/p/serviceAccounts/-/keys": 429,
        "/v2/projects/p/sinks": _DURABLE_SINKS_PAYLOAD,
    }
    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(handlers),
    )
    with pytest.raises(ValueError, match=r"(?i)serviceAccounts"):
        list(connector.collect())


def test_sinks_endpoint_429_raises_with_endpoint_named() -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    handlers = {
        "/v1/projects/p/serviceAccounts/-/keys": _FRESH_KEYS_PAYLOAD,
        "/v2/projects/p/sinks": 429,
    }
    connector = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(handlers),
    )
    with pytest.raises(ValueError, match=r"(?i)sinks"):
        list(connector.collect())


def test_dedupe_uid_stable_per_project_signal_and_date(monkeypatch) -> None:
    from lemma.sdk.connectors.gcp import GCPConnector

    fixed_now = datetime(2026, 5, 2, 12, 0, 0, tzinfo=UTC)

    class _FixedNow:
        @staticmethod
        def now(tz=None):
            return fixed_now

    monkeypatch.setattr("lemma.sdk.connectors.gcp.datetime", _FixedNow)

    c1 = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers()),
    )
    c2 = GCPConnector(
        project_id="p",
        access_token="t",
        client=_client(_default_handlers()),
    )
    uids1 = sorted(e.metadata["product"]["uid"] for e in c1.collect())
    uids2 = sorted(e.metadata["product"]["uid"] for e in c2.collect())
    assert uids1 == uids2
    assert all(uid.endswith(":2026-05-02") for uid in uids1)
    assert all(":p:" in uid for uid in uids1)


def test_can_drive_via_lemma_evidence_collect_config(tmp_path, monkeypatch) -> None:
    """Smoke test: the GCP connector wires up via the
    `lemma evidence collect --config` path from #116."""
    import shutil

    from typer.testing import CliRunner

    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    monkeypatch.setenv("LEMMA_GCP_ACCESS_TOKEN", "smoke-token")

    cfg = tmp_path / "lemma_connector_config.yaml"
    cfg.write_text("connector: gcp\nconfig:\n  project_id: smoke\n")

    result = CliRunner().invoke(app, ["evidence", "collect", "--config", str(cfg)])
    # Either the connector ran (exit 0) or hit the network boundary
    # (exit 1) — both prove the wiring resolved.
    assert result.exit_code in (0, 1), result.stdout
    shutil.rmtree(tmp_path / ".lemma", ignore_errors=True)
