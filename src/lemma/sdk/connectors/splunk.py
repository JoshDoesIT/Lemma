"""First-party Splunk connector (Refs #41).

Pulls security-monitoring posture from a Splunk deployment and emits one
``ComplianceFinding`` counting the **enabled, scheduled saved searches** — the
alert/correlation rules that actually run. It's the auditable signal a SOC 2
CC7.2 (system monitoring) review wants: the entity operates monitoring that
detects anomalous activity, and those rules are active rather than disabled.

Auth: Splunk's REST API accepts a bearer token
(``Authorization: Bearer <API_TOKEN>``). The token is required (set
``LEMMA_SPLUNK_TOKEN`` in the environment or pass ``token=...`` to the
constructor); a missing token is a loud error at construction time, not a
cryptic 401 later. The REST API defaults to XML, so every request asks for
``output_mode=json``.

``base_url`` is the Splunk management endpoint (e.g.
``https://splunk.example.com:8089``); its host is used to make ``metadata.uid``
stable per ``(site, UTC date)`` so same-day re-runs dedupe.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI never
touches a real Splunk deployment.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "Splunk"


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _site_from(base_url: str) -> str:
    return urlparse(base_url).netloc or base_url


def _metadata(site: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Splunk", "uid": uid},
        "site": site,
        "uid": uid,
    }


def _truthy(value: object) -> bool:
    """Splunk REST returns booleans as JSON ``true``/``false`` on newer
    versions but ``"1"``/``"0"`` on others — accept both."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


class SplunkConnector(Connector):
    """Collect security-monitoring posture from a Splunk deployment."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._token = token or os.environ.get("LEMMA_SPLUNK_TOKEN") or None
        if not self._token:
            msg = (
                "SplunkConnector requires an API token. "
                "Set LEMMA_SPLUNK_TOKEN in the environment or pass token=... "
                "to the constructor."
            )
            raise ValueError(msg)

        self._base_url = base_url
        self._site = _site_from(base_url)
        self._client = client or httpx.Client(base_url=base_url)

        self.manifest = ConnectorManifest(
            name="splunk",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "Splunk security-monitoring posture (SOC 2 CC7.2): enabled, "
                "scheduled saved-search alert rules."
            ),
            capabilities=["security-monitoring"],
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
        }

    def _get(self, path: str, params: dict[str, str] | None = None) -> httpx.Response:
        response = self._client.get(path, headers=self._headers(), params=params)
        if response.status_code == 429:
            msg = (
                f"Splunk API rate-limit exceeded while fetching {path}. "
                "Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _security_monitoring_finding(self) -> ComplianceFinding:
        response = self._get(
            "/services/saved/searches",
            params={"output_mode": "json", "count": "0"},
        )
        uid = f"splunk:security-monitoring:{self._site}:{_today_utc_iso_date()}"

        entries: list[dict] = []
        if response.is_success:
            payload = response.json()
            if isinstance(payload, dict) and isinstance(payload.get("entry"), list):
                entries = [e for e in payload["entry"] if isinstance(e, dict)]

        def _is_enabled_alert(entry: dict) -> bool:
            content = entry.get("content")
            if not isinstance(content, dict):
                return False
            return _truthy(content.get("is_scheduled")) and not _truthy(content.get("disabled"))

        alert_count = sum(1 for e in entries if _is_enabled_alert(e))

        if alert_count:
            message = (
                f"Splunk security monitoring on {self._site}: {alert_count} enabled "
                f"scheduled alert search(es) of {len(entries)} saved search(es)."
            )
            status_id = 1
        else:
            message = (
                f"No enabled scheduled alert searches on Splunk {self._site} "
                f"({len(entries)} saved search(es) total) — no active security monitoring."
            )
            status_id = 2

        md = _metadata(self._site, uid)
        md["saved_search_total"] = len(entries)
        md["scheduled_alert_count"] = alert_count

        return ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200301,
            activity_id=1,
            time=datetime.now(UTC),
            message=message,
            status_id=status_id,
            metadata=md,
        )

    def collect(self) -> Iterable[OcsfBaseEvent]:
        yield self._security_monitoring_finding()
