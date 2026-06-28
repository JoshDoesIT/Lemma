"""First-party PagerDuty connector (Refs #41).

Pulls incident-response posture from PagerDuty and emits one
``ComplianceFinding`` aggregating escalation-policy and active on-call
coverage — the auditable signal a SOC 2 CC7.x (incident response) review
wants: there is a defined escalation path and someone is actually on call.

Auth: PagerDuty's REST API uses ``Authorization: Token token=<API_TOKEN>``.
The token is required (set ``LEMMA_PAGERDUTY_TOKEN`` in the environment or pass
``token=...`` to the constructor); a missing token is a loud error at
construction time, not a cryptic 401 later.

``subdomain`` is a label used only to make ``metadata.uid`` stable per
``(subdomain, UTC date)`` so same-day re-runs dedupe against themselves; the
REST host is the shared ``api.pagerduty.com`` for every account.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI never
touches a real PagerDuty account.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "PagerDuty"
_BASE_URL = "https://api.pagerduty.com"


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(subdomain: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "PagerDuty", "uid": uid},
        "subdomain": subdomain,
        "uid": uid,
    }


def _count(payload: object, key: str) -> int:
    """Length of ``payload[key]`` when it's a list, else 0."""
    if isinstance(payload, dict):
        items = payload.get(key)
        if isinstance(items, list):
            return len(items)
    return 0


class PagerDutyConnector(Connector):
    """Collect incident-response posture from a PagerDuty account."""

    def __init__(
        self,
        *,
        subdomain: str = "pagerduty",
        token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._token = token or os.environ.get("LEMMA_PAGERDUTY_TOKEN") or None
        if not self._token:
            msg = (
                "PagerDutyConnector requires an API token. "
                "Set LEMMA_PAGERDUTY_TOKEN in the environment or pass token=... "
                "to the constructor."
            )
            raise ValueError(msg)

        self._subdomain = subdomain
        self._client = client or httpx.Client(base_url=_BASE_URL)

        self.manifest = ConnectorManifest(
            name="pagerduty",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "PagerDuty incident-response posture (SOC 2 CC7.x): escalation "
                "policies defined and active on-call coverage."
            ),
            capabilities=["incident-response"],
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Token token={self._token}",
        }

    def _get(self, path: str, params: dict[str, str] | None = None) -> httpx.Response:
        response = self._client.get(path, headers=self._headers(), params=params)
        if response.status_code == 429:
            msg = (
                f"PagerDuty API rate-limit exceeded while fetching {path}. "
                "Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _incident_response_finding(self) -> ComplianceFinding:
        ep_resp = self._get("/escalation_policies", params={"limit": "100"})
        oc_resp = self._get("/oncalls", params={"limit": "100"})
        uid = f"pagerduty:incident-response:{self._subdomain}:{_today_utc_iso_date()}"

        policies = _count(ep_resp.json() if ep_resp.is_success else None, "escalation_policies")
        oncalls = _count(oc_resp.json() if oc_resp.is_success else None, "oncalls")

        if policies and oncalls:
            message = (
                f"PagerDuty incident-response posture on {self._subdomain}: "
                f"{policies} escalation policy(ies) with {oncalls} active on-call(s)."
            )
            status_id = 1
        elif policies:
            message = (
                f"PagerDuty has {policies} escalation policy(ies) on {self._subdomain} "
                "but no active on-call coverage — gaps leave incidents unrouted."
            )
            status_id = 2
        else:
            message = (
                f"No PagerDuty escalation policies on {self._subdomain}; the "
                "incident-response escalation path is undefined."
            )
            status_id = 2

        md = _metadata(self._subdomain, uid)
        md["escalation_policy_count"] = policies
        md["active_oncall_count"] = oncalls

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
        yield self._incident_response_finding()
