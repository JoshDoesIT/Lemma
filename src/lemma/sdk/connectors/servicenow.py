"""First-party ServiceNow connector (Refs #115).

Pulls change-request evidence from a ServiceNow instance and emits one
``ComplianceFinding`` aggregating the approved / rejected breakdown
across recent change records — the SOC 2 CC8.1 audit signal for
change management. Mirrors the Jira connector's shape so operators
running both ITSM tools get the same OCSF wire format.

Auth: ServiceNow's REST table API uses HTTP Basic with
``username:password``. Password via ``LEMMA_SERVICENOW_PASSWORD`` env
var or ``password=...`` constructor arg. Missing credentials fail at
construction time, not mid-collect.

The default query targets every record in ``change_request``.
Operators override via ``query=...`` (ServiceNow's encoded query
language) for per-state, per-assignment-group, or per-time-window
scoping. The ``metadata.uid`` is stable per ``(instance, UTC date)``
so same-day re-runs dedupe through the EvidenceLog.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches a real ServiceNow instance.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "ServiceNow"
_DEFAULT_QUERY = ""

# State-name buckets. ServiceNow installations customise state values
# but these are the OOB names. Custom installations set ``query=...``
# to filter to the states they care about and the bucket counts still
# add up to the total.
_APPROVED_STATES = {"Closed Complete", "Closed Successful", "Approved"}
_REJECTED_STATES = {"Closed Cancelled", "Closed Unsuccessful", "Rejected", "Closed Skipped"}


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(instance: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "ServiceNow, Inc.", "uid": uid},
        "instance": instance,
        "uid": uid,
    }


class ServiceNowConnector(Connector):
    """Collect change-request posture from a ServiceNow instance."""

    def __init__(
        self,
        *,
        instance: str,
        username: str,
        password: str | None = None,
        query: str = _DEFAULT_QUERY,
        client: httpx.Client | None = None,
    ) -> None:
        if not instance:
            msg = (
                "ServiceNowConnector requires an instance "
                "(the subdomain of <instance>.service-now.com)."
            )
            raise ValueError(msg)
        if not username:
            msg = "ServiceNowConnector requires a username for HTTP Basic auth."
            raise ValueError(msg)
        self._instance = instance
        self._username = username
        self._password = password or os.environ.get("LEMMA_SERVICENOW_PASSWORD") or None
        if not self._password:
            msg = (
                "ServiceNowConnector requires a password. Set "
                "LEMMA_SERVICENOW_PASSWORD in the environment or pass "
                "password=... to the constructor."
            )
            raise ValueError(msg)

        self._query = query
        self._client = client or httpx.Client(base_url=f"https://{instance}.service-now.com")

        self.manifest = ConnectorManifest(
            name="servicenow",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "ServiceNow change-management posture: aggregate count of recent "
                "change_request records with approved/rejected breakdown."
            ),
            capabilities=["change-management"],
        )

    def _auth_header(self) -> str:
        creds = f"{self._username}:{self._password}".encode()
        return "Basic " + base64.b64encode(creds).decode()

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": self._auth_header(),
        }

    def _get(self, path: str, params: dict[str, str] | None = None) -> httpx.Response:
        response = self._client.get(path, headers=self._headers(), params=params)
        if response.status_code == 429:
            msg = (
                f"ServiceNow API rate-limit exceeded while fetching {path}. "
                "Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _change_management_finding(self) -> ComplianceFinding:
        params: dict[str, str] = {
            "sysparm_fields": "number,short_description,state",
            "sysparm_display_value": "true",
        }
        if self._query:
            params["sysparm_query"] = self._query
        response = self._get("/api/now/table/change_request", params=params)
        uid = f"servicenow:change-management:{self._instance}:{_today_utc_iso_date()}"

        records: list[dict] = []
        if response.is_success:
            payload = response.json()
            if isinstance(payload, dict):
                raw = payload.get("result")
                if isinstance(raw, list):
                    records = raw

        approved = sum(1 for r in records if _state(r) in _APPROVED_STATES)
        rejected = sum(1 for r in records if _state(r) in _REJECTED_STATES)
        other = len(records) - approved - rejected

        if len(records) == 0:
            message = (
                f"No change_request records matched on ServiceNow instance "
                f"{self._instance} (query: {self._query or 'all'})."
            )
            status_id = 0
        else:
            message = (
                f"ServiceNow change-management posture on {self._instance}: "
                f"{len(records)} record(s) — {approved} Approved, "
                f"{rejected} Rejected, {other} other."
            )
            status_id = 1 if approved > 0 else 2

        md = _metadata(self._instance, uid)
        md["change_total"] = len(records)
        md["change_approved"] = approved
        md["change_rejected"] = rejected
        md["change_other"] = other
        md["query"] = self._query

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
        yield self._change_management_finding()


def _state(record: dict) -> str:
    state = record.get("state") if isinstance(record, dict) else None
    return state if isinstance(state, str) else ""
