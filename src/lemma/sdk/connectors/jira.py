"""First-party Jira connector (Refs #115).

Pulls change-management evidence from a Jira Cloud site and emits one
``ComplianceFinding`` aggregating the approved / rejected breakdown
across recent change tickets — the auditable signal a SOC 2 CC8.1
review wants for change management.

Auth: Jira Cloud uses HTTP Basic with ``email:api_token``. The token
is required (set ``LEMMA_JIRA_TOKEN`` in the environment or pass
``token=...`` to the constructor); a missing token is a loud error at
construction time, not a cryptic 401 later.

The default JQL targets issues labeled ``change-management``. Operators
override via ``jql=...`` to scope (e.g. by project, time range,
component). The ``metadata.uid`` is stable per
``(site, UTC date)`` so same-day re-runs dedupe against themselves.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches a real Jira site.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "Jira"
_DEFAULT_JQL = 'labels = "change-management" ORDER BY created DESC'


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _site_from(base_url: str) -> str:
    """Extract the host portion of ``base_url`` for stable UIDs."""
    return urlparse(base_url).netloc or base_url


def _metadata(site: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Atlassian", "uid": uid},
        "site": site,
        "uid": uid,
    }


class JiraConnector(Connector):
    """Collect change-management posture from a Jira Cloud site."""

    def __init__(
        self,
        *,
        base_url: str,
        email: str | None = None,
        token: str | None = None,
        jql: str = _DEFAULT_JQL,
        client: httpx.Client | None = None,
    ) -> None:
        if not email:
            msg = (
                "JiraConnector requires an email (Jira Cloud uses HTTP Basic with "
                "email:api_token). Pass email=... to the constructor."
            )
            raise ValueError(msg)
        self._email = email
        self._token = token or os.environ.get("LEMMA_JIRA_TOKEN") or None
        if not self._token:
            msg = (
                "JiraConnector requires an API token. "
                "Set LEMMA_JIRA_TOKEN in the environment or pass token=... to the constructor."
            )
            raise ValueError(msg)

        self._base_url = base_url
        self._site = _site_from(base_url)
        self._jql = jql
        self._client = client or httpx.Client(base_url=base_url)

        self.manifest = ConnectorManifest(
            name="jira",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "Jira Cloud change-management posture: aggregate count of recent "
                "change tickets with approved/rejected breakdown."
            ),
            capabilities=["change-management"],
        )

    def _auth_header(self) -> str:
        creds = f"{self._email}:{self._token}".encode()
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
                f"Jira API rate-limit exceeded while fetching {path}. Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _change_management_finding(self) -> ComplianceFinding:
        # Jira's REST returns the issue list under `issues` and a total
        # under `total`. Fields we read: status.name and labels.
        response = self._get(
            "/rest/api/3/search",
            params={"jql": self._jql, "fields": "status,summary,labels"},
        )
        uid = f"jira:change-management:{self._site}:{_today_utc_iso_date()}"

        issues: list[dict] = []
        if response.is_success:
            payload = response.json()
            if isinstance(payload, dict):
                raw_issues = payload.get("issues")
                if isinstance(raw_issues, list):
                    issues = raw_issues

        approved = sum(1 for i in issues if _status_name(i) == "Approved")
        rejected = sum(1 for i in issues if _status_name(i) == "Rejected")
        other = len(issues) - approved - rejected

        if len(issues) == 0:
            message = (
                f"No change-management tickets matched JQL on Jira site {self._site} "
                f"(JQL: {self._jql})."
            )
            status_id = 0
        else:
            message = (
                f"Jira change-management posture on {self._site}: "
                f"{len(issues)} ticket(s) — {approved} Approved, "
                f"{rejected} Rejected, {other} other."
            )
            status_id = 1 if approved > 0 else 2

        md = _metadata(self._site, uid)
        md["change_total"] = len(issues)
        md["change_approved"] = approved
        md["change_rejected"] = rejected
        md["change_other"] = other
        md["jql"] = self._jql

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


def _status_name(issue: dict) -> str:
    fields = issue.get("fields") if isinstance(issue, dict) else None
    if not isinstance(fields, dict):
        return ""
    status = fields.get("status")
    if not isinstance(status, dict):
        return ""
    name = status.get("name")
    return name if isinstance(name, str) else ""
