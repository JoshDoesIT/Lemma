"""First-party Azure DevOps connector (Refs #115).

Pulls change-management evidence from an Azure DevOps project's work
items and emits one ``ComplianceFinding`` aggregating the approved /
rejected / in-flight breakdown across recent records — the same
SOC 2 CC8.1 audit signal the Jira (#206) and ServiceNow (#207)
connectors emit, on the same OCSF wire format so cross-tool
aggregation in ``lemma control-plane compliance`` (#204) groups
findings from all three under the same ``(framework, control_id)``
key.

Auth: Azure DevOps uses Personal Access Tokens (PATs) over HTTP Basic
with an empty username and the PAT as the password (the canonical
``Basic <base64(":" + PAT)>`` encoding). Token via
``LEMMA_AZURE_DEVOPS_TOKEN`` env var or ``token=...`` constructor arg.

The default WIQL query targets work items tagged
``change-management``. Operators override via ``wiql=...`` (the full
WIQL ``SELECT ... FROM workitems WHERE ...`` form) for per-area-path,
per-sprint, or per-process scoping.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches a real Azure DevOps organisation.
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

_PRODUCER = "Azure DevOps"
_DEFAULT_WIQL = (
    "SELECT [System.Id], [System.State] FROM workitems "
    "WHERE [System.Tags] CONTAINS 'change-management'"
)
_API_VERSION = "7.0"

# Default-process state names. Orgs running a custom process should
# pre-filter via ``wiql`` to states they care about; the bucket counts
# still add up to the work-item total.
_APPROVED_STATES = {"Closed", "Done", "Completed", "Resolved"}
_REJECTED_STATES = {"Removed", "Cancelled"}


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(organization: str, project: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Microsoft", "uid": uid},
        "organization": organization,
        "project": project,
        "uid": uid,
    }


class AzureDevOpsConnector(Connector):
    """Collect change-management posture from an Azure DevOps project."""

    def __init__(
        self,
        *,
        organization: str,
        project: str,
        token: str | None = None,
        wiql: str = _DEFAULT_WIQL,
        client: httpx.Client | None = None,
    ) -> None:
        if not organization:
            msg = (
                "AzureDevOpsConnector requires an organization "
                "(the path segment after dev.azure.com/)."
            )
            raise ValueError(msg)
        if not project:
            msg = "AzureDevOpsConnector requires a project (within the organization)."
            raise ValueError(msg)
        self._organization = organization
        self._project = project
        self._token = token or os.environ.get("LEMMA_AZURE_DEVOPS_TOKEN") or None
        if not self._token:
            msg = (
                "AzureDevOpsConnector requires a Personal Access Token. "
                "Set LEMMA_AZURE_DEVOPS_TOKEN in the environment or pass "
                "token=... to the constructor."
            )
            raise ValueError(msg)

        self._wiql = wiql
        self._client = client or httpx.Client(base_url="https://dev.azure.com")

        self.manifest = ConnectorManifest(
            name="azure-devops",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "Azure DevOps change-management posture: aggregate count of "
                "recent work items with approved/rejected breakdown."
            ),
            capabilities=["change-management"],
        )

    def _auth_header(self) -> str:
        # Azure DevOps PAT auth: empty username, PAT as password.
        creds = f":{self._token}".encode()
        return "Basic " + base64.b64encode(creds).decode()

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "Authorization": self._auth_header(),
        }
        if content_type:
            h["Content-Type"] = content_type
        return h

    def _post_wiql(self) -> httpx.Response:
        path = f"/{self._organization}/{self._project}/_apis/wit/wiql"
        response = self._client.post(
            path,
            headers=self._headers("application/json"),
            params={"api-version": _API_VERSION},
            json={"query": self._wiql},
        )
        if response.status_code == 429:
            msg = (
                f"Azure DevOps API rate-limit exceeded while POSTing {path}. "
                "Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _get_workitems(self, ids: list[int]) -> httpx.Response:
        path = f"/{self._organization}/_apis/wit/workitems"
        response = self._client.get(
            path,
            headers=self._headers(),
            params={
                "ids": ",".join(str(i) for i in ids),
                "fields": "System.Id,System.State",
                "api-version": _API_VERSION,
            },
        )
        if response.status_code == 429:
            msg = (
                f"Azure DevOps API rate-limit exceeded while fetching {path}. "
                "Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _change_management_finding(self) -> ComplianceFinding:
        wiql_response = self._post_wiql()
        uid = (
            f"azure-devops:change-management:"
            f"{self._organization}/{self._project}:{_today_utc_iso_date()}"
        )

        ids: list[int] = []
        if wiql_response.is_success:
            payload = wiql_response.json()
            if isinstance(payload, dict):
                items = payload.get("workItems")
                if isinstance(items, list):
                    ids = [
                        i.get("id")
                        for i in items
                        if isinstance(i, dict) and isinstance(i.get("id"), int)
                    ]

        states: list[str] = []
        if ids:
            details = self._get_workitems(ids)
            if details.is_success:
                payload = details.json()
                if isinstance(payload, dict):
                    value = payload.get("value")
                    if isinstance(value, list):
                        states = [_state(item) for item in value]

        approved = sum(1 for s in states if s in _APPROVED_STATES)
        rejected = sum(1 for s in states if s in _REJECTED_STATES)
        other = len(ids) - approved - rejected

        if not ids:
            message = (
                f"No work items matched on Azure DevOps "
                f"{self._organization}/{self._project} (WIQL: {self._wiql})."
            )
            status_id = 0
        else:
            message = (
                f"Azure DevOps change-management posture on "
                f"{self._organization}/{self._project}: "
                f"{len(ids)} work item(s) — {approved} Approved, "
                f"{rejected} Rejected, {other} other."
            )
            status_id = 1 if approved > 0 else 2

        md = _metadata(self._organization, self._project, uid)
        md["change_total"] = len(ids)
        md["change_approved"] = approved
        md["change_rejected"] = rejected
        md["change_other"] = other
        md["wiql"] = self._wiql

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


def _state(item: dict) -> str:
    fields = item.get("fields") if isinstance(item, dict) else None
    if not isinstance(fields, dict):
        return ""
    state = fields.get("System.State")
    return state if isinstance(state, str) else ""
