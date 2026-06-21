"""First-party Azure connector (Refs #115).

Pulls compliance posture from Microsoft Entra ID + Azure Resource Manager
and emits OCSF ``ComplianceFinding`` events. Three findings per run,
mirroring the AWS connector's three-finding pattern:

1. **Entra ID MFA conditional-access posture** — at least one ENABLED
   conditional-access policy includes MFA as a grant control.
2. **Azure Activity Log retention** — diagnostic settings are present
   on the subscription (the surface that controls Activity Log
   capture and retention).
3. **Azure Policy assignments** — at least one Policy assignment is
   present on the subscription.

Auth: OAuth2 client-credentials flow against
``https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token``
with one access token cached per scope on the connector instance.
Two scopes are needed: ``https://graph.microsoft.com/.default`` for
the Entra ID call and ``https://management.azure.com/.default`` for
the Resource Manager calls.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches a real Azure tenant.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "Azure"

_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_ARM_SCOPE = "https://management.azure.com/.default"

_GRAPH_BASE = "https://graph.microsoft.com"
_ARM_BASE = "https://management.azure.com"


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(tenant_id: str, subscription_id: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Microsoft Corporation", "uid": uid},
        "tenant_id": tenant_id,
        "subscription_id": subscription_id,
        "uid": uid,
    }


class AzureConnector(Connector):
    """Collect tenant + subscription posture from a Microsoft Azure account."""

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        subscription_id: str,
        client_secret: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        if not tenant_id:
            msg = "AzureConnector requires a tenant_id (Entra ID directory id)."
            raise ValueError(msg)
        if not client_id:
            msg = "AzureConnector requires a client_id (App registration application id)."
            raise ValueError(msg)
        if not subscription_id:
            msg = "AzureConnector requires a subscription_id."
            raise ValueError(msg)
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._subscription_id = subscription_id
        self._client_secret = client_secret or os.environ.get("LEMMA_AZURE_CLIENT_SECRET") or None
        if not self._client_secret:
            msg = (
                "AzureConnector requires a client secret. Set "
                "LEMMA_AZURE_CLIENT_SECRET in the environment or pass "
                "client_secret=... to the constructor."
            )
            raise ValueError(msg)

        self._client = client or httpx.Client()
        self._token_cache: dict[str, str] = {}

        self.manifest = ConnectorManifest(
            name="azure",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "Azure tenant + subscription posture: Entra ID conditional-access "
                "MFA, Activity Log diagnostic settings, Azure Policy assignments."
            ),
            capabilities=[
                "entra-mfa-conditional-access",
                "activity-log-retention",
                "policy-assignments",
            ],
        )

    def _token_for(self, scope: str) -> str:
        if scope in self._token_cache:
            return self._token_cache[scope]
        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": scope,
        }
        response = self._client.post(url, data=data)
        if not response.is_success:
            msg = (
                f"Azure token endpoint returned {response.status_code} for scope "
                f"{scope}; check tenant_id, client_id, and client_secret."
            )
            raise ValueError(msg)
        try:
            payload = response.json()
        except ValueError as exc:
            msg = f"Azure token endpoint returned non-JSON body for scope {scope}."
            raise ValueError(msg) from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            msg = f"Azure token endpoint did not include an access_token for scope {scope}."
            raise ValueError(msg)
        self._token_cache[scope] = token
        return token

    def _get(self, url: str, *, scope: str) -> httpx.Response:
        token = self._token_for(scope)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        response = self._client.get(url, headers=headers)
        if response.status_code == 429:
            msg = (
                f"Azure API rate-limit exceeded while fetching {url}. Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _entra_mfa_finding(self) -> ComplianceFinding:
        url = f"{_GRAPH_BASE}/v1.0/identity/conditionalAccess/policies"
        response = self._get(url, scope=_GRAPH_SCOPE)
        uid = f"azure:entra-mfa:{self._tenant_id}:{self._subscription_id}:{_today_utc_iso_date()}"
        md = _metadata(self._tenant_id, self._subscription_id, uid)

        if not response.is_success:
            md["enabled_mfa_policy_count"] = 0
            md["total_policy_count"] = 0
            return ComplianceFinding(
                class_name="Compliance Finding",
                category_uid=2000,
                category_name="Findings",
                type_uid=200301,
                activity_id=1,
                time=datetime.now(UTC),
                message=(
                    f"Could not read Entra ID conditional-access policies on "
                    f"tenant {self._tenant_id} (HTTP {response.status_code})."
                ),
                status_id=0,
                metadata=md,
            )

        payload = response.json() if response.is_success else {}
        policies = payload.get("value", []) if isinstance(payload, dict) else []
        if not isinstance(policies, list):
            policies = []

        enabled_mfa = [p for p in policies if _is_enabled_mfa_policy(p)]

        if enabled_mfa:
            names = ", ".join(p.get("displayName", "(unnamed)") for p in enabled_mfa)
            message = (
                f"Entra ID conditional-access MFA enabled on tenant "
                f"{self._tenant_id} ({len(enabled_mfa)}): {names}."
            )
            status_id = 1
        else:
            message = (
                f"No enabled Entra ID conditional-access policy requires MFA on "
                f"tenant {self._tenant_id}."
            )
            status_id = 2

        md["enabled_mfa_policy_count"] = len(enabled_mfa)
        md["total_policy_count"] = len(policies)

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

    def _activity_log_retention_finding(self) -> ComplianceFinding:
        url = (
            f"{_ARM_BASE}/subscriptions/{self._subscription_id}/providers/"
            "Microsoft.Insights/diagnosticSettings"
            "?api-version=2021-05-01-preview"
        )
        response = self._get(url, scope=_ARM_SCOPE)
        uid = (
            f"azure:activity-log-retention:{self._tenant_id}:"
            f"{self._subscription_id}:{_today_utc_iso_date()}"
        )
        md = _metadata(self._tenant_id, self._subscription_id, uid)

        if not response.is_success:
            md["diagnostic_settings_count"] = 0
            return ComplianceFinding(
                class_name="Compliance Finding",
                category_uid=2000,
                category_name="Findings",
                type_uid=200301,
                activity_id=1,
                time=datetime.now(UTC),
                message=(
                    f"Could not read diagnostic settings on subscription "
                    f"{self._subscription_id} (HTTP {response.status_code})."
                ),
                status_id=0,
                metadata=md,
            )

        payload = response.json()
        settings = payload.get("value", []) if isinstance(payload, dict) else []
        if not isinstance(settings, list):
            settings = []

        count = len(settings)
        md["diagnostic_settings_count"] = count

        if count > 0:
            message = (
                f"Subscription {self._subscription_id} has {count} diagnostic "
                f"setting(s) capturing Activity Log."
            )
            status_id = 1
        else:
            message = (
                f"Subscription {self._subscription_id} has no diagnostic settings; "
                "Activity Log is not being captured to a durable destination."
            )
            status_id = 2

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

    def _policy_assignments_finding(self) -> ComplianceFinding:
        url = (
            f"{_ARM_BASE}/subscriptions/{self._subscription_id}/providers/"
            "Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        )
        response = self._get(url, scope=_ARM_SCOPE)
        uid = (
            f"azure:policy-assignments:{self._tenant_id}:"
            f"{self._subscription_id}:{_today_utc_iso_date()}"
        )
        md = _metadata(self._tenant_id, self._subscription_id, uid)

        if not response.is_success:
            md["assignment_count"] = 0
            return ComplianceFinding(
                class_name="Compliance Finding",
                category_uid=2000,
                category_name="Findings",
                type_uid=200301,
                activity_id=1,
                time=datetime.now(UTC),
                message=(
                    f"Could not read Azure Policy assignments on subscription "
                    f"{self._subscription_id} (HTTP {response.status_code})."
                ),
                status_id=0,
                metadata=md,
            )

        payload = response.json()
        assignments = payload.get("value", []) if isinstance(payload, dict) else []
        if not isinstance(assignments, list):
            assignments = []

        count = len(assignments)
        md["assignment_count"] = count

        if count > 0:
            message = (
                f"Subscription {self._subscription_id} has {count} Azure Policy assignment(s)."
            )
            status_id = 1
        else:
            message = (
                f"Subscription {self._subscription_id} has zero Azure Policy "
                "assignments; built-in initiatives are not in effect."
            )
            status_id = 2

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
        yield self._entra_mfa_finding()
        yield self._activity_log_retention_finding()
        yield self._policy_assignments_finding()


def _is_enabled_mfa_policy(policy: dict) -> bool:
    if not isinstance(policy, dict):
        return False
    if policy.get("state") != "enabled":
        return False
    grant_controls = policy.get("grantControls")
    if not isinstance(grant_controls, dict):
        return False
    built_in = grant_controls.get("builtInControls")
    if not isinstance(built_in, list):
        return False
    return any(isinstance(c, str) and c.lower() == "mfa" for c in built_in)
