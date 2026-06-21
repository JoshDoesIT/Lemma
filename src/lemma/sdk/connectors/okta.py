"""First-party Okta connector.

Emits OCSF compliance evidence for identity-governance posture that
matters to auditors:

- MFA enrollment policy — one ``ComplianceFinding`` describing the
  presence (or absence) of an active MFA enrollment policy.
- SSO applications — one ``ComplianceFinding`` with active-vs-total
  app counts on ``metadata``.

Auth: a required Okta API token (env ``LEMMA_OKTA_TOKEN`` or
constructor ``token=...``). Okta has no unauthenticated mode; missing
a token is a loud error at construction time, not a cryptic 401 later.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches a real Okta domain.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import AuthenticationEvent, ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "Okta"
_AUTH_WINDOW_HOURS = 24


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(domain: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Okta, Inc.", "uid": uid},
        "domain": domain,
        "uid": uid,
    }


class OktaConnector(Connector):
    """Collect identity-governance posture from an Okta org."""

    def __init__(
        self,
        *,
        domain: str,
        client: httpx.Client | None = None,
        token: str | None = None,
    ) -> None:
        self._domain = domain
        self._token = token or os.environ.get("LEMMA_OKTA_TOKEN") or None
        if not self._token:
            msg = (
                "OktaConnector requires an API token. "
                "Set LEMMA_OKTA_TOKEN in the environment or pass token=... to the constructor."
            )
            raise ValueError(msg)

        self._client = client or httpx.Client(base_url=f"https://{domain}")

        self.manifest = ConnectorManifest(
            name="okta",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "Okta org posture: MFA enrollment policy, SSO application inventory, "
                "user-lifecycle inventory, group/admin rosters, password policy, "
                "and recent authentication events."
            ),
            capabilities=[
                "mfa-policy",
                "sso-apps",
                "user-inventory",
                "groups",
                "password-policy",
                "auth-events",
            ],
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"SSWS {self._token}",
        }

    def _get(self, path: str) -> httpx.Response:
        response = self._client.get(path, headers=self._headers())
        if response.status_code == 429:
            msg = (
                f"Okta API rate-limit exceeded while fetching {path}. Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _mfa_policy_finding(self) -> ComplianceFinding:
        response = self._get("/api/v1/policies?type=MFA_ENROLL")
        uid = f"okta:mfa-policy:{self._domain}:{_today_utc_iso_date()}"

        policies = response.json() if response.is_success else []
        if not isinstance(policies, list):
            policies = []

        active = [p for p in policies if p.get("status") == "ACTIVE"]

        if active:
            names = ", ".join(p.get("name", "(unnamed)") for p in active)
            message = f"Okta MFA enrollment policy active ({len(active)}): {names}."
            status_id = 1
        else:
            message = f"No active MFA enrollment policy on Okta domain {self._domain}."
            status_id = 2

        md = _metadata(self._domain, uid)
        md["active_policy_count"] = len(active)
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

    def _sso_apps_finding(self) -> ComplianceFinding:
        response = self._get("/api/v1/apps")
        uid = f"okta:sso-apps:{self._domain}:{_today_utc_iso_date()}"

        apps = response.json() if response.is_success else []
        if not isinstance(apps, list):
            apps = []

        active_count = sum(1 for a in apps if a.get("status") == "ACTIVE")
        total_count = len(apps)

        message = (
            f"Okta SSO application inventory on {self._domain}: "
            f"{active_count} active, {total_count} total."
        )

        md = _metadata(self._domain, uid)
        md["active_count"] = active_count
        md["total_count"] = total_count

        return ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200301,
            activity_id=1,
            time=datetime.now(UTC),
            message=message,
            status_id=1 if total_count > 0 else 0,
            metadata=md,
        )

    def _user_inventory_finding(self) -> ComplianceFinding:
        response = self._get("/api/v1/users")
        uid = f"okta:user-inventory:{self._domain}:{_today_utc_iso_date()}"

        users = response.json() if response.is_success else []
        if not isinstance(users, list):
            users = []

        def _count(status: str) -> int:
            return sum(1 for u in users if isinstance(u, dict) and u.get("status") == status)

        active = _count("ACTIVE")
        suspended = _count("SUSPENDED")
        deprovisioned = _count("DEPROVISIONED")
        total = len(users)

        if not response.is_success:
            message = (
                f"Failed to read user inventory for Okta domain {self._domain} "
                f"(HTTP {response.status_code})."
            )
            status_id = 0
        else:
            message = (
                f"Okta user inventory on {self._domain}: {active} active, "
                f"{suspended} suspended, {deprovisioned} deprovisioned ({total} total)."
            )
            status_id = 1 if total > 0 else 0

        md = _metadata(self._domain, uid)
        md["active_count"] = active
        md["suspended_count"] = suspended
        md["deprovisioned_count"] = deprovisioned
        md["total_count"] = total

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

    def _groups_finding(self) -> ComplianceFinding:
        response = self._get("/api/v1/groups")
        uid = f"okta:groups:{self._domain}:{_today_utc_iso_date()}"

        groups = response.json() if response.is_success else []
        if not isinstance(groups, list):
            groups = []

        def _name(group: dict) -> str:
            profile = group.get("profile") if isinstance(group, dict) else None
            if isinstance(profile, dict):
                name = profile.get("name")
                if isinstance(name, str):
                    return name
            return ""

        admin_groups = [
            _name(g) for g in groups if isinstance(g, dict) and "admin" in _name(g).lower()
        ]

        if not response.is_success:
            message = (
                f"Failed to read groups for Okta domain {self._domain} "
                f"(HTTP {response.status_code})."
            )
            status_id = 0
        else:
            message = (
                f"Okta groups on {self._domain}: {len(groups)} total, "
                f"{len(admin_groups)} privileged (admin) group(s)."
            )
            status_id = 1 if groups else 0

        md = _metadata(self._domain, uid)
        md["group_count"] = len(groups)
        md["admin_group_count"] = len(admin_groups)
        md["admin_groups"] = admin_groups

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

    def _password_policy_finding(self) -> ComplianceFinding:
        response = self._get("/api/v1/policies?type=PASSWORD")
        uid = f"okta:password-policy:{self._domain}:{_today_utc_iso_date()}"

        policies = response.json() if response.is_success else []
        if not isinstance(policies, list):
            policies = []

        active = [p for p in policies if isinstance(p, dict) and p.get("status") == "ACTIVE"]

        if not response.is_success:
            message = (
                f"Failed to read password policy for Okta domain {self._domain} "
                f"(HTTP {response.status_code})."
            )
            status_id = 0
        elif active:
            names = ", ".join(p.get("name", "(unnamed)") for p in active)
            message = f"Okta password policy active ({len(active)}): {names}."
            status_id = 1
        else:
            message = f"No active password policy on Okta domain {self._domain}."
            status_id = 2

        md = _metadata(self._domain, uid)
        md["active_policy_count"] = len(active)
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

    def _auth_events_finding(self) -> AuthenticationEvent:
        # System Log API; the connector summarizes the recent window into one
        # rollup Authentication event so same-day re-runs dedupe by uid.
        response = self._get(f"/api/v1/logs?since=-{_AUTH_WINDOW_HOURS}h")
        uid = f"okta:auth-events:{self._domain}:{_today_utc_iso_date()}"

        events = response.json() if response.is_success else []
        if not isinstance(events, list):
            events = []

        def _result(entry: dict) -> str:
            outcome = entry.get("outcome") if isinstance(entry, dict) else None
            if isinstance(outcome, dict):
                return str(outcome.get("result", "")).upper()
            return ""

        success = sum(1 for e in events if _result(e) == "SUCCESS")
        failure = sum(1 for e in events if _result(e) == "FAILURE")

        if not response.is_success:
            message = (
                f"Failed to read the Okta System Log for {self._domain} "
                f"(HTTP {response.status_code}); authentication posture unknown."
            )
            status_id = 0
        else:
            message = (
                f"Okta authentication events on {self._domain} over the last "
                f"{_AUTH_WINDOW_HOURS}h: {success} succeeded, {failure} failed."
            )
            status_id = 1

        md = _metadata(self._domain, uid)
        md["success_count"] = success
        md["failure_count"] = failure
        md["window_hours"] = _AUTH_WINDOW_HOURS

        return AuthenticationEvent(
            class_name="Authentication",
            category_uid=3000,
            category_name="Identity & Access Management",
            type_uid=300201,
            activity_id=1,
            time=datetime.now(UTC),
            message=message,
            status_id=status_id,
            metadata=md,
        )

    def collect(self) -> Iterable[OcsfBaseEvent]:
        yield self._mfa_policy_finding()
        yield self._sso_apps_finding()
        yield self._user_inventory_finding()
        yield self._groups_finding()
        yield self._password_policy_finding()
        yield self._auth_events_finding()
