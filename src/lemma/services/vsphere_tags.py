"""vSphere Automation (vAPI) tag resolution for scope discovery (Refs #24).

The legacy SOAP SDK (pyVmomi) used by ``vsphere_discovery`` projects only
vCenter **Custom Attributes** (``obj.customValue``). vSphere 6.0+ shops use
the modern **Tags + Categories** model, which lives behind the vSphere
Automation REST API (vAPI / ``cis.tagging``) and uses a *separate* session
from the SOAP SDK.

This module talks to those REST endpoints and resolves the tags attached to
a managed object (by managed-object id + type) into a ``{category: tag}``
dict, suitable for projection alongside the legacy custom-attribute tags.
Tag and category metadata are cached per resolver instance so a fleet-wide
discover doesn't refetch the same category name once per object.

Auth is HTTP Basic against ``POST /api/session``; the returned session id is
sent as the ``vmware-api-session-id`` header on every subsequent call.
Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI never
touches a real vCenter.
"""

from __future__ import annotations

import httpx

_SESSION_HEADER = "vmware-api-session-id"
_SESSION_PATH = "/api/session"
_TAG_ASSOC_PATH = "/api/cis/tagging/tag-association?action=list-attached-tags"
_TAG_PATH = "/api/cis/tagging/tag/"
_CATEGORY_PATH = "/api/cis/tagging/category/"


def _unwrap(payload: object) -> object:
    """vAPI responses come bare on ``/api`` and wrapped as ``{"value": ...}``
    on the legacy ``/rest`` surface; tolerate both."""
    if isinstance(payload, dict) and "value" in payload:
        return payload["value"]
    return payload


class VsphereTagResolver:
    """Resolve modern vSphere Tags for a managed object via the vAPI."""

    def __init__(self, *, client: httpx.Client, session_token: str) -> None:
        self._client = client
        self._client.headers[_SESSION_HEADER] = session_token
        # tag id -> (tag name, category id)
        self._tag_cache: dict[str, tuple[str, str]] = {}
        # category id -> category name
        self._category_cache: dict[str, str] = {}

    @classmethod
    def connect(
        cls,
        *,
        base_url: str,
        user: str,
        password: str,
        verify: bool = True,
        client: httpx.Client | None = None,
    ) -> VsphereTagResolver:
        """Open a vAPI session with HTTP Basic auth and return a resolver.

        ``verify=False`` skips TLS verification for lab vCenters with
        self-signed certs (mirrors the SOAP ``--insecure`` flag).
        """
        client = client or httpx.Client(base_url=base_url, verify=verify)
        response = client.post(_SESSION_PATH, auth=(user, password))
        if response.status_code not in (200, 201):
            msg = (
                f"vSphere vAPI session auth failed at {base_url} "
                f"(HTTP {response.status_code}). Verify the credentials and that "
                "the vCenter exposes the Automation (cis.tagging) REST API."
            )
            raise ValueError(msg)
        token = _unwrap(response.json())
        if not isinstance(token, str) or not token:
            msg = f"vSphere vAPI session at {base_url} returned no session id."
            raise ValueError(msg)
        return cls(client=client, session_token=token)

    def close(self) -> None:
        """Close the underlying HTTP client (drops the vAPI session)."""
        self._client.close()

    def tags_for(self, moid: str, vim_type: str) -> dict[str, str]:
        """Return ``{category_name: tag_name}`` for the tags attached to a
        managed object.

        ``vim_type`` is the vSphere managed-object type name the vAPI expects
        (``VirtualMachine`` / ``HostSystem`` / ``Datastore``). On a category
        with multiple attached tags the last one wins — the common
        single-cardinality case maps cleanly; multi-cardinality categories
        should be matched on the legacy custom-attribute projection instead.
        """
        out: dict[str, str] = {}
        for tag_id in self._list_attached_tags(moid, vim_type):
            name, category_id = self._tag(tag_id)
            out[self._category(category_id)] = name
        return out

    def _list_attached_tags(self, moid: str, vim_type: str) -> list[str]:
        response = self._client.post(
            _TAG_ASSOC_PATH,
            json={"object_id": {"id": moid, "type": vim_type}},
        )
        if response.status_code == 429:
            msg = (
                "vSphere vAPI rate-limit exceeded on tag-association "
                f"list-attached-tags for {vim_type} {moid}. Retry after the "
                "quota resets."
            )
            raise ValueError(msg)
        if not response.is_success:
            return []
        data = _unwrap(response.json())
        if not isinstance(data, list):
            return []
        return [t for t in data if isinstance(t, str)]

    def _tag(self, tag_id: str) -> tuple[str, str]:
        cached = self._tag_cache.get(tag_id)
        if cached is not None:
            return cached
        body = self._get_json(f"{_TAG_PATH}{tag_id}", endpoint="tag")
        result = (str(body.get("name", "")), str(body.get("category_id", "")))
        self._tag_cache[tag_id] = result
        return result

    def _category(self, category_id: str) -> str:
        cached = self._category_cache.get(category_id)
        if cached is not None:
            return cached
        body = self._get_json(f"{_CATEGORY_PATH}{category_id}", endpoint="category")
        name = str(body.get("name", category_id))
        self._category_cache[category_id] = name
        return name

    def _get_json(self, path: str, *, endpoint: str) -> dict:
        response = self._client.get(path)
        if response.status_code == 429:
            msg = f"vSphere vAPI rate-limit exceeded on {endpoint} ({path})."
            raise ValueError(msg)
        if not response.is_success:
            return {}
        unwrapped = _unwrap(response.json())
        return unwrapped if isinstance(unwrapped, dict) else {}


__all__ = ["VsphereTagResolver"]
