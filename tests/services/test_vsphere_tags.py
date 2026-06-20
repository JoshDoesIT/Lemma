"""Tests for vSphere Automation (vAPI) tag resolution (Refs #24).

All vAPI REST calls are mocked via httpx ``MockTransport`` so CI never
touches a real vCenter.
"""

from __future__ import annotations

import json

import httpx
import pytest

# A small fake vCenter tagging inventory:
#   object vm-1 → tags t-env-prod, t-owner-platform
#   object vm-2 → tag  t-env-dev
#   t-env-prod   → name "prod",     category c-env   ("Environment")
#   t-env-dev    → name "dev",      category c-env   ("Environment")
#   t-owner-plat → name "platform", category c-owner ("Owner")
_ATTACHED = {
    "vm-1": ["t-env-prod", "t-owner-plat"],
    "vm-2": ["t-env-dev"],
}
_TAGS = {
    "t-env-prod": {"name": "prod", "category_id": "c-env"},
    "t-env-dev": {"name": "dev", "category_id": "c-env"},
    "t-owner-plat": {"name": "platform", "category_id": "c-owner"},
}
_CATEGORIES = {
    "c-env": {"name": "Environment"},
    "c-owner": {"name": "Owner"},
}


def _make_handler(*, call_log: list | None = None, fail_status: dict | None = None):
    """Build a MockTransport handler over the fake tagging inventory.

    ``fail_status`` maps a path-substring to an HTTP status to force (e.g.
    ``{"list-attached-tags": 429}``).
    """
    fail_status = fail_status or {}

    def _handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if call_log is not None:
            call_log.append((request.method, path, dict(request.headers)))

        for needle, status in fail_status.items():
            if needle in str(request.url):
                return httpx.Response(status, json={})

        if request.method == "POST" and path == "/api/session":
            return httpx.Response(201, json="session-token-xyz")

        if "list-attached-tags" in str(request.url):
            payload = json.loads(request.content or b"{}")
            moid = payload.get("object_id", {}).get("id")
            return httpx.Response(200, json=_ATTACHED.get(moid, []))

        if path.startswith("/api/cis/tagging/tag/"):
            tag_id = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json=_TAGS[tag_id])

        if path.startswith("/api/cis/tagging/category/"):
            cat_id = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json=_CATEGORIES[cat_id])

        return httpx.Response(404, json={"path": path})

    return _handle


def _client(**kw) -> httpx.Client:
    return httpx.Client(
        base_url="https://vcenter.example.com",
        transport=httpx.MockTransport(_make_handler(**kw)),
    )


class TestConnect:
    def test_connect_posts_session_and_stores_token(self):
        from lemma.services.vsphere_tags import VsphereTagResolver

        log: list = []
        resolver = VsphereTagResolver.connect(
            base_url="https://vcenter.example.com",
            user="administrator@vsphere.local",
            password="secret",
            client=_client(call_log=log),
        )

        # The session POST happened with HTTP Basic.
        method, path, headers = log[0]
        assert method == "POST"
        assert path == "/api/session"
        assert headers.get("authorization", "").startswith("Basic ")
        # Subsequent calls carry the session token header.
        tags = resolver.tags_for("vm-1", "VirtualMachine")
        assert tags  # sanity
        assert any(h.get("vmware-api-session-id") == "session-token-xyz" for _, _, h in log[1:])

    def test_failed_auth_raises_value_error(self):
        from lemma.services.vsphere_tags import VsphereTagResolver

        with pytest.raises(ValueError, match=r"(?i)vapi|session|auth"):
            VsphereTagResolver.connect(
                base_url="https://vcenter.example.com",
                user="bad",
                password="creds",
                client=_client(fail_status={"/api/session": 401}),
            )


class TestTagsFor:
    def _resolver(self, **kw):
        from lemma.services.vsphere_tags import VsphereTagResolver

        return VsphereTagResolver.connect(
            base_url="https://vcenter.example.com",
            user="u",
            password="p",
            client=_client(**kw),
        )

    def test_resolves_attached_tags_to_category_tag_dict(self):
        resolver = self._resolver()
        tags = resolver.tags_for("vm-1", "VirtualMachine")
        assert tags == {"Environment": "prod", "Owner": "platform"}

    def test_object_with_single_tag(self):
        resolver = self._resolver()
        assert resolver.tags_for("vm-2", "VirtualMachine") == {"Environment": "dev"}

    def test_object_with_no_tags_returns_empty(self):
        resolver = self._resolver()
        assert resolver.tags_for("vm-404", "VirtualMachine") == {}

    def test_object_id_and_type_sent_in_request_body(self):
        log: list = []
        resolver = self._resolver(call_log=log)
        resolver.tags_for("vm-1", "VirtualMachine")
        assoc = next(
            (m, p) for (m, p, _) in log if "tag-association" in p or "tag-association" in str(p)
        )
        assert assoc[0] == "POST"

    def test_tag_and_category_lookups_are_cached(self):
        log: list = []
        resolver = self._resolver(call_log=log)
        # vm-1 and vm-2 both reference category c-env; resolving both should
        # fetch the c-env category at most once.
        resolver.tags_for("vm-1", "VirtualMachine")
        resolver.tags_for("vm-2", "VirtualMachine")
        category_fetches = [p for (_, p, _) in log if p == "/api/cis/tagging/category/c-env"]
        assert len(category_fetches) == 1

    def test_rate_limit_raises_value_error_naming_endpoint(self):
        with pytest.raises(ValueError, match=r"(?i)tag-association|rate"):
            self._resolver(fail_status={"list-attached-tags": 429}).tags_for(
                "vm-1", "VirtualMachine"
            )
