"""Tests for ServiceNow CMDB discovery (Refs #24).

Uses ``httpx.MockTransport`` per the GitHub connector test pattern. No real
ServiceNow API traffic in CI.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest


def _ci_row(
    *,
    sys_id: str,
    sys_class_name: str = "cmdb_ci_server",
    name: str = "host-1",
    extra: dict[str, Any] | None = None,
) -> dict:
    row = {
        "sys_id": sys_id,
        "sys_class_name": sys_class_name,
        "name": name,
        "operational_status": "1",
    }
    if extra:
        row.update(extra)
    return row


def _client_with(handler) -> httpx.Client:
    return httpx.Client(
        base_url="https://dev12345.service-now.com",
        transport=httpx.MockTransport(handler),
    )


class TestSingleCI:
    def test_emits_resource_definition_with_instance_in_id(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "result": [
                        _ci_row(
                            sys_id="abc123" + "0" * 26,
                            sys_class_name="cmdb_ci_server",
                            name="web-1",
                        )
                    ]
                },
            )

        result = discover_resources_from_servicenow(
            client=_client_with(_handler),
            instance="dev12345",
            ci_class="cmdb_ci",
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "snow-dev12345-abc123" + "0" * 26
        assert rd.type == "snow.cmdb_ci_server"
        assert rd.attributes["snow"]["instance"] == "dev12345"
        assert rd.attributes["snow"]["sys_id"] == "abc123" + "0" * 26
        assert rd.attributes["snow"]["sys_class_name"] == "cmdb_ci_server"
        assert rd.attributes["snow"]["name"] == "web-1"
        assert rd.attributes["snow"]["operational_status"] == "1"


class TestMultipleClasses:
    def test_distinct_types_per_sys_class_name(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "result": [
                        _ci_row(sys_id="s" * 32, sys_class_name="cmdb_ci_server"),
                        _ci_row(sys_id="d" * 32, sys_class_name="cmdb_ci_database"),
                        _ci_row(sys_id="a" * 32, sys_class_name="cmdb_ci_app_server"),
                    ]
                },
            )

        result = discover_resources_from_servicenow(
            client=_client_with(_handler),
            instance="dev",
            ci_class="cmdb_ci",
        )

        types = {r.type for r in result}
        assert types == {
            "snow.cmdb_ci_server",
            "snow.cmdb_ci_database",
            "snow.cmdb_ci_app_server",
        }


class TestCustomFields:
    def test_u_fields_preserved_verbatim(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "result": [
                        _ci_row(
                            sys_id="x" * 32,
                            extra={
                                "u_environment": "prod",
                                "u_owner": "platform-team",
                                "u_data_center": "dc-east",
                            },
                        )
                    ]
                },
            )

        rd = discover_resources_from_servicenow(
            client=_client_with(_handler),
            instance="dev",
            ci_class="cmdb_ci",
        )[0]

        assert rd.attributes["snow"]["u_environment"] == "prod"
        assert rd.attributes["snow"]["u_owner"] == "platform-team"
        assert rd.attributes["snow"]["u_data_center"] == "dc-east"


class TestPagination:
    def test_two_pages_combined_via_sysparm_offset(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        page_size = 3  # use a small page so the test is short
        page1 = [_ci_row(sys_id=f"{i:032x}") for i in range(page_size)]
        page2 = [_ci_row(sys_id=f"{i + 100:032x}") for i in range(2)]
        seen_offsets: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            offset = request.url.params.get("sysparm_offset", "0")
            seen_offsets.append(offset)
            if offset == "0":
                return httpx.Response(200, json={"result": page1})
            return httpx.Response(200, json={"result": page2})

        result = discover_resources_from_servicenow(
            client=_client_with(_handler),
            instance="dev",
            ci_class="cmdb_ci",
            page_size=page_size,
        )

        assert len(result) == 5
        # Two requests issued: offset=0 (full page) and offset=3 (partial page).
        assert seen_offsets == ["0", "3"]


class TestEmptyAndMalformed:
    def test_empty_result_returns_empty_list(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"result": []})

        assert (
            discover_resources_from_servicenow(
                client=_client_with(_handler),
                instance="dev",
                ci_class="cmdb_ci",
            )
            == []
        )

    def test_row_missing_sys_id_silently_skipped(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "result": [
                        _ci_row(sys_id="g" * 32),
                        {"sys_class_name": "cmdb_ci_server", "name": "ghost"},  # no sys_id
                        _ci_row(sys_id="h" * 32),
                    ]
                },
            )

        result = discover_resources_from_servicenow(
            client=_client_with(_handler),
            instance="dev",
            ci_class="cmdb_ci",
        )

        # Only the two well-formed rows are returned; the missing-sys_id row is silently dropped.
        assert len(result) == 2
        ids = {r.id for r in result}
        assert ids == {f"snow-dev-{'g' * 32}", f"snow-dev-{'h' * 32}"}


class TestCIClassRouting:
    def test_ci_class_reflected_in_request_path(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        seen_paths: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            seen_paths.append(request.url.path)
            return httpx.Response(200, json={"result": []})

        discover_resources_from_servicenow(
            client=_client_with(_handler),
            instance="dev",
            ci_class="cmdb_ci_server",
        )

        assert seen_paths == ["/api/now/table/cmdb_ci_server"]


class TestErrorHandling:
    def test_http_401_surfaces_as_value_error(self):
        from lemma.services.servicenow_discovery import discover_resources_from_servicenow

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": {"message": "User Not Authenticated"}})

        with pytest.raises(ValueError, match=r"(?i)401|auth|servicenow"):
            discover_resources_from_servicenow(
                client=_client_with(_handler),
                instance="dev",
                ci_class="cmdb_ci",
            )
