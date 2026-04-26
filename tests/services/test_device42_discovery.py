"""Tests for Device42 CMDB discovery (Refs #24).

Uses ``httpx.MockTransport`` per the GitHub / ServiceNow connector test
pattern. No real Device42 API traffic in CI.
"""

from __future__ import annotations

import httpx
import pytest


def _device(
    *,
    device_id: int,
    name: str = "host-1",
    type_: str = "physical",
    service_level: str = "production",
    tags: object = "",
    custom_fields: list[dict] | None = None,
    extra: dict | None = None,
) -> dict:
    row = {
        "device_id": device_id,
        "name": name,
        "type": type_,
        "service_level": service_level,
        "tags": tags,
        "custom_fields": custom_fields or [],
    }
    if extra:
        row.update(extra)
    return row


def _client_with(handler) -> httpx.Client:
    return httpx.Client(
        base_url="https://d42.example.com",
        transport=httpx.MockTransport(handler),
    )


class TestSingleDevice:
    def test_emits_resource_definition_with_host_in_id(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "Devices": [
                        _device(
                            device_id=42,
                            name="web-1",
                            type_="physical",
                            service_level="production",
                        )
                    ],
                    "limit": 1000,
                    "offset": 0,
                    "total_count": 1,
                },
            )

        result = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "device42-d42.example.com-42"
        assert rd.type == "device42.physical"
        assert rd.attributes["device42"]["url"] == "https://d42.example.com"
        assert rd.attributes["device42"]["device_id"] == 42
        assert rd.attributes["device42"]["name"] == "web-1"
        assert rd.attributes["device42"]["service_level"] == "production"


class TestMultipleTypes:
    def test_distinct_types_per_device_type_field(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "Devices": [
                        _device(device_id=1, type_="physical"),
                        _device(device_id=2, type_="virtual"),
                        _device(device_id=3, type_="cluster"),
                    ],
                    "total_count": 3,
                },
            )

        result = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
        )

        types = {r.type for r in result}
        assert types == {"device42.physical", "device42.virtual", "device42.cluster"}


class TestCustomFields:
    def test_custom_fields_array_normalized_to_dict(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "Devices": [
                        _device(
                            device_id=10,
                            custom_fields=[
                                {"key": "environment", "value": "prod"},
                                {"key": "owner", "value": "platform-team"},
                                {"key": "data_center", "value": "dc-east"},
                            ],
                        )
                    ],
                    "total_count": 1,
                },
            )

        rd = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
        )[0]

        assert rd.attributes["device42"]["custom_fields"]["environment"] == "prod"
        assert rd.attributes["device42"]["custom_fields"]["owner"] == "platform-team"
        assert rd.attributes["device42"]["custom_fields"]["data_center"] == "dc-east"


class TestPagination:
    def test_total_count_drives_two_page_walk(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        page_size = 3
        seen_offsets: list[int] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            offset = int(request.url.params.get("offset", "0"))
            seen_offsets.append(offset)
            if offset == 0:
                page = [_device(device_id=i) for i in range(page_size)]
            else:
                page = [_device(device_id=100 + i) for i in range(2)]
            return httpx.Response(
                200,
                json={"Devices": page, "limit": page_size, "offset": offset, "total_count": 5},
            )

        result = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
            limit=page_size,
        )

        assert len(result) == 5
        assert seen_offsets == [0, 3]


class TestEmptyAndMalformed:
    def test_empty_result_returns_empty_list(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"Devices": [], "total_count": 0, "limit": 1000, "offset": 0}
            )

        assert (
            discover_resources_from_device42(
                client=_client_with(_handler),
                url="https://d42.example.com",
            )
            == []
        )

    def test_row_missing_device_id_silently_skipped(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "Devices": [
                        _device(device_id=1),
                        {"name": "ghost", "type": "physical"},  # no device_id
                        _device(device_id=2),
                    ],
                    "total_count": 3,
                },
            )

        result = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
        )

        assert len(result) == 2
        ids = {r.id for r in result}
        assert ids == {"device42-d42.example.com-1", "device42-d42.example.com-2"}


class TestTagsPreservedVerbatim:
    def test_string_tags_preserved(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "Devices": [_device(device_id=7, tags="prod,critical,monitored")],
                    "total_count": 1,
                },
            )

        rd = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
        )[0]
        assert rd.attributes["device42"]["tags"] == "prod,critical,monitored"

    def test_list_tags_preserved(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "Devices": [_device(device_id=8, tags=["prod", "critical", "monitored"])],
                    "total_count": 1,
                },
            )

        rd = discover_resources_from_device42(
            client=_client_with(_handler),
            url="https://d42.example.com",
        )[0]
        assert rd.attributes["device42"]["tags"] == ["prod", "critical", "monitored"]


class TestErrorHandling:
    def test_http_401_surfaces_as_value_error(self):
        from lemma.services.device42_discovery import discover_resources_from_device42

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"msg": "Unauthorized"})

        with pytest.raises(ValueError, match=r"(?i)401|auth|device42"):
            discover_resources_from_device42(
                client=_client_with(_handler),
                url="https://d42.example.com",
            )
