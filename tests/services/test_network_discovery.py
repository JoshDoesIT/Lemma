"""Tests for network CIDR-sweep discovery (Refs #24).

The scan function is injected so tests never shell out to nmap. The
matching production wrapper lives in
``lemma.commands.scope._build_network_scanner`` and exercises nmap +
xml.etree.ElementTree.
"""

from __future__ import annotations

from typing import Any

import pytest


def _fake_scan(*, hosts: dict[str, dict] | None = None, raises: Exception | None = None):
    def _scan(cidrs: list[str], ports: list[int]) -> dict[str, dict]:
        if raises is not None:
            raise raises
        return hosts or {}

    return _scan


class TestSingleHost:
    def test_emits_resource_definition_with_ip_in_id(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(
            hosts={
                "10.0.0.5": {"hostname": "web-1.internal", "open_ports": [22, 80, 443]},
            }
        )

        result = discover_resources_from_network(
            scan_function=scan,
            cidrs=["10.0.0.0/24"],
            ports=[22, 80, 443],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "network-10.0.0.5"
        assert rd.type == "network.host"
        assert rd.attributes["network"]["ip"] == "10.0.0.5"
        assert rd.attributes["network"]["hostname"] == "web-1.internal"
        assert rd.attributes["network"]["open_ports"] == [22, 80, 443]
        assert "scan_label" not in rd.attributes["network"]


class TestMultipleHosts:
    def test_distinct_ips_produce_distinct_ids(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(
            hosts={
                "10.0.0.5": {"hostname": "web-1", "open_ports": [80]},
                "10.0.0.6": {"hostname": "web-2", "open_ports": [80]},
                "10.0.0.7": {"hostname": None, "open_ports": []},
            }
        )

        result = discover_resources_from_network(
            scan_function=scan, cidrs=["10.0.0.0/24"], ports=[80]
        )

        ids = {r.id for r in result}
        assert ids == {"network-10.0.0.5", "network-10.0.0.6", "network-10.0.0.7"}


class TestEdgeCases:
    def test_host_with_no_open_ports_keeps_empty_list(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(hosts={"10.0.0.9": {"hostname": "quiet-host", "open_ports": []}})

        rd = discover_resources_from_network(scan_function=scan, cidrs=["10.0.0.0/24"], ports=[22])[
            0
        ]

        assert rd.attributes["network"]["open_ports"] == []

    def test_host_with_no_reverse_dns_keeps_none(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(hosts={"10.0.0.10": {"hostname": None, "open_ports": [443]}})

        rd = discover_resources_from_network(
            scan_function=scan, cidrs=["10.0.0.0/24"], ports=[443]
        )[0]

        assert rd.attributes["network"]["hostname"] is None


class TestLabel:
    def test_label_present_is_baked_into_id_and_attrs(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(hosts={"10.0.0.5": {"hostname": "rdp-host", "open_ports": [3389]}})

        rd = discover_resources_from_network(
            scan_function=scan,
            cidrs=["10.0.0.0/24"],
            ports=[3389],
            label="prod-vlan",
        )[0]

        assert rd.id == "network-prod-vlan-10.0.0.5"
        assert rd.attributes["network"]["scan_label"] == "prod-vlan"

    def test_label_absent_omits_label_key(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(hosts={"10.0.0.5": {"hostname": "h", "open_ports": []}})

        rd = discover_resources_from_network(
            scan_function=scan,
            cidrs=["10.0.0.0/24"],
            ports=[],
            label=None,
        )[0]

        assert rd.id == "network-10.0.0.5"
        assert "scan_label" not in rd.attributes["network"]


class TestMultiCidr:
    def test_multiple_cidrs_forwarded_and_all_hosts_emitted(self):
        from lemma.services.network_discovery import discover_resources_from_network

        captured_cidrs: list[list[str]] = []

        def _scan(cidrs: list[str], ports: list[int]) -> dict[str, dict]:
            captured_cidrs.append(list(cidrs))
            return {
                "10.0.0.5": {"hostname": "a", "open_ports": []},
                "10.0.1.5": {"hostname": "b", "open_ports": []},
            }

        result = discover_resources_from_network(
            scan_function=_scan,
            cidrs=["10.0.0.0/24", "10.0.1.0/24"],
            ports=[80],
        )

        assert captured_cidrs == [["10.0.0.0/24", "10.0.1.0/24"]]
        assert {r.id for r in result} == {"network-10.0.0.5", "network-10.0.1.5"}


class TestValidation:
    def test_empty_cidrs_raises_value_error(self):
        from lemma.services.network_discovery import discover_resources_from_network

        with pytest.raises(ValueError, match=r"(?i)at least one|empty|cidr"):
            discover_resources_from_network(
                scan_function=_fake_scan(),
                cidrs=[],
                ports=[80],
            )

    def test_invalid_cidr_string_raises_naming_the_value(self):
        from lemma.services.network_discovery import discover_resources_from_network

        with pytest.raises(ValueError, match=r"not-a-cidr"):
            discover_resources_from_network(
                scan_function=_fake_scan(),
                cidrs=["10.0.0.0/24", "not-a-cidr"],
                ports=[80],
            )


class TestPrivilegedMode:
    """Service consumes whatever shape `scan_function` emits.

    The CLI wires `--privileged` into the scan function returned by
    `_build_network_scanner`; the service projects whatever extra fields
    (`os`, `mac`) appear on each host record.
    """

    def test_os_match_derives_fine_grained_type_and_attrs(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(
            hosts={
                "10.0.0.5": {
                    "hostname": "web-1",
                    "open_ports": [22, 80],
                    "os": {"name": "Linux 5.x", "family": "linux", "accuracy": 95},
                    "mac": "aa:bb:cc:dd:ee:ff",
                }
            }
        )

        rd = discover_resources_from_network(
            scan_function=scan, cidrs=["10.0.0.0/24"], ports=[22, 80]
        )[0]

        assert rd.type == "network.host.linux"
        assert rd.attributes["network"]["os"] == {
            "name": "Linux 5.x",
            "family": "linux",
            "accuracy": 95,
        }
        assert rd.attributes["network"]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_no_os_match_falls_back_to_bare_type_and_omits_keys(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(
            hosts={
                "10.0.0.6": {
                    "hostname": "h",
                    "open_ports": [443],
                    "os": None,
                    "mac": None,
                }
            }
        )

        rd = discover_resources_from_network(
            scan_function=scan, cidrs=["10.0.0.0/24"], ports=[443]
        )[0]

        assert rd.type == "network.host"
        assert "os" not in rd.attributes["network"]
        assert "mac" not in rd.attributes["network"]


class TestServiceVersionDetection:
    def test_services_dict_projects_per_port_when_present(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(
            hosts={
                "10.0.0.5": {
                    "hostname": "web-1",
                    "open_ports": [22, 80],
                    "services": {
                        "22": {"name": "ssh", "product": "OpenSSH", "version": "9.0p1"},
                        "80": {"name": "http", "product": "nginx", "version": "1.24.0"},
                    },
                }
            }
        )

        rd = discover_resources_from_network(
            scan_function=scan, cidrs=["10.0.0.0/24"], ports=[22, 80]
        )[0]

        assert rd.attributes["network"]["open_ports"] == [22, 80]
        assert rd.attributes["network"]["services"] == {
            "22": {"name": "ssh", "product": "OpenSSH", "version": "9.0p1"},
            "80": {"name": "http", "product": "nginx", "version": "1.24.0"},
        }

    def test_services_key_omitted_when_scan_returns_none(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(
            hosts={"10.0.0.5": {"hostname": "h", "open_ports": [80], "services": None}}
        )

        rd = discover_resources_from_network(scan_function=scan, cidrs=["10.0.0.0/24"], ports=[80])[
            0
        ]

        assert "services" not in rd.attributes["network"]


class TestIPv6:
    def test_v6_mode_accepts_v6_cidr_and_brackets_id(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(hosts={"2001:db8::1": {"hostname": "v6-host", "open_ports": [80]}})

        rd = discover_resources_from_network(
            scan_function=scan,
            cidrs=["2001:db8::/64"],
            ports=[80],
            ipv6=True,
        )[0]

        assert rd.id == "network-[2001:db8::1]"
        assert rd.attributes["network"]["ip"] == "2001:db8::1"

    def test_v6_mode_with_label_brackets_id_and_keeps_label(self):
        from lemma.services.network_discovery import discover_resources_from_network

        scan = _fake_scan(hosts={"2001:db8::1": {"hostname": None, "open_ports": []}})

        rd = discover_resources_from_network(
            scan_function=scan,
            cidrs=["2001:db8::/64"],
            ports=[],
            label="prod-v6",
            ipv6=True,
        )[0]

        assert rd.id == "network-prod-v6-[2001:db8::1]"

    def test_v6_mode_rejects_v4_cidr(self):
        from lemma.services.network_discovery import discover_resources_from_network

        with pytest.raises(ValueError, match=r"10\.0\.0\.0/24"):
            discover_resources_from_network(
                scan_function=_fake_scan(),
                cidrs=["2001:db8::/64", "10.0.0.0/24"],
                ports=[80],
                ipv6=True,
            )

    def test_v4_mode_rejects_v6_cidr(self):
        from lemma.services.network_discovery import discover_resources_from_network

        with pytest.raises(ValueError, match=r"2001:db8::/64.*--ipv6"):
            discover_resources_from_network(
                scan_function=_fake_scan(),
                cidrs=["10.0.0.0/24", "2001:db8::/64"],
                ports=[80],
            )


class TestParser:
    def test_parse_nmap_xml_filters_down_and_ipv6_hosts(self):
        from lemma.commands.scope import _parse_nmap_xml

        xml: Any = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web-1.internal" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="3389"><state state="closed"/></port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.99" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
"""

        result = _parse_nmap_xml(xml)

        assert result == {
            "10.0.0.5": {
                "hostname": "web-1.internal",
                "open_ports": [22, 80],
                "os": None,
                "mac": None,
                "services": None,
            },
        }

    def test_parse_nmap_xml_extracts_os_match_and_mac(self):
        from lemma.commands.scope import _parse_nmap_xml

        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell"/>
    <ports/>
    <os>
      <osmatch name="Linux 5.4 - 5.15" accuracy="98">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X"/>
      </osmatch>
      <osmatch name="Linux 4.x" accuracy="89">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X"/>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""

        result = _parse_nmap_xml(xml)

        assert result["10.0.0.5"]["os"] == {
            "name": "Linux 5.4 - 5.15",
            "family": "linux",
            "accuracy": 98,
        }
        assert result["10.0.0.5"]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_parse_nmap_xml_extracts_service_banners(self):
        from lemma.commands.scope import _parse_nmap_xml

        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

        result = _parse_nmap_xml(xml)

        assert result["10.0.0.5"]["services"] == {
            "22": {"name": "ssh", "product": "OpenSSH", "version": "9.0p1"},
        }
        assert result["10.0.0.5"]["open_ports"] == [22, 80]

    def test_parse_nmap_xml_picks_up_v6_when_v6_mode(self):
        from lemma.commands.scope import _parse_nmap_xml

        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""

        result = _parse_nmap_xml(xml, ipv6=True)

        assert "2001:db8::1" in result
        assert "10.0.0.5" not in result
        assert result["2001:db8::1"]["open_ports"] == [80]
