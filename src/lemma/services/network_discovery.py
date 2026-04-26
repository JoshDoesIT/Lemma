"""Network CIDR-sweep discovery for the scope engine (Refs #24).

Walks operator-supplied CIDR ranges via an injected ``scan_function`` and
yields a ``ResourceDefinition`` per discovered host — same shape every
other discovery service returns, so the scope-discover command feeds
network scans through the same matcher and graph-write loop as AWS /
k8s / GCP / Azure / Ansible / ServiceNow / Device42 / vSphere.

The injection seam (``scan_function``) lets tests skip the nmap
subprocess entirely. The production wrapper lives in
``lemma.commands.scope._build_network_scanner`` and shells out to nmap
then parses the ``-oX`` XML with stdlib ``xml.etree.ElementTree``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any

from lemma.models.resource import ResourceDefinition

ScanFunction = Callable[[list[str], list[int]], dict[str, dict[str, Any]]]

_OS_FAMILY_TO_TYPE_SUFFIX: dict[str, str] = {
    "linux": "linux",
    "windows": "windows",
    "macos": "macos",
    "mac os x": "macos",
    "freebsd": "bsd",
    "openbsd": "bsd",
    "netbsd": "bsd",
    "bsd": "bsd",
    "solaris": "solaris",
}


def discover_resources_from_network(
    *,
    scan_function: ScanFunction,
    cidrs: list[str],
    ports: list[int],
    label: str | None = None,
    ipv6: bool = False,
) -> list[ResourceDefinition]:
    """Discover live hosts across the requested CIDR(s).

    Args:
        scan_function: Callable taking ``(cidrs, ports)`` and returning a
            ``{ip: {hostname, open_ports, os?, mac?, services?}}`` dict.
            ``os`` / ``mac`` populate when ``--privileged`` is in effect on
            the wrapping CLI; ``services`` populates when
            ``--detect-versions`` is set. The service treats those fields
            as opt-in: ``None`` or missing means "not collected."
        cidrs: Non-empty list of CIDR strings. Each must parse via
            ``ipaddress.ip_network`` and match the family selected by
            ``ipv6`` (v4 in default mode, v6 when ``ipv6=True``).
        ports: TCP port numbers. Each must be in ``1..65535``. Empty list
            valid (host-discovery only).
        label: Optional tag baked into discovered ids
            (``network-<label>-<ip>`` for v4, bracket-wrapped for v6).
        ipv6: When ``True``, only v6 CIDRs are accepted and v6 host ids
            are bracket-wrapped (``network-[2001:db8::1]``). Otherwise
            v4-only.

    Returns:
        One ``ResourceDefinition`` per live host. ``type`` is
        ``network.host`` by default, or ``network.host.<family>`` when
        the scan function supplied an OS match.

    Raises:
        ValueError: If ``cidrs`` is empty, any CIDR is unparseable, any
            port is out of range, or a CIDR's address family conflicts
            with ``ipv6``.
    """
    if not cidrs:
        msg = "discover_resources_from_network requires at least one CIDR."
        raise ValueError(msg)

    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            msg = f"Invalid CIDR '{cidr}': {exc}"
            raise ValueError(msg) from exc
        if ipv6 and net.version != 6:
            msg = (
                f"--ipv6 requires every --cidr to be IPv6; got '{cidr}'. "
                f"Run a separate v4 scan without --ipv6."
            )
            raise ValueError(msg)
        if not ipv6 and net.version != 4:
            msg = f"IPv6 CIDR '{cidr}' requires --ipv6. Run with --ipv6 to scan v6 ranges."
            raise ValueError(msg)

    for port in ports:
        if not 1 <= port <= 65535:
            msg = f"Port out of range (1-65535): {port}."
            raise ValueError(msg)

    scan_results = scan_function(cidrs, ports)

    discovered: list[ResourceDefinition] = []
    for ip, host in scan_results.items():
        discovered.append(_project_host(ip, host, label, ipv6))
    return discovered


def _project_host(
    ip: str, host: dict[str, Any], label: str | None, ipv6: bool
) -> ResourceDefinition:
    rendered_ip = f"[{ip}]" if ipv6 else ip
    rid = f"network-{label}-{rendered_ip}" if label else f"network-{rendered_ip}"

    network: dict[str, Any] = {
        "ip": ip,
        "hostname": host.get("hostname"),
        "open_ports": list(host.get("open_ports") or []),
    }
    if label:
        network["scan_label"] = label

    os_info = host.get("os")
    rtype = "network.host"
    if os_info:
        network["os"] = os_info
        suffix = _OS_FAMILY_TO_TYPE_SUFFIX.get((os_info.get("family") or "").lower())
        if suffix:
            rtype = f"network.host.{suffix}"

    mac = host.get("mac")
    if mac:
        network["mac"] = mac

    services = host.get("services")
    if services:
        network["services"] = services

    return ResourceDefinition(
        id=rid,
        type=rtype,
        scope="",
        attributes={"network": network},
    )
