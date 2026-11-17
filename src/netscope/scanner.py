"""Scan orchestration: discovery -> identification -> ports -> classification."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import datetime, timezone

from netscope import __version__, classify, discovery, ports, vendor
from netscope.network import LocalInterface

Progress = Callable[[str], None]


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run_scan(
    net: ipaddress.IPv4Network,
    *,
    local: LocalInterface | None = None,
    port_list: list[int] | None = None,
    ping_timeout_ms: int = 800,
    port_timeout: float = 0.8,
    resolve: bool = True,
    oui: dict[str, str] | None = None,
    progress: Progress | None = None,
) -> dict:
    say = progress or (lambda _msg: None)
    port_list = sorted(ports.COMMON_PORTS) if port_list is None else port_list
    oui = vendor.load_oui() if oui is None else oui
    started, clock = _now(), time.monotonic()

    targets = [str(ip) for ip in (net.hosts() if net.prefixlen < 31 else net)]
    say(f"Pinging {len(targets)} addresses in {net}...")
    answered_ping = discovery.ping_sweep(targets, timeout_ms=ping_timeout_ms)

    neighbors = {
        ip: mac for ip, mac in discovery.read_neighbors().items() if discovery.in_network(ip, net)
    }
    alive = set(answered_ping) | set(neighbors)
    if local and discovery.in_network(local.ip, net):
        alive.add(local.ip)
        if local.mac:
            neighbors[local.ip] = local.mac
    hosts = sorted(alive, key=ipaddress.ip_address)
    say(f"Found {len(hosts)} devices ({len(answered_ping)} answered ping).")

    names: dict[str, str] = {}
    if resolve and hosts:
        say("Resolving host names...")
        names = discovery.resolve_names(hosts)

    open_ports: dict[str, list[int]] = {}
    if port_list and hosts:
        say(f"Checking {len(port_list)} TCP ports on each device...")
        open_ports = ports.scan_ports(hosts, port_list, timeout=port_timeout)

    gateway = local.gateway if local else None
    devices = []
    for ip in hosts:
        mac = neighbors.get(ip)
        evidence = [name for name, ok in (("ping", ip in answered_ping), ("arp", mac)) if ok]
        device = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor.lookup(mac, oui),
            "randomized_mac": bool(mac) and vendor.is_randomized(mac),
            "hostname": names.get(ip),
            "is_gateway": ip == gateway,
            "is_self": bool(local) and ip == local.ip,
            "open_ports": open_ports.get(ip, []),
            "evidence": evidence,
        }
        device["services"] = {str(p): ports.service_name(p) for p in device["open_ports"]}
        device["type"] = classify.guess_type(device)
        device["findings"] = classify.findings_for(device)
        devices.append(device)

    return {
        "tool": "NetScope",
        "version": __version__,
        "started": started,
        "finished": _now(),
        "duration_s": round(time.monotonic() - clock, 1),
        "network": str(net),
        "gateway": gateway,
        "scanner_ip": local.ip if local else None,
        "ports_checked": port_list,
        "vendor_db_size": len(oui),
        "devices": devices,
    }
