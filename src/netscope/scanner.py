"""Scan orchestration: discovery -> ports -> identification -> classification."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone

from netscope import __version__, classify, discovery, identify, ports, vendor
from netscope.network import LocalInterface, platform_name

Progress = Callable[[str], None]

#: Facts copied from the identification probes onto each device.
_IDENTITY_FIELDS = ("mdns_name", "friendly_name", "model", "netbios_name", "workgroup",
                    "upnp", "http", "ssh", "ftp", "smb1")


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


#: Placeholder names some devices announce instead of a real one.
_MEANINGLESS = re.compile(
    r"^(none(-\d+)?|android(-\d+)?|localhost|unknown|esp_?[0-9a-f]+|[0-9a-f]{12,})$", re.IGNORECASE
)


def meaningful(name: str | None) -> bool:
    return bool(name) and not _MEANINGLESS.match(name.strip())


def best_name(device: dict) -> str | None:
    """Reverse DNS first, then the names devices give themselves."""
    upnp = device.get("upnp") or {}
    for name in (device.get("hostname"), device.get("friendly_name"), upnp.get("friendly_name"),
                 device.get("mdns_name"), device.get("netbios_name")):
        if meaningful(name):
            return name
    return None


def best_model(device: dict) -> str | None:
    upnp = device.get("upnp") or {}
    if upnp.get("model_name"):
        maker = upnp.get("manufacturer") or ""
        model = upnp["model_name"]
        number = upnp.get("model_number") or ""
        # Model numbers like "43UJ620V-ZA" help; firmware-like "02.03.01.035" do not.
        if number and not re.match(r"^v?\d+(\.\d+)+", number) and number not in model:
            model = f"{model} {number}"
        return model if maker and maker.lower() in model.lower() else f"{maker} {model}".strip()
    model = device.get("model")
    # Samba/TrueNAS fake an Apple model ("MacPro7,1@ECOLOR=...") so Finder shows an icon.
    if model and "@" not in model and meaningful(model):
        return model
    return None


def run_scan(
    net: ipaddress.IPv4Network,
    *,
    local: LocalInterface | None = None,
    port_list: list[int] | None = None,
    ping_timeout_ms: int = 800,
    port_timeout: float = 0.8,
    resolve: bool = True,
    deep: bool = True,
    tcp_discovery: bool | None = None,
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
    answered_tcp: set[str] = set()
    if tcp_discovery or (tcp_discovery is None and not neighbors):
        say("ARP table not available: probing common TCP ports to find more devices...")
        answered_tcp = discovery.tcp_sweep(set(targets) - answered_ping)

    alive = set(answered_ping) | set(neighbors) | answered_tcp
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

    extra: dict[str, dict] = {}
    if deep and hosts:
        say("Identifying devices (mDNS, UPnP, NetBIOS, web pages, certificates)...")
        extra = identify.identify(hosts, open_ports, local_ip=local.ip if local else None)

    gateway = local.gateway if local else None
    devices = []
    for ip in hosts:
        mac = neighbors.get(ip)
        evidence = [
            source for source, ok in
            (("ping", ip in answered_ping), ("arp", mac), ("tcp", ip in answered_tcp)) if ok
        ]
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
        info = extra.get(ip, {})
        for field in _IDENTITY_FIELDS:
            if info.get(field) not in (None, "", {}, []):
                device[field] = info[field]
        if info.get("services"):
            device["services_mdns"] = info["services"]
        device["hostname"] = best_name(device)
        model = best_model(device)
        if model:
            device["model"] = model
        else:
            device.pop("model", None)
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
        "platform": platform_name(),
        "ports_checked": port_list,
        "vendor_db_size": len(oui),
        "devices": devices,
    }
