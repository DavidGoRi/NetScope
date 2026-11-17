"""Local interface detection and scan-target validation.

NetScope only scans private networks it is attached to. ``validate_target`` is
the single gate every CIDR goes through before a packet is sent.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

#: Largest number of host addresses NetScope agrees to scan (a /22).
MAX_HOSTS = 1024

#: Prefix used when the real one cannot be detected, or is too large to scan.
DEFAULT_PREFIX = 24

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class TargetError(ValueError):
    """Raised when a scan target is not allowed."""


@dataclass
class LocalInterface:
    ip: str
    prefix: int
    mac: str | None = None
    gateway: str | None = None

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.ip}/{self.prefix}", strict=False)


def is_windows() -> bool:
    return platform.system() == "Windows"


def run(cmd: list[str], timeout: float = 10) -> str:
    """Run a command and return its stdout, or "" if it fails or times out."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or ""


def validate_target(cidr: str, max_hosts: int = MAX_HOSTS) -> ipaddress.IPv4Network:
    """Parse ``cidr`` and refuse anything that is not a small private IPv4 network."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise TargetError(f"'{cidr}' is not a valid network (example: 192.168.1.0/24)") from exc
    if net.version != 4:
        raise TargetError("only IPv4 networks are supported")
    first, last = net.network_address, net.broadcast_address
    if first.is_loopback or not (first.is_private and last.is_private):
        raise TargetError(
            f"{net} is not a private network. NetScope only scans local ranges "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)."
        )
    hosts = host_count(net)
    if hosts > max_hosts:
        raise TargetError(
            f"{net} has {hosts} host addresses; the limit is {max_hosts} "
            "(use a /22 or a smaller network)"
        )
    return net


def host_count(net: ipaddress.IPv4Network) -> int:
    return net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2


def clamp_network(iface: LocalInterface, max_hosts: int = MAX_HOSTS) -> ipaddress.IPv4Network:
    """The interface network, or the /24 around the interface address if it is too big."""
    net = iface.network
    if host_count(net) > max_hosts:
        net = ipaddress.ip_network(f"{iface.ip}/{DEFAULT_PREFIX}", strict=False)
    return net


def local_ip() -> str | None:
    """IPv4 address of the interface that holds the default route.

    Connecting a UDP socket sends no packets; it only asks the OS which source
    address it would use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1, never contacted
            return sock.getsockname()[0]
        except OSError:
            return None


def detect_interface() -> LocalInterface | None:
    ip = local_ip()
    if not ip or ip.startswith("127."):
        return None
    system = platform.system()
    if system == "Windows":
        details = _windows_details(ip)
    elif system == "Linux":
        details = _linux_details(ip)
    else:
        details = _bsd_details()
    return LocalInterface(
        ip=ip,
        prefix=details.get("prefix") or DEFAULT_PREFIX,
        mac=details.get("mac"),
        gateway=details.get("gateway"),
    )


def _windows_details(ip: str) -> dict:
    script = (
        f"$a = Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction Stop;"
        "$n = Get-NetAdapter -InterfaceIndex $a.InterfaceIndex;"
        "$g = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $a.InterfaceIndex "
        "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1;"
        "[pscustomobject]@{prefix=[int]$a.PrefixLength; mac=$n.MacAddress; gateway=$g.NextHop}"
        " | ConvertTo-Json -Compress"
    )
    out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=20)
    try:
        data = json.loads(out.strip() or "{}")
    except ValueError:
        return {}
    from netscope.discovery import normalize_mac  # avoid an import cycle

    return {
        "prefix": data.get("prefix"),
        "mac": normalize_mac(data["mac"]) if data.get("mac") else None,
        "gateway": data.get("gateway") or None,
    }


def _linux_details(ip: str) -> dict:
    details: dict = {}
    for line in run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        match = re.search(rf"^\d+:\s+(\S+)\s+inet\s+{re.escape(ip)}/(\d+)", line)
        if match:
            iface, details["prefix"] = match.group(1), int(match.group(2))
            mac_file = Path("/sys/class/net") / iface / "address"
            with contextlib.suppress(OSError):
                details["mac"] = mac_file.read_text().strip().upper()
            break
    match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", run(["ip", "route", "show", "default"]))
    if match:
        details["gateway"] = match.group(1)
    return details


def _bsd_details() -> dict:
    match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", run(["route", "-n", "get", "default"]))
    return {"gateway": match.group(1)} if match else {}
