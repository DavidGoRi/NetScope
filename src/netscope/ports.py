"""TCP connect scan of a short list of well-known ports.

A full TCP handshake is used (no raw packets), so it needs no privileges and is
what any normal client would do. The connection is closed straight away.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterable

#: Ports checked by default, with the service usually behind them.
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    135: "msrpc",
    139: "netbios",
    443: "https",
    445: "smb",
    515: "lpd",
    548: "afp",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    3389: "rdp",
    5000: "upnp/nas",
    5001: "nas-https",
    5900: "vnc",
    8008: "cast",
    8009: "cast-tls",
    8080: "http-alt",
    8123: "home-assistant",
    8443: "https-alt",
    9100: "jetdirect",
    32400: "plex",
    62078: "apple-sync",
}

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"


def parse_ports(spec: str) -> list[int]:
    """'common' | 'none' | '22,80,8000-8010' -> sorted list of ports."""
    spec = spec.strip().lower()
    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec in ("none", ""):
        return []
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    if len(ports) > 1024:
        raise ValueError("at most 1024 ports can be checked per scan")
    return sorted(ports)


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "")


async def probe(ip: str, port: int, timeout: float) -> str:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except ConnectionRefusedError:
        return CLOSED
    except (asyncio.TimeoutError, OSError):
        return FILTERED
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return OPEN


async def _scan(
    hosts: list[str], ports: list[int], timeout: float, concurrency: int
) -> dict[str, list[int]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def limited(ip: str, port: int) -> tuple[str, int, str]:
        async with semaphore:
            return ip, port, await probe(ip, port, timeout)

    results = await asyncio.gather(*(limited(ip, port) for ip in hosts for port in ports))
    open_ports: dict[str, list[int]] = {ip: [] for ip in hosts}
    for ip, port, state in results:
        if state == OPEN:
            open_ports[ip].append(port)
    return {ip: sorted(found) for ip, found in open_ports.items()}


def scan_ports(
    hosts: Iterable[str], ports: Iterable[int], timeout: float = 0.8, concurrency: int = 200
) -> dict[str, list[int]]:
    """Open ports per host. Hosts are expected to be already validated."""
    host_list, port_list = list(hosts), list(ports)
    if not host_list or not port_list:
        return {ip: [] for ip in host_list}
    return asyncio.run(_scan(host_list, port_list, timeout, concurrency))
