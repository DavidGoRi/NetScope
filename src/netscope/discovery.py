"""Host discovery without raw sockets or administrator rights.

1. A parallel ping sweep makes the OS resolve every address with ARP.
2. The neighbour (ARP) table is read back: any host that answered ARP is on the
   wire, even when its firewall drops ICMP (the default on Windows clients).
3. Reverse DNS gives each host a name when the router or a DNS server knows it.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout

from netscope.network import is_windows, run

_MAC_RE = re.compile(r"\b(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def normalize_mac(mac: str) -> str:
    """'a-b-cc-dd-ee-ff' / 'A:B:...' -> '0A:0B:CC:DD:EE:FF'."""
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(part.zfill(2) for part in parts).upper()


def usable_mac(mac: str) -> bool:
    """False for broadcast, all-zero and multicast addresses."""
    if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
        return False
    return not int(mac[:2], 16) & 0x01


def parse_neighbors(text: str) -> dict[str, str]:
    """IP -> MAC from ``arp -a`` (Windows, any language), ``ip neigh`` or ``arp -an``."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        ip_match, mac_match = _IP_RE.search(line), _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(0))
        if usable_mac(mac):
            table[ip_match.group(1)] = mac
    return table


def read_neighbors() -> dict[str, str]:
    if is_windows():
        return parse_neighbors(run(["arp", "-a"]))
    text = run(["ip", "neigh", "show"]) or run(["arp", "-an"])
    return parse_neighbors(text)


def ping(ip: str, timeout_ms: int = 800) -> bool:
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
    # "TTL=" only appears in real echo replies; Windows also exits with 0 when a
    # router answers "destination host unreachable".
    return "ttl=" in run(cmd, timeout=timeout_ms / 1000 + 5).lower()


def ping_sweep(
    ips: Iterable[str],
    timeout_ms: int = 800,
    workers: int = 64,
    progress: Callable[[int, int], None] | None = None,
) -> set[str]:
    targets = list(ips)
    alive: set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping, ip, timeout_ms): ip for ip in targets}
        for done, future in enumerate(as_completed(futures), start=1):
            if future.result():
                alive.add(futures[future])
            if progress:
                progress(done, len(targets))
    return alive


def resolve_names(ips: Iterable[str], timeout: float = 4.0) -> dict[str, str]:
    """Reverse DNS for each address; slow or unknown names are simply skipped."""

    def lookup(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None

    names: dict[str, str] = {}
    targets = list(ips)
    if not targets:
        return names
    pool = ThreadPoolExecutor(max_workers=min(32, len(targets)))
    futures = {pool.submit(lookup, ip): ip for ip in targets}
    try:
        for future in as_completed(futures, timeout=timeout):
            name = future.result()
            if name and name != futures[future]:
                names[futures[future]] = name
    except FuturesTimeout:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return names


def in_network(ip: str, net: ipaddress.IPv4Network) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr not in net:
        return False
    return net.prefixlen >= 31 or addr not in (net.network_address, net.broadcast_address)
