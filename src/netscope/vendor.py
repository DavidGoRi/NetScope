"""MAC address vendor lookup (IEEE OUI registry).

The registry (~35,000 entries) is not bundled: ``netscope update-oui`` downloads
the public IEEE MA-L list once and stores a compact copy in the user cache.
Without it, only a few built-in prefixes (virtual machines, Raspberry Pi) are known.
"""

from __future__ import annotations

import csv
import io
import os
import platform
import urllib.request
from pathlib import Path

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

BUILTIN_OUI: dict[str, str] = {
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "Oracle VirtualBox",
    "00155D": "Microsoft Hyper-V",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
}


def cache_path() -> Path:
    override = os.environ.get("NETSCOPE_OUI")
    if override:
        return Path(override)
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "NetScope" / "oui.txt"
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "netscope" / "oui.txt"


def prefix(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()[:6]


def is_randomized(mac: str) -> bool:
    """Locally administered bit set: phones and laptops use these 'private' MACs."""
    return bool(int(mac[:2], 16) & 0x02)


def parse_ieee_csv(text: str) -> dict[str, str]:
    """IEEE MA-L CSV (Registry, Assignment, Organization Name, ...) -> {OUI: name}."""
    table: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        assignment = (row.get("Assignment") or "").strip().upper()
        name = " ".join((row.get("Organization Name") or "").split())
        if len(assignment) == 6 and name:
            table[assignment] = name
    return table


def load_oui(path: Path | None = None) -> dict[str, str]:
    table = dict(BUILTIN_OUI)
    path = path or cache_path()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return table
    for line in lines:
        oui, _, name = line.partition("\t")
        if len(oui) == 6 and name:
            table[oui] = name
    return table


def save_oui(table: dict[str, str], path: Path | None = None) -> Path:
    path = path or cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"{oui}\t{name}" for oui, name in sorted(table.items()))
    path.write_text(body + "\n", encoding="utf-8")
    return path


def update_oui(url: str = IEEE_OUI_URL, path: Path | None = None, timeout: float = 60) -> int:
    """Download the IEEE registry and store it in the cache. Returns the entry count."""
    from netscope import __version__

    request = urllib.request.Request(url, headers={"User-Agent": f"NetScope/{__version__}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        text = response.read().decode("utf-8", errors="replace")
    table = parse_ieee_csv(text)
    if len(table) < 1000:
        raise RuntimeError(f"the downloaded registry looks wrong ({len(table)} entries)")
    save_oui(table, path)
    return len(table)


def lookup(mac: str | None, table: dict[str, str]) -> str | None:
    if not mac or is_randomized(mac):
        return None
    return table.get(prefix(mac))
