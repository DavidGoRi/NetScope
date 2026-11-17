"""Change tracking between scans of the same network.

Each scan is compared with the previous one saved in ``<out>/scans`` and the
differences are stored in the scan itself (``scan["changes"]``), so the
dashboard can also show the changes of earlier scans (``scan["history"]``).
"""

from __future__ import annotations

import json
from pathlib import Path

from netscope.classify import RISKY_PORTS
from netscope.inventory import device_key

HISTORY_SCANS = 15

CHANGE_TEXT = {
    "new_device": "New device on the network",
    "appeared": "Back on the network",
    "disappeared": "No longer on the network",
    "ip_changed": "IP address changed",
    "ports_opened": "Ports opened",
    "ports_closed": "Ports closed",
    "name_changed": "Name changed",
}


def load_scans(scans_dir: Path, network: str, limit: int = HISTORY_SCANS) -> list[dict]:
    """Most recent saved scans of ``network``, newest first."""
    scans: list[dict] = []
    for path in sorted(scans_dir.glob("scan-*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if data.get("network") == network:
            scans.append(data)
            if len(scans) >= limit:
                break
    return scans


def _name(device: dict) -> str | None:
    return device.get("label") or device.get("hostname")


def _change(kind: str, device: dict, **details) -> dict:
    severity = "info"
    if kind == "new_device" or (
        kind == "ports_opened" and set(details.get("ports", [])) & RISKY_PORTS
    ):
        severity = "warn"
    item = {
        "kind": kind,
        "severity": severity,
        "key": device_key(device),
        "ip": device["ip"],
        "name": _name(device),
        "vendor": device.get("vendor"),
        "message": CHANGE_TEXT[kind],
    }
    item.update(details)
    return item


def diff_scans(previous: dict, current: dict) -> list[dict]:
    before = {device_key(d): d for d in previous["devices"]}
    after = {device_key(d): d for d in current["devices"]}
    changes: list[dict] = []
    for key, device in after.items():
        old = before.get(key)
        if old is None:
            changes.append(_change("new_device" if device.get("new") else "appeared", device))
            continue
        if old["ip"] != device["ip"]:
            changes.append(_change("ip_changed", device, old=old["ip"], new=device["ip"]))
        opened = sorted(set(device["open_ports"]) - set(old["open_ports"]))
        closed = sorted(set(old["open_ports"]) - set(device["open_ports"]))
        if opened:
            changes.append(_change("ports_opened", device, ports=opened))
        if closed:
            changes.append(_change("ports_closed", device, ports=closed))
        if _name(old) and _name(device) and _name(old) != _name(device):
            changes.append(_change("name_changed", device, old=_name(old), new=_name(device)))
    for key, device in before.items():
        if key not in after:
            changes.append(_change("disappeared", device))
    order = {"warn": 0, "info": 1}
    return sorted(changes, key=lambda c: (order[c["severity"]], c["kind"], c["ip"]))


def apply_history(scan: dict, previous_scans: list[dict]) -> dict:
    """Fill ``scan["changes"]`` and ``scan["history"]`` from earlier scans (newest first)."""
    previous = previous_scans[0] if previous_scans else None
    scan["changes"] = {
        "since": previous["finished"] if previous else None,
        "items": diff_scans(previous, scan) if previous else [],
    }
    scan["history"] = [
        {
            "scan": old["finished"],
            "since": old["changes"]["since"],
            "items": old["changes"]["items"],
        }
        for old in previous_scans
        if (old.get("changes") or {}).get("items")
    ]
    return scan
