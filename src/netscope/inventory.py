"""Known-device register: remembers every device ever seen to flag newcomers.

Devices are keyed by MAC address (or by IP when the MAC is unknown). The first
scan of a network creates the baseline and flags nothing as new.
"""

from __future__ import annotations

import json
from pathlib import Path

from netscope.classify import SEVERITY_ORDER, finding


def device_key(device: dict) -> str:
    return device.get("mac") or f"ip:{device['ip']}"


def load_known(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"devices": {}}
    data.setdefault("devices", {})
    return data


def save_known(known: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(known, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def apply_known(scan: dict, known: dict) -> dict:
    """Mark new devices in ``scan`` and update ``known`` in place. Returns ``known``."""
    devices = known.setdefault("devices", {})
    baseline = not devices
    seen_at = scan["finished"]
    scan["baseline"] = baseline
    for device in scan["devices"]:
        key = device_key(device)
        entry = devices.get(key)
        device["new"] = entry is None and not baseline
        device["first_seen"] = entry["first_seen"] if entry else seen_at
        if device["new"]:
            device["findings"].append(finding("new_device"))
            device["findings"].sort(key=lambda item: SEVERITY_ORDER[item["severity"]])
        devices[key] = {
            "first_seen": device["first_seen"],
            "last_seen": seen_at,
            "ip": device["ip"],
            "hostname": device.get("hostname"),
            "vendor": device.get("vendor"),
            "type": device.get("type"),
            "label": (entry or {}).get("label"),
        }
        if devices[key]["label"]:
            device["label"] = devices[key]["label"]
    known["network"] = scan["network"]
    return known
