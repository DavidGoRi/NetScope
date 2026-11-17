"""Device type guessing and security findings.

Both are heuristics over open ports, MAC vendor and hostname; the report shows
them as hints, not certainties. Findings carry a stable ``code`` so the
dashboard can translate them, plus an English ``message`` for the JSON/CLI.
"""

from __future__ import annotations

SEVERITY_ORDER = {"crit": 0, "warn": 1, "info": 2}

DEVICE_TYPES = (
    "router",
    "printer",
    "camera",
    "nas",
    "console",
    "windows",
    "apple-mobile",
    "apple",
    "media",
    "home-automation",
    "linux",
    "virtual-machine",
    "mobile",
    "unknown",
)

_PRINTER_PORTS = {515, 631, 9100}
_WEB_PORTS = {80, 8080}
_TLS_WEB_PORTS = {443, 8443, 5001}

FINDINGS: dict[str, tuple[str, str]] = {
    "telnet_open": ("crit", "Telnet (23/tcp) is open: logins travel in clear text."),
    "ftp_open": ("warn", "FTP (21/tcp) is open: files and passwords travel in clear text."),
    "vnc_open": ("warn", "VNC remote control (5900/tcp) is reachable from the network."),
    "rdp_open": ("warn", "Remote Desktop (3389/tcp) is reachable from the network."),
    "mqtt_open": ("warn", "Unencrypted MQTT broker (1883/tcp) is reachable."),
    "smb_open": ("info", "File sharing (SMB, 445/tcp) is enabled."),
    "http_only_admin": (
        "warn",
        "Web interface only over plain HTTP: its password is not encrypted.",
    ),
    "new_device": ("warn", "New device: it was not seen in any earlier scan."),
    "private_mac": ("info", "Private (randomized) MAC: the vendor is hidden and may change."),
}

_PORT_FINDINGS = {
    23: "telnet_open",
    21: "ftp_open",
    5900: "vnc_open",
    3389: "rdp_open",
    1883: "mqtt_open",
    445: "smb_open",
}


def finding(code: str, **params) -> dict:
    severity, message = FINDINGS[code]
    item = {"code": code, "severity": severity, "message": message}
    item.update(params)
    return item


def _has(text: str | None, *words: str) -> bool:
    lowered = (text or "").lower()
    return any(word in lowered for word in words)


def guess_type(device: dict) -> str:
    ports = set(device.get("open_ports") or [])
    vendor, name = device.get("vendor"), device.get("hostname")

    if device.get("is_gateway"):
        return "router"
    if ports & _PRINTER_PORTS or _has(vendor, "brother", "epson", "canon", "lexmark", "kyocera"):
        return "printer"
    if _has(vendor, "vmware", "virtualbox", "hyper-v", "pcs systemtechnik", "qemu"):
        return "virtual-machine"
    if 554 in ports or _has(vendor, "hikvision", "dahua", "reolink", "axis comm"):
        return "camera"
    nas_vendor = _has(vendor, "synology", "qnap", "western digital", "asustor")
    nas_name = _has(name, "nas", "synology", "diskstation", "qnap")
    if (nas_vendor and ports & {5000, 5001}) or (nas_name and ports & {21, 445, 2049, 5000}):
        return "nas"
    if _has(name, "xbox", "playstation", "ps4", "ps5", "nintendo") or _has(
        vendor, "nintendo", "sony interactive"
    ):
        return "console"
    if {53} <= ports and ports & (_WEB_PORTS | _TLS_WEB_PORTS) and not ports & {22, 445}:
        return "router"  # DNS + web admin and nothing else: access point or mesh node
    if 62078 in ports or _has(name, "iphone", "ipad"):
        return "apple-mobile"
    if 3389 in ports or {135, 445} <= ports or _has(name, "desktop-", "laptop-"):
        return "windows"
    if 548 in ports or _has(vendor, "apple"):
        return "apple"
    if ports & {8008, 8009, 32400} or _has(vendor, "roku", "sonos", "chromecast"):
        return "media"
    if ports & {8123, 1883} or _has(vendor, "espressif", "tuya", "shelly", "signify", "philips"):
        return "home-automation"
    if 22 in ports or _has(vendor, "raspberry"):
        return "linux"
    if device.get("randomized_mac") or _has(
        vendor, "samsung", "xiaomi", "huawei", "oneplus", "motorola", "oppo"
    ):
        return "mobile"
    return "unknown"


def findings_for(device: dict) -> list[dict]:
    ports = set(device.get("open_ports") or [])
    items = [finding(code, port=port) for port, code in _PORT_FINDINGS.items() if port in ports]

    web = sorted(ports & _WEB_PORTS)
    if web and not ports & _TLS_WEB_PORTS and device.get("type") in (
        "router", "printer", "camera", "nas", "home-automation"
    ):
        items.append(finding("http_only_admin", port=web[0]))
    if device.get("randomized_mac"):
        items.append(finding("private_mac"))
    return sorted(items, key=lambda item: SEVERITY_ORDER[item["severity"]])
