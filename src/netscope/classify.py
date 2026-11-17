"""Device type guessing and security findings.

Both are heuristics over open ports, MAC vendor, names, announced services
(mDNS, UPnP) and web page titles; the report shows them as hints, not
certainties. Findings carry a stable ``code`` so the dashboard can translate
them, plus an English ``message`` for the JSON/CLI.
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

#: Port numbers whose opening is worth an alert.
RISKY_PORTS = {21, 23, 445, 1883, 3389, 5900}

#: Days before expiry at which an HTTPS certificate is reported.
CERT_WARNING_DAYS = 30

FINDINGS: dict[str, tuple[str, str]] = {
    "telnet_open": ("crit", "Telnet (23/tcp) is open: logins travel in clear text."),
    "smb1_enabled": ("crit", "SMBv1 is enabled: the old file-sharing protocol WannaCry used."),
    "ftp_open": ("warn", "FTP (21/tcp) is open: files and passwords travel in clear text."),
    "vnc_open": ("warn", "VNC remote control (5900/tcp) is reachable from the network."),
    "rdp_open": ("warn", "Remote Desktop (3389/tcp) is reachable from the network."),
    "mqtt_open": ("warn", "Unencrypted MQTT broker (1883/tcp) is reachable."),
    "http_only_admin": (
        "warn",
        "Web interface only over plain HTTP: its password is not encrypted.",
    ),
    "tls_expired": ("warn", "The HTTPS certificate has expired."),
    "new_device": ("warn", "New device: it was not seen in any earlier scan."),
    "tls_expiring": ("info", "The HTTPS certificate expires within 30 days."),
    "tls_self_signed": ("info", "Self-signed HTTPS certificate: browsers will show a warning."),
    "upnp_igd": (
        "info",
        "UPnP port forwarding is on: devices can open router ports by themselves.",
    ),
    "smb_open": ("info", "File sharing (SMB, 445/tcp) is enabled."),
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

# mDNS service type -> device type (strong signals, checked first)
_SERVICE_TYPES = [
    ({"ipp._tcp", "ipps._tcp", "printer._tcp", "pdl-datastream._tcp", "scanner._tcp"}, "printer"),
    ({"companion-link._tcp", "apple-mobdev2._tcp"}, "apple-mobile"),
    ({"googlecast._tcp", "airplay._tcp", "raop._tcp", "spotify-connect._tcp", "sonos._tcp",
      "androidtvremote2._tcp", "amzn-wplay._tcp"}, "media"),
    ({"hap._tcp", "home-assistant._tcp", "matter._tcp", "matterc._udp", "hue._tcp"},
     "home-automation"),
    ({"adisk._tcp", "afpovertcp._tcp"}, "nas"),
]


def finding(code: str, **params) -> dict:
    severity, message = FINDINGS[code]
    item = {"code": code, "severity": severity, "message": message}
    item.update(params)
    return item


def describe(device: dict) -> str:
    """Every free-text fact about a device, lower-cased, for keyword checks."""
    upnp = device.get("upnp") or {}
    http = device.get("http") or {}
    parts = [
        device.get("vendor"), device.get("hostname"), device.get("mdns_name"),
        device.get("netbios_name"), device.get("friendly_name"), device.get("model"),
        upnp.get("friendly_name"), upnp.get("manufacturer"), upnp.get("model_name"),
        upnp.get("device_type"), device.get("ssh"),
        *(page.get("title") for page in http.values()),
        *(page.get("server") for page in http.values()),
    ]
    return " ".join(str(part) for part in parts if part).lower()


def _has(text: str, *words: str) -> bool:
    return any(word in text for word in words)


def guess_type(device: dict) -> str:
    ports = set(device.get("open_ports") or [])
    services = set(device.get("services_mdns") or [])
    text = describe(device)
    vendor = (device.get("vendor") or "").lower()

    if device.get("is_gateway") or _has(text, "internetgatewaydevice"):
        return "router"
    for service_set, device_type in _SERVICE_TYPES:
        if services & service_set:
            return device_type
    if ports & _PRINTER_PORTS or _has(
        text, "printer", "laserjet", "officejet", "deskjet", "brother", "epson", "canon",
        "lexmark", "kyocera",
    ):
        return "printer"
    if _has(vendor, "vmware", "virtualbox", "hyper-v", "pcs systemtechnik", "qemu"):
        return "virtual-machine"
    if 554 in ports or _has(text, "hikvision", "dahua", "reolink", "axis comm", "ipcam", "camera"):
        return "camera"
    if _has(text, "truenas", "synology", "diskstation", "qnap", "unraid", "openmediavault") or (
        _has(text, "nas") and ports & {21, 445, 2049, 5000}
    ):
        return "nas"
    if _has(text, "xbox", "playstation", "ps4", "ps5", "nintendo", "sony interactive"):
        return "console"
    if _has(text, "home assistant", "espressif", "tuya", "shelly", "signify", "philips hue"):
        return "home-automation"
    if {53} <= ports and ports & (_WEB_PORTS | _TLS_WEB_PORTS) and not ports & {22, 445}:
        return "router"  # DNS + web admin and nothing else: access point or mesh node
    if _has(text, "router", "openwrt", "luci", "mikrotik", "routeros", "fritz!box", "livebox"):
        return "router"
    if 62078 in ports or _has(text, "iphone", "ipad"):
        return "apple-mobile"
    if 3389 in ports or {135, 445} <= ports or _has(text, "desktop-", "laptop-"):
        return "windows"
    if 548 in ports or "apple" in vendor or _has(text, "macbook", "imac", "mac mini"):
        return "apple"
    if ports & {8008, 8009, 32400} or _has(
        text, "roku", "sonos", "chromecast", "smart tv", "bravia", "webos", "tizen", "plex",
    ):
        return "media"
    if 8123 in ports or 1883 in ports:
        return "home-automation"
    if 22 in ports or _has(text, "raspberry", "ubuntu", "debian", "linux"):
        return "linux"
    if device.get("randomized_mac") or _has(
        text, "samsung", "xiaomi", "huawei", "oneplus", "motorola", "oppo", "android", "galaxy",
    ):
        return "mobile"
    return "unknown"


def findings_for(device: dict) -> list[dict]:
    ports = set(device.get("open_ports") or [])
    items = [finding(code, port=port) for port, code in _PORT_FINDINGS.items() if port in ports]

    if device.get("smb1"):
        items.append(finding("smb1_enabled", port=445))
    web = sorted(ports & _WEB_PORTS)
    if web and not ports & _TLS_WEB_PORTS and device.get("type") in (
        "router", "printer", "camera", "nas", "home-automation"
    ):
        items.append(finding("http_only_admin", port=web[0]))
    for port, page in sorted((device.get("http") or {}).items()):
        cert = page.get("cert")
        if not cert:
            continue
        if cert["days_left"] < 0:
            items.append(finding("tls_expired", port=int(port), not_after=cert["not_after"]))
        elif cert["days_left"] <= CERT_WARNING_DAYS:
            items.append(finding("tls_expiring", port=int(port), not_after=cert["not_after"]))
        if cert.get("self_signed"):
            items.append(finding("tls_self_signed", port=int(port)))
    if (device.get("upnp") or {}).get("igd"):
        items.append(finding("upnp_igd"))
    if device.get("randomized_mac"):
        items.append(finding("private_mac"))
    return sorted(items, key=lambda item: SEVERITY_ORDER[item["severity"]])
