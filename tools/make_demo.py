"""Build the public demo dashboard from a fictional office network.

Every name, address and MAC below is invented. Type guesses and findings are
computed by the real NetScope code, so the demo shows exactly what a scan
would report. Usage: python tools/make_demo.py [output-folder]
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netscope import __version__, classify, history, ports, report  # noqa: E402

SEED = 2026
OLD_SEEN = "2026-10-01T09:00:00+02:00"
NEW_SEEN = "2026-11-17T09:00:00+01:00"

# ip suffix, vendor, hostname, open ports, extra flags
DEVICES = [
    (1, "Ubiquiti Inc", "gateway.office.lan", [22, 53, 80, 443], {"is_gateway": True}),
    (2, "TP-Link Systems Inc", "ap-floor2.office.lan", [53, 80], {}),
    (10, "Synology Incorporated", "nas01.office.lan", [139, 445, 5000, 5001], {}),
    (11, "Raspberry Pi Trading Ltd", "pihole.office.lan", [22, 53, 80], {}),
    (20, "Brother Industries, LTD.", "printer-reception.office.lan", [80, 515, 631, 9100], {}),
    (21, "HP Inc.", "mfp-floor2.office.lan", [21, 80, 443, 631, 9100], {}),
    (30, "Hangzhou Hikvision Digital Technology Co.,Ltd.", "cam-entrance", [80, 554], {}),
    (31, "Hangzhou Hikvision Digital Technology Co.,Ltd.", "cam-warehouse", [23, 80, 554], {}),
    (40, "Dell Inc.", "DESKTOP-RECEPTION.office.lan", [135, 139, 445], {}),
    (41, "Dell Inc.", "LAPTOP-SALES01.office.lan", [135, 139, 445], {}),
    (42, "Lenovo", "DESKTOP-ACCOUNTS.office.lan", [135, 139, 445, 3389], {"new": True}),
    (43, "Dell Inc.", "DESKTOP-IT.office.lan", [135, 139, 445, 5900], {"is_self": True}),
    (50, "Apple, Inc.", "MacBook-Design.office.lan", [445, 548], {}),
    (51, "Apple, Inc.", "iPhone-Reception", [62078], {}),
    (60, "Espressif Inc.", "thermostat", [80, 1883], {}),
    (61, "Google, Inc.", "meeting-room-tv", [8008, 8009, 8443], {}),
    (70, "VMware, Inc.", "build-server.office.lan", [22, 80, 443], {}),
    (80, None, None, [], {"randomized_mac": True}),
    (81, None, "Galaxy-S24", [], {"randomized_mac": True, "new": True}),
    (90, "Samsung Electronics Co.,Ltd", None, [], {}),
]


def fake_mac(rng: random.Random, randomized: bool) -> str:
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFC) | (0x02 if randomized else 0x00)
    return ":".join(f"{o:02X}" for o in octets)


def cert(subject: str, issuer: str, not_after: str, days_left: int) -> dict:
    return {"subject": subject, "issuer": issuer, "self_signed": subject == issuer,
            "not_after": not_after, "days_left": days_left}


# What the identification probes would add (mDNS, UPnP, NetBIOS, banners, certificates)
IDENTITY = {
    1: {"upnp": {"igd": True, "friendly_name": "UniFi Dream Machine", "manufacturer": "Ubiquiti Inc.",
                 "model_name": "UDM-Pro", "server": "Linux UPnP/1.1 MiniUPnPd/2.3.4"},
        "http": {"443": {"status": 200, "title": "UniFi OS", "server": "nginx",
                         "cert": cert("unifi.local", "unifi.local", "2027-03-02", 105)}},
        "ssh": "SSH-2.0-OpenSSH_9.2p1"},
    2: {"http": {"80": {"status": 200, "title": "TL-WA1201 Access Point", "server": "httpd"}},
        "model": "TL-WA1201"},
    10: {"netbios_name": "NAS01", "workgroup": "OFFICE", "smb1": False,
         "services_mdns": ["adisk._tcp", "http._tcp", "smb._tcp"],
         "http": {"5001": {"status": 200, "title": "Synology DiskStation - NAS01",
                           "cert": cert("nas01.office.lan", "R11", "2026-12-04", 17)}},
         "model": "DS923+"},
    11: {"ssh": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
         "http": {"80": {"status": 403, "title": "Pi-hole", "server": "lighttpd/1.4.69"}}},
    20: {"services_mdns": ["ipp._tcp", "pdl-datastream._tcp", "printer._tcp"],
         "friendly_name": "Brother HL-L2350DW", "model": "Brother HL-L2350DW series",
         "http": {"80": {"status": 200, "title": "Brother HL-L2350DW series", "server": "debut/1.30"}}},
    21: {"http": {"80": {"status": 200, "title": "HP LaserJet MFP M234", "server": "HP HTTP Server"},
                  "443": {"status": 200, "title": "HP LaserJet MFP M234",
                          "cert": cert("HPF0C2A1", "HPF0C2A1", "2025-06-30", -505)}},
         "ftp": "220 JD FTP Server Ready", "model": "HP LaserJet MFP M234"},
    30: {"http": {"80": {"status": 200, "title": "Hikvision DS-2CD2143", "server": "webs"}},
         "model": "DS-2CD2143G2-I"},
    31: {"http": {"80": {"status": 200, "title": "Hikvision DS-2CD2143", "server": "webs"}},
         "model": "DS-2CD2143G2-I"},
    40: {"netbios_name": "DESKTOP-RECEPTION", "workgroup": "OFFICE", "smb1": False},
    41: {"netbios_name": "LAPTOP-SALES01", "workgroup": "OFFICE", "smb1": False},
    42: {"netbios_name": "DESKTOP-ACCOUNTS", "workgroup": "OFFICE", "smb1": True},
    43: {"netbios_name": "DESKTOP-IT", "workgroup": "OFFICE", "smb1": False},
    50: {"services_mdns": ["companion-link._tcp", "device-info._tcp", "smb._tcp"],
         "model": "MacBookPro18,3", "mdns_name": "MacBook-Design"},
    51: {"services_mdns": ["apple-mobdev2._tcp", "companion-link._tcp"]},
    60: {"http": {"80": {"status": 200, "title": "Smart Thermostat", "server": "esp-httpd"}},
         "services_mdns": ["hap._tcp"]},
    61: {"services_mdns": ["googlecast._tcp"], "friendly_name": "Meeting room TV",
         "model": "Chromecast with Google TV",
         "upnp": {"friendly_name": "Meeting room TV", "manufacturer": "Google Inc.",
                  "model_name": "Chromecast", "server": "Linux UPnP/1.0 Chromecast/1.56"}},
    70: {"ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
         "http": {"80": {"status": 302, "server": "Apache/2.4.52 (Ubuntu)"},
                  "443": {"status": 200, "title": "Jenkins", "server": "Jetty(10.0.20)",
                          "cert": cert("build-server.office.lan", "build-server.office.lan",
                                       "2027-01-15", 59)}}},
}

PREVIOUS_SCAN = "2026-11-16T09:30:10+01:00"


def changes_for(devices: list[dict]) -> dict:
    by_ip = {d["ip"]: d for d in devices}

    def change(kind, ip, severity="info", **extra):
        d = by_ip.get(ip, {"ip": ip, "hostname": None, "vendor": None, "mac": None})
        item = {"kind": kind, "severity": severity, "key": d.get("mac") or f"ip:{ip}", "ip": ip,
                "name": d.get("hostname"), "vendor": d.get("vendor"),
                "message": history.CHANGE_TEXT[kind]}
        item.update(extra)
        return item

    return {
        "since": PREVIOUS_SCAN,
        "items": [
            change("new_device", "10.20.0.42", "warn"),
            change("new_device", "10.20.0.81", "warn"),
            change("ports_opened", "10.20.0.43", "warn", ports=[5900]),
            change("ip_changed", "10.20.0.41", old="10.20.0.45", new="10.20.0.41"),
            change("ports_closed", "10.20.0.70", ports=[8080]),
            change("disappeared", "10.20.0.95", name="LAPTOP-GUEST", vendor="ASUSTek COMPUTER INC."),
        ],
    }


HISTORY = [
    {"scan": PREVIOUS_SCAN, "since": "2026-11-15T09:30:09+01:00", "items": [
        {"kind": "appeared", "severity": "info", "key": "ip:10.20.0.95", "ip": "10.20.0.95",
         "name": "LAPTOP-GUEST", "vendor": "ASUSTek COMPUTER INC.", "message": "Back on the network"},
        {"kind": "ports_closed", "severity": "info", "key": "ip:10.20.0.21", "ip": "10.20.0.21",
         "name": "mfp-floor2.office.lan", "vendor": "HP Inc.", "message": "Ports closed",
         "ports": [23]},
    ]},
]


def build_scan() -> dict:
    rng = random.Random(SEED)
    devices = []
    for suffix, vendor_name, hostname, open_ports, extra in DEVICES:
        device = {
            "ip": f"10.20.0.{suffix}",
            "mac": fake_mac(rng, extra.get("randomized_mac", False)),
            "vendor": vendor_name,
            "randomized_mac": extra.get("randomized_mac", False),
            "hostname": hostname,
            "is_gateway": extra.get("is_gateway", False),
            "is_self": extra.get("is_self", False),
            "open_ports": open_ports,
            "services": {str(p): ports.service_name(p) for p in open_ports},
            "evidence": ["arp"] if suffix in (40, 41, 51, 81) else ["ping", "arp"],
            "new": extra.get("new", False),
            "first_seen": NEW_SEEN if extra.get("new") else OLD_SEEN,
        }
        device.update(IDENTITY.get(suffix, {}))
        device["type"] = classify.guess_type(device)
        device["findings"] = classify.findings_for(device)
        if device["new"]:
            device["findings"].insert(0, classify.finding("new_device"))
            device["findings"].sort(key=lambda f: classify.SEVERITY_ORDER[f["severity"]])
        devices.append(device)
    return {
        "tool": "NetScope",
        "version": __version__,
        "started": "2026-11-17T09:30:00+01:00",
        "finished": "2026-11-17T09:30:11+01:00",
        "duration_s": 12.4,
        "network": "10.20.0.0/24",
        "gateway": "10.20.0.1",
        "scanner_ip": "10.20.0.43",
        "platform": "Windows",
        "ports_checked": sorted(ports.COMMON_PORTS),
        "vendor_db_size": 38712,
        "baseline": False,
        "devices": devices,
        "changes": changes_for(devices),
        "history": HISTORY,
    }


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "_site")
    path = report.write_report(build_scan(), out / "index.html")
    print(f"demo written to {path}")


if __name__ == "__main__":
    main()
