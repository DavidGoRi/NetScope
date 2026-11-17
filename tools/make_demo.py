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

from netscope import __version__, classify, ports, report  # noqa: E402

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
        "duration_s": 10.6,
        "network": "10.20.0.0/24",
        "gateway": "10.20.0.1",
        "scanner_ip": "10.20.0.43",
        "ports_checked": sorted(ports.COMMON_PORTS),
        "vendor_db_size": 38712,
        "baseline": False,
        "devices": devices,
    }


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "_site")
    path = report.write_report(build_scan(), out / "index.html")
    print(f"demo written to {path}")


if __name__ == "__main__":
    main()
