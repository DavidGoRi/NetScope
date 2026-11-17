# NetScope

[![CI](https://github.com/DavidGoRi/NetScope/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidGoRi/NetScope/actions/workflows/ci.yml)
[![Live demo](https://img.shields.io/badge/demo-live-0f8a7e)](https://davidgori.github.io/NetScope/)
![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![No dependencies](https://img.shields.io/badge/dependencies-none-success)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**Find every device on your local network, identify it and spot the risky ones, in about ten seconds and without administrator rights.**

NetScope sweeps a private network, works out what each device is (router, printer, camera, NAS, Windows PC, phone…), checks a short list of well-known ports and turns the result into a single HTML dashboard that flags what deserves a look: a camera with Telnet open, a printer whose admin page has no HTTPS, a Remote Desktop port reachable from the whole network, or **a device that was not there yesterday**.

### ▶ [Open the live demo](https://davidgori.github.io/NetScope/)

The demo shows a fictitious office network of 20 devices. It is the same single HTML file NetScope produces.

*Leer en [español](README.es.md).*

## Why

"What is actually connected to our network?" is one of the first questions in any IT support or security job, and the answer is usually a spreadsheet nobody updates. NetScope answers it with:

- **No dependencies.** Only the Python standard library. No Npcap, no nmap, no agents.
- **No administrator rights.** Discovery uses the system `ping` and the ARP table; port checks are normal TCP connections.
- **Safe by design.** It refuses public IP ranges and networks larger than 1,024 hosts, and only checks 26 well-known ports unless told otherwise.
- **Offline dashboard.** One self-contained HTML file with no external libraries: open it from a USB stick or attach it to a ticket.

## How it works

```
 ping sweep (64 in parallel) ──► ARP table ──► reverse DNS ──► TCP connect to 26 ports
        │                            │               │                    │
        └── who answers ICMP         └── who answered ARP, even with a firewall that drops ping
                                                     │                    │
                                     MAC vendor (IEEE registry) ──► type guess + findings
                                                                          │
                                       known_devices.json ──► "new device" flag ──► JSON + HTML
```

1. **Discovery.** Every address gets one ping. Even when a device ignores the ping (Windows clients and phones do by default), the operating system has to resolve its MAC with ARP first, so reading the ARP table afterwards finds it anyway. On a real home network this finds 18 devices where ping alone finds 11.
2. **Identification.** The MAC prefix gives the manufacturer (from the public IEEE registry). Randomized "private" MACs used by modern phones are detected and labelled. Reverse DNS adds the host name when the router knows it.
3. **Ports.** An asynchronous TCP connect check of 26 common ports (SSH, Telnet, HTTP/S, SMB, RDP, VNC, printing, MQTT, RTSP, Chromecast, Plex…), 200 at a time.
4. **Classification.** Heuristics over ports, vendor and name guess the device type, and rules produce findings with a severity:

| Finding | Severity |
|---|---|
| Telnet open (credentials in clear text) | Critical |
| FTP, VNC, Remote Desktop or unencrypted MQTT reachable | Warning |
| Router, printer, camera, NAS or smart device with a web admin page over HTTP only | Warning |
| New device (not seen in earlier scans) | Warning |
| SMB file sharing enabled, private (randomized) MAC | Info |

5. **History.** Every device is stored in `known_devices.json` keyed by MAC. The first scan is the baseline; from then on, newcomers are flagged.

## Quick start

```bash
git clone https://github.com/DavidGoRi/NetScope.git
cd NetScope
python -m pip install .
netscope update-oui        # once: downloads the public IEEE vendor registry
netscope scan              # scans the network this computer is on
```

Output:

```
IP          MAC                VENDOR                        NAME                          TYPE      PORTS             FLAGS
10.20.0.1   3C:A3:34:72:D7:FB  Ubiquiti Inc                  gateway.office.lan            router    22,53,80,443      gateway
10.20.0.20  AC:2D:95:93:EA:48  Brother Industries, LTD.      printer-reception.office.lan  printer   80,515,631,9100   WARN
10.20.0.31  C8:84:D7:F5:0C:72  Hangzhou Hikvision Digital ~  cam-warehouse                 camera    23,80,554         CRIT WARN
10.20.0.42  CC:9D:F5:CD:DD:67  Lenovo                        DESKTOP-ACCOUNTS.office.lan   windows   135,139,445,3389  NEW WARN
10.20.0.81  16:89:B6:4F:02:A0  (private MAC)                 Galaxy-S24                    mobile    -                 NEW
...
20 devices on 10.20.0.0/24 in 10.6 s - 1 critical, 11 warnings
```

(Output of the fictitious demo network.)

The dashboard is written to `output/netscope-report.html`; each scan is also saved as JSON in `output/scans/`.

## Usage

```
netscope scan [--cidr 192.168.1.0/24] [--ports common|none|22,80,8000-8010]
              [--out DIR] [--no-resolve] [--no-report] [--json]
              [--fail-on crit|warn|new] [--ping-timeout MS] [--port-timeout S]
netscope report output/scans/scan-20261117-093000.json [-o report.html]
netscope update-oui
```

| Option | Meaning |
|---|---|
| `--cidr` | Network to scan. Defaults to this computer's network (a /24 if it is larger than 1,024 hosts). |
| `--ports` | `common` (default), `none` for discovery only, or a custom list/range (max. 1,024 ports). |
| `--json` | Print the full scan as JSON (for scripts or other tools). |
| `--fail-on` | Exit with code `3` if there is a critical finding (`crit`), any warning (`warn`) or a new device (`new`). Useful in a scheduled task. |

Exit codes: `0` OK, `1` error, `2` invalid arguments or target, `3` findings matched `--fail-on`.

To give a device a friendly name, set its `label` in `output/known_devices.json`; it is kept across scans and shown in the dashboard.

### Run it every morning (Windows)

```powershell
schtasks /Create /TN "NetScope" /SC DAILY /ST 08:00 /TR "netscope scan --out C:\NetScope --fail-on new"
```

## The dashboard

- Summary tiles: devices, new devices, open ports, critical findings and warnings.
- Sortable, searchable device table with type filters, open ports (risky ones highlighted) and the most serious finding.
- Detail page per device: identity, open ports with service names, all findings.
- Findings view across the whole network, filterable by severity.
- CSV export, light and dark themes, **English and Spanish** (follows the browser; `?lang=es` forces it).

Host names come from the network and are untrusted, so the scan data is escaped before it is embedded and everything is rendered as text.

## Project layout

```
src/netscope/
  network.py     interface detection and the private-range / size gate
  discovery.py   ping sweep, ARP table parsing (Windows in any language, Linux, macOS), reverse DNS
  ports.py       asyncio TCP connect scan
  vendor.py      IEEE OUI registry download, cache and lookup; randomized MAC detection
  classify.py    device type heuristics and findings
  inventory.py   known-device register and "new device" detection
  scanner.py     orchestration
  report.py      dashboard rendering (templates/report.html)
  cli.py         command line
tests/           pytest suite (no network needed except a local loopback socket)
tools/make_demo.py   builds the public demo from a fictitious network
```

CI runs ruff and the test suite on Windows and Linux with Python 3.9 and 3.13, and a real smoke scan of the runner's own subnet.

## Responsible use

Only scan networks you own or are authorised to audit. NetScope enforces private address ranges and a host limit, and its port check is a plain TCP connection to a short list of ports, the same as any client would make, but on a network that is not yours even that may be against the rules.

## Roadmap

- Alerts (email / Telegram) when a new device appears.
- Change history between scans (ports opened or closed, IP changes).
- mDNS / NetBIOS names for devices the router does not name.

## License

[MIT](LICENSE)
