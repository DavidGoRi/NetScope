# Changelog

## 1.0.0 - 2026-11-17

### Identification
- mDNS / DNS-SD discovery: device names, models and announced services (Chromecast, AirPlay, printers, HomeKit, Matter…).
- SSDP / UPnP discovery with the manufacturer, model and friendly name from each device description.
- NetBIOS node status: Windows and Samba computer names and workgroups.
- Web page titles and Server headers, SSH and FTP banners.
- Multicast queries leave through the interface of the scanned network (fixes no answers on PCs with VPN or Hyper-V adapters).
- Placeholder names and fake models are ignored; the type guess uses all of the above.

### Security checks
- SMBv1 detection (critical).
- HTTPS certificates: expired (warning), expiring within 30 days and self-signed (info).
- UPnP port forwarding enabled on the router (info).

### History and alerts
- Every scan is compared with the previous one: new devices, devices that left or came back, IP and name changes, ports opened and closed. New dashboard tab with the history.
- Telegram and email alerts for new devices, risky ports that open and findings above a chosen level, without repeats.
- `netscope watch` (scan every N minutes) and `netscope schedule` (Windows Task Scheduler or cron).

### Platforms
- macOS: interface, netmask and MAC detection; correct ping timeout.
- Android (Termux): TCP discovery when the ARP table cannot be read.
- Release builds: standalone binaries for Windows, Linux and macOS, plus `netscope.pyz` for any system with Python 3.10+.

### Dashboard
- Changes tab, model column, device page with names, services, banners and certificates, direct links (`#changes`, `#device=IP`).

## 0.1.0 - 2026-11-17

First version.

- Host discovery with a parallel ping sweep plus the ARP table (finds devices that drop ping).
- MAC vendor lookup from the IEEE registry (`netscope update-oui`) and randomized MAC detection.
- Reverse DNS names.
- Asynchronous TCP connect check of 26 well-known ports, or a custom list.
- Device type guessing and security findings (Telnet, FTP, VNC, RDP, MQTT, HTTP-only admin pages, SMB).
- Known-device register with "new device" detection.
- Self-contained HTML dashboard in English and Spanish with CSV export.
- Safety gate: private ranges only, at most 1,024 hosts.
- CI on Windows and Linux (Python 3.10 and 3.13) and a live demo on GitHub Pages.
