# Changelog

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
