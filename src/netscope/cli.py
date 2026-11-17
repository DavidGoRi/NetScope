"""Command line interface: ``netscope scan | report | update-oui``."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from netscope import __version__, inventory, report, vendor
from netscope.network import (
    MAX_HOSTS,
    TargetError,
    clamp_network,
    detect_interface,
    validate_target,
)
from netscope.ports import parse_ports

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_FINDINGS = 0, 1, 2, 3


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="Find the devices on your local network, identify them "
        "and flag risky open ports.",
    )
    parser.add_argument("--version", action="version", version=f"NetScope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    scan = sub.add_parser("scan", help="scan the local network and build the dashboard")
    scan.add_argument(
        "--cidr",
        help=f"network to scan, e.g. 192.168.1.0/24 (default: the network of this computer; "
        f"private ranges only, at most {MAX_HOSTS} hosts)",
    )
    scan.add_argument(
        "--ports",
        default="common",
        help="'common' (default, 26 well-known ports), 'none', or a list such as 22,80,8000-8010",
    )
    scan.add_argument("--out", default="output", help="folder for scans, known devices and report")
    scan.add_argument("--no-resolve", action="store_true", help="skip reverse DNS lookups")
    scan.add_argument("--no-report", action="store_true", help="do not write the HTML dashboard")
    scan.add_argument("--json", action="store_true", help="print the scan as JSON on stdout")
    scan.add_argument(
        "--fail-on",
        choices=("crit", "warn", "new"),
        help="exit with code 3 if there is a finding of this level or higher (or a new device)",
    )
    scan.add_argument("--ping-timeout", type=int, default=800, help="ping timeout in ms (800)")
    scan.add_argument("--port-timeout", type=float, default=0.8, help="TCP timeout in s (0.8)")

    rep = sub.add_parser("report", help="rebuild the dashboard from a saved scan JSON")
    rep.add_argument("scan_file", type=Path)
    rep.add_argument("-o", "--output", type=Path, help="HTML file (default: next to the JSON)")

    sub.add_parser("update-oui", help="download the IEEE MAC vendor registry (once)")
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "report":
        return cmd_report(args)
    if args.command == "update-oui":
        return cmd_update_oui()
    parser.print_help()
    return EXIT_USAGE


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        port_list = parse_ports(args.ports)
    except ValueError as exc:
        _log(f"error: --ports: {exc}")
        return EXIT_USAGE

    local = detect_interface()
    try:
        if args.cidr:
            net = validate_target(args.cidr)
        elif local:
            net = validate_target(str(clamp_network(local)))
            if net.prefixlen != local.prefix:
                _log(f"note: {local.network} is too large, scanning {net} instead (use --cidr)")
        else:
            _log("error: no network connection detected; pass --cidr")
            return EXIT_USAGE
    except TargetError as exc:
        _log(f"error: {exc}")
        return EXIT_USAGE

    from netscope.scanner import run_scan  # imported late: keeps --help fast

    oui = vendor.load_oui()
    if len(oui) <= len(vendor.BUILTIN_OUI):
        _log("note: vendor names need the IEEE registry; run 'netscope update-oui' once")
    scan = run_scan(
        net,
        local=local,
        port_list=port_list,
        ping_timeout_ms=args.ping_timeout,
        port_timeout=args.port_timeout,
        resolve=not args.no_resolve,
        oui=oui,
        progress=_log,
    )

    out = Path(args.out)
    known_path = out / "known_devices.json"
    known = inventory.apply_known(scan, inventory.load_known(known_path))
    inventory.save_known(known, known_path)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_path = out / "scans" / f"scan-{stamp}.json"
    scan_path.parent.mkdir(parents=True, exist_ok=True)
    scan_path.write_text(json.dumps(scan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(scan, indent=2, ensure_ascii=False))
    else:
        print_table(scan)
    _log(f"scan saved to {scan_path}")
    if not args.no_report:
        html = report.write_report(scan, out / "netscope-report.html")
        _log(f"dashboard: {html.resolve()}")
    return EXIT_FINDINGS if should_fail(scan, args.fail_on) else EXIT_OK


def should_fail(scan: dict, level: str | None) -> bool:
    if not level:
        return False
    if level == "new":
        return any(device.get("new") for device in scan["devices"])
    allowed = {"crit": {"crit"}, "warn": {"crit", "warn"}}[level]
    return any(f["severity"] in allowed for d in scan["devices"] for f in d["findings"])


def print_table(scan: dict) -> None:
    columns = ("IP", "MAC", "VENDOR", "NAME", "TYPE", "PORTS", "FLAGS")
    rows = []
    for device in scan["devices"]:
        flags = []
        if device.get("new"):
            flags.append("NEW")
        if device.get("is_gateway"):
            flags.append("gateway")
        if device.get("is_self"):
            flags.append("this-pc")
        severities = {
            f["severity"]
            for f in device["findings"]
            if f["severity"] != "info" and f["code"] != "new_device"
        }
        flags += [level.upper() for level in ("crit", "warn") if level in severities]
        private = "(private MAC)" if device.get("randomized_mac") else "-"
        rows.append((
            device["ip"],
            device.get("mac") or "-",
            _cut(device.get("vendor") or private),
            _cut(device.get("label") or device.get("hostname") or "-"),
            device["type"],
            ",".join(map(str, device["open_ports"])) or "-",
            " ".join(flags),
        ))
    widths = [max(len(str(row[i])) for row in [columns, *rows]) for i in range(len(columns))]
    for row in [columns, *rows]:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    findings = [f for d in scan["devices"] for f in d["findings"]]
    print(
        f"\n{len(scan['devices'])} devices on {scan['network']} in {scan['duration_s']} s - "
        f"{sum(f['severity'] == 'crit' for f in findings)} critical, "
        f"{sum(f['severity'] == 'warn' for f in findings)} warnings"
        + (" - baseline saved" if scan.get("baseline") else "")
    )


def _cut(text: str, width: int = 28) -> str:
    return text if len(text) <= width else text[: width - 1] + "~"


def cmd_report(args: argparse.Namespace) -> int:
    try:
        scan = json.loads(args.scan_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log(f"error: cannot read {args.scan_file}: {exc}")
        return EXIT_ERROR
    target = args.output or args.scan_file.with_suffix(".html")
    _log(f"dashboard: {report.write_report(scan, target).resolve()}")
    return EXIT_OK


def cmd_update_oui() -> int:
    _log(f"downloading {vendor.IEEE_OUI_URL} ...")
    try:
        count = vendor.update_oui()
    except Exception as exc:  # network errors come in many shapes
        _log(f"error: {exc}")
        return EXIT_ERROR
    _log(f"saved {count} vendor prefixes to {vendor.cache_path()}")
    return EXIT_OK
