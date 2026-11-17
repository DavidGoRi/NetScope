"""Command line interface.

netscope scan | watch | schedule | report | alert-test | update-oui
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from netscope import __version__, alerts, history, inventory, report, schedule, vendor
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


def _scan_options() -> argparse.ArgumentParser:
    """Options shared by 'scan', 'watch' and 'schedule'."""
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument(
        "--cidr",
        help=f"network to scan, e.g. 192.168.1.0/24 (default: the network of this computer; "
        f"private ranges only, at most {MAX_HOSTS} hosts)",
    )
    options.add_argument(
        "--ports",
        default="common",
        help="'common' (default, 26 well-known ports), 'none', or a list such as 22,80,8000-8010",
    )
    options.add_argument("--out", default="output", help="folder for scans, history and report")
    options.add_argument("--no-resolve", action="store_true", help="skip reverse DNS lookups")
    options.add_argument(
        "--quick", action="store_true",
        help="skip identification (mDNS, UPnP, NetBIOS, web titles, certificates, SMBv1)",
    )
    options.add_argument(
        "--tcp-discovery", action="store_true",
        help="also find hosts by TCP (automatic when the ARP table cannot be read, e.g. Android)",
    )
    options.add_argument("--no-report", action="store_true", help="do not write the HTML dashboard")
    options.add_argument(
        "--alert", action="store_true",
        help="send Telegram/email alerts configured in the alerts file",
    )
    options.add_argument("--alerts", type=Path, help="alerts settings (default: OUT/alerts.json)")
    options.add_argument(
        "--fail-on",
        choices=("crit", "warn", "new"),
        help="exit with code 3 if there is a finding of this level or higher (or a new device)",
    )
    options.add_argument("--ping-timeout", type=int, default=800, help="ping timeout in ms (800)")
    options.add_argument("--port-timeout", type=float, default=0.8, help="TCP timeout in s (0.8)")
    return options


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="Find the devices on your local network, identify them "
        "and flag risky open ports.",
    )
    parser.add_argument("--version", action="version", version=f"NetScope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")
    options = _scan_options()

    scan = sub.add_parser(
        "scan", parents=[options], help="scan the network and build the dashboard"
    )
    scan.add_argument("--json", action="store_true", help="print the scan as JSON on stdout")

    watch = sub.add_parser("watch", parents=[options], help="scan again every N minutes")
    watch.add_argument("--every", default="15m", help="interval, e.g. 15m or 1h (default 15m)")

    sched = sub.add_parser(
        "schedule", parents=[options],
        help="run scans automatically (Task Scheduler on Windows, cron elsewhere)",
    )
    when = sched.add_mutually_exclusive_group(required=True)
    when.add_argument("--every", help="interval, e.g. 30m or 2h")
    when.add_argument("--daily", metavar="HH:MM", help="once a day at this time")
    when.add_argument("--remove", action="store_true", help="remove the scheduled scan")
    sched.add_argument("--dry-run", action="store_true", help="only show what would be installed")

    rep = sub.add_parser("report", help="rebuild the dashboard from a saved scan JSON")
    rep.add_argument("scan_file", type=Path)
    rep.add_argument("-o", "--output", type=Path, help="HTML file (default: next to the JSON)")

    test = sub.add_parser("alert-test", help="send a test message through the alert channels")
    test.add_argument("--alerts", type=Path, default=Path("output/alerts.json"))

    sub.add_parser("update-oui", help="download the IEEE MAC vendor registry (once)")
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan, "watch": cmd_watch, "schedule": cmd_schedule,
        "report": cmd_report, "alert-test": cmd_alert_test,
    }
    if args.command in handlers:
        return handlers[args.command](args)
    if args.command == "update-oui":
        return cmd_update_oui()
    parser.print_help()
    return EXIT_USAGE


def resolve_target(args: argparse.Namespace):
    """(network, local interface) or raises TargetError."""
    local = detect_interface()
    if args.cidr:
        return validate_target(args.cidr), local
    if not local:
        raise TargetError("no network connection detected; pass --cidr")
    net = validate_target(str(clamp_network(local)))
    if net.prefixlen != local.prefix:
        _log(f"note: {local.network} is too large, scanning {net} instead (use --cidr)")
    return net, local


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        port_list = parse_ports(args.ports)
        net, local = resolve_target(args)
    except TargetError as exc:
        _log(f"error: {exc}")
        return EXIT_USAGE
    except ValueError as exc:
        _log(f"error: --ports: {exc}")
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
        deep=not args.quick,
        tcp_discovery=True if args.tcp_discovery else None,
        oui=oui,
        progress=_log,
    )

    out = Path(args.out)
    known_path = out / "known_devices.json"
    known = inventory.apply_known(scan, inventory.load_known(known_path))
    inventory.save_known(known, known_path)

    scans_dir = out / "scans"
    history.apply_history(scan, history.load_scans(scans_dir, scan["network"]))
    scans_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_path = scans_dir / f"scan-{stamp}.json"
    scan_path.write_text(json.dumps(scan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if getattr(args, "json", False):
        print(json.dumps(scan, indent=2, ensure_ascii=False))
    else:
        print_table(scan)
    _log(f"scan saved to {scan_path}")
    if not args.no_report:
        html = report.write_report(scan, out / "netscope-report.html")
        _log(f"dashboard: {html.resolve()}")
    if args.alert:
        config = args.alerts or out / "alerts.json"
        try:
            sent, channels = alerts.run_alerts(scan, config, out / "alerts-state.json")
        except (alerts.AlertError, OSError) as exc:
            _log(f"alerts: error: {exc}")
            return EXIT_ERROR
        _log(f"alerts: {sent} sent" + (f" via {', '.join(channels)}" if channels else ""))
    return EXIT_FINDINGS if should_fail(scan, args.fail_on) else EXIT_OK


def cmd_watch(args: argparse.Namespace) -> int:
    try:
        minutes = schedule.parse_every(args.every)
    except schedule.ScheduleError as exc:
        _log(f"error: {exc}")
        return EXIT_USAGE
    _log(f"watching: one scan every {minutes} min (Ctrl+C to stop)")
    try:
        while True:
            code = cmd_scan(args)
            if code == EXIT_USAGE:
                return code
            _log(f"next scan at {datetime.fromtimestamp(time.time() + minutes * 60):%H:%M}")
            time.sleep(minutes * 60)
    except KeyboardInterrupt:
        _log("stopped")
        return EXIT_OK


def _forwarded_options(args: argparse.Namespace) -> list[str]:
    """The scan options given to 'schedule', to repeat them in the scheduled command."""
    extra: list[str] = []
    for flag, value in (("--cidr", args.cidr), ("--ports", args.ports),
                        ("--fail-on", args.fail_on)):
        if value and not (flag == "--ports" and value == "common"):
            extra += [flag, value]
    if args.alerts:
        extra += ["--alerts", str(Path(args.alerts).resolve())]
    for flag, enabled in (("--no-resolve", args.no_resolve), ("--quick", args.quick),
                          ("--tcp-discovery", args.tcp_discovery),
                          ("--no-report", args.no_report), ("--alert", args.alert)):
        if enabled:
            extra.append(flag)
    return extra


def cmd_schedule(args: argparse.Namespace) -> int:
    try:
        if args.remove:
            _log(schedule.remove(dry_run=args.dry_run))
            return EXIT_OK
        every = schedule.parse_every(args.every) if args.every else None
        daily = schedule.parse_daily(args.daily) if args.daily else None
        command = schedule.scan_command(Path(args.out), _forwarded_options(args))
        result = schedule.install(command, every, daily, dry_run=args.dry_run)
    except schedule.ScheduleError as exc:
        _log(f"error: {exc}")
        return EXIT_ERROR
    print(result)
    return EXIT_OK


def cmd_alert_test(args: argparse.Namespace) -> int:
    try:
        config = alerts.load_config(args.alerts)
        channels = alerts.deliver(
            config, f"{config['title']}: test message. Alerts are working."
        )
    except (alerts.AlertError, OSError) as exc:
        _log(f"error: {exc}")
        return EXIT_ERROR
    _log(f"test message sent via {', '.join(channels)}")
    return EXIT_OK


def should_fail(scan: dict, level: str | None) -> bool:
    if not level:
        return False
    if level == "new":
        return any(device.get("new") for device in scan["devices"])
    allowed = {"crit": {"crit"}, "warn": {"crit", "warn"}}[level]
    return any(f["severity"] in allowed for d in scan["devices"] for f in d["findings"])


def print_table(scan: dict) -> None:
    columns = ("IP", "MAC", "VENDOR / MODEL", "NAME", "TYPE", "PORTS", "FLAGS")
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
            _cut(device.get("model") or device.get("vendor") or private),
            _cut(device.get("label") or device.get("hostname") or "-"),
            device["type"],
            ",".join(map(str, device["open_ports"])) or "-",
            " ".join(flags),
        ))
    widths = [max(len(str(row[i])) for row in [columns, *rows]) for i in range(len(columns))]
    for row in [columns, *rows]:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    findings = [f for d in scan["devices"] for f in d["findings"]]
    changes = (scan.get("changes") or {}).get("items", [])
    print(
        f"\n{len(scan['devices'])} devices on {scan['network']} in {scan['duration_s']} s - "
        f"{sum(f['severity'] == 'crit' for f in findings)} critical, "
        f"{sum(f['severity'] == 'warn' for f in findings)} warnings"
        + (f", {len(changes)} changes since the last scan" if changes else "")
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
