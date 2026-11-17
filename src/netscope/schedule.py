"""Run NetScope on a schedule: Windows Task Scheduler or cron (Linux, macOS, Termux).

``netscope schedule`` builds the command that runs the scan with the same
options and installs it; ``--dry-run`` only shows what it would do.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

from netscope.network import is_android, is_windows

TASK_NAME = "NetScope"
CRON_MARKER = "# netscope-scheduled-scan"


class ScheduleError(RuntimeError):
    pass


def launcher() -> list[str]:
    """How to start this same NetScope: frozen binary, .pyz archive or the package."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    first = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if first and first.suffix == ".pyz" and first.exists():
        return [sys.executable, str(first.resolve())]
    return [sys.executable, "-m", "netscope"]


def scan_command(out: Path, extra: list[str]) -> list[str]:
    return [*launcher(), "scan", "--out", str(out.resolve()), *extra]


def parse_every(text: str) -> int:
    """'30m', '2h', '45' (minutes) -> minutes."""
    text = text.strip().lower()
    factor = 60 if text.endswith("h") else 1
    number = text.rstrip("mh")
    if not number.isdigit() or int(number) <= 0:
        raise ScheduleError(f"invalid interval '{text}' (examples: 30m, 2h)")
    minutes = int(number) * factor
    if minutes < 5:
        raise ScheduleError("the interval must be at least 5 minutes")
    return minutes


def parse_daily(text: str) -> tuple[int, int]:
    try:
        hour_text, minute_text = text.split(":")
        hour, minute = int(hour_text), int(minute_text)
    except ValueError as exc:
        raise ScheduleError(f"invalid time '{text}' (example: 08:00)") from exc
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise ScheduleError(f"invalid time '{text}'")
    return hour, minute


def windows_create(command: list[str], every: int | None, daily: tuple[int, int] | None):
    task_run = subprocess.list2cmdline(command)
    if every:
        timing = ["/SC", "MINUTE", "/MO", str(every)] if every < 60 or every % 60 else [
            "/SC", "HOURLY", "/MO", str(every // 60)
        ]
    else:
        timing = ["/SC", "DAILY", "/ST", f"{daily[0]:02d}:{daily[1]:02d}"]
    return ["schtasks", "/Create", "/F", "/TN", TASK_NAME, *timing, "/TR", task_run]


def cron_line(command: list[str], every: int | None, daily: tuple[int, int] | None) -> str:
    if every:
        if every < 60:
            timing = f"*/{every} * * * *"
        elif every % 60 == 0 and every < 24 * 60:
            timing = f"0 */{every // 60} * * *"
        else:
            raise ScheduleError("with cron, use an interval below 60 minutes or whole hours")
    else:
        timing = f"{daily[1]} {daily[0]} * * *"
    log = Path(command[command.index("--out") + 1]) / "netscope.log"
    return f"{timing} {shlex.join(command)} >> {shlex.quote(str(log))} 2>&1 {CRON_MARKER}"


def merge_crontab(current: str, line: str | None) -> str:
    kept = [entry for entry in current.splitlines() if CRON_MARKER not in entry]
    if line:
        kept.append(line)
    return "\n".join(kept) + "\n" if kept else ""


def _crontab_read() -> str:
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else ""


def _crontab_write(content: str) -> None:
    result = subprocess.run(["crontab", "-"], input=content, capture_output=True, text=True)
    if result.returncode != 0:
        raise ScheduleError(result.stderr.strip() or "crontab failed")


def install(command: list[str], every: int | None, daily: tuple[int, int] | None,
            dry_run: bool = False) -> str:
    """Install (or show) the scheduled scan. Returns a description of what was done."""
    if is_windows():
        create = windows_create(command, every, daily)
        if dry_run:
            return subprocess.list2cmdline(create)
        result = subprocess.run(create, capture_output=True, text=True)
        if result.returncode != 0:
            raise ScheduleError(result.stderr.strip() or result.stdout.strip())
        return f"Windows task '{TASK_NAME}' created: {subprocess.list2cmdline(command)}"

    line = cron_line(command, every, daily)
    if dry_run:
        return line
    try:
        _crontab_write(merge_crontab(_crontab_read(), line))
    except FileNotFoundError as exc:
        hint = " (Termux: pkg install cronie termux-services, then sv-enable crond)" \
            if is_android() else ""
        raise ScheduleError(f"crontab is not installed{hint}") from exc
    return f"cron entry added: {line}"


def remove(dry_run: bool = False) -> str:
    if is_windows():
        command = ["schtasks", "/Delete", "/F", "/TN", TASK_NAME]
        if dry_run:
            return subprocess.list2cmdline(command)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise ScheduleError(result.stderr.strip() or "task not found")
        return f"Windows task '{TASK_NAME}' removed"
    if dry_run:
        return f"remove crontab lines containing '{CRON_MARKER}'"
    try:
        _crontab_write(merge_crontab(_crontab_read(), None))
    except FileNotFoundError as exc:
        raise ScheduleError("crontab is not installed") from exc
    return "cron entry removed"
