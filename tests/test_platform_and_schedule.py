import socket
import sys
import zipfile
from pathlib import Path

import pytest

from netscope import discovery, network, schedule

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "system, expected",
    [
        ("Windows", ["ping", "-n", "1", "-w", "800", "10.0.0.1"]),
        ("Darwin", ["ping", "-c", "1", "-W", "800", "10.0.0.1"]),
        ("Linux", ["ping", "-c", "1", "-W", "1", "10.0.0.1"]),
    ],
)
def test_ping_command_per_platform(system, expected):
    assert discovery.ping_command("10.0.0.1", 800, system) == expected


MACOS_IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:1:2:3
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
"""


def test_macos_ifconfig_gives_prefix_and_mac():
    assert network.parse_ifconfig(MACOS_IFCONFIG, "192.168.1.20") == {
        "prefix": 24, "mac": "A4:83:E7:01:02:03",
    }


def test_dotted_netmask_is_understood():
    text = "eth0: flags=4163<UP>\n        inet 10.0.0.5 netmask 255.255.252.0\n"
    assert network.parse_ifconfig(text, "10.0.0.5") == {"prefix": 22}


def test_android_is_detected(monkeypatch):
    monkeypatch.setenv("TERMUX_VERSION", "0.118")
    assert network.is_android()
    assert network.platform_name() == "Android"
    assert discovery.read_neighbors() == {}


def test_tcp_sweep_counts_refused_connections_as_alive(monkeypatch):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free = sock.getsockname()[1]
    monkeypatch.setattr(discovery, "TCP_DISCOVERY_PORTS", (free,))
    # Windows retries a refused connection for ~2 s before reporting it
    assert discovery.tcp_sweep(["127.0.0.1"], timeout=4) == {"127.0.0.1"}


# ---------------------------------------------------------------- schedule


@pytest.mark.parametrize("text, minutes", [("30m", 30), ("2h", 120), ("45", 45)])
def test_parse_every(text, minutes):
    assert schedule.parse_every(text) == minutes


@pytest.mark.parametrize("text", ["0m", "2m", "abc", "-5"])
def test_parse_every_rejects(text):
    with pytest.raises(schedule.ScheduleError):
        schedule.parse_every(text)


def test_parse_daily():
    assert schedule.parse_daily("08:30") == (8, 30)
    with pytest.raises(schedule.ScheduleError):
        schedule.parse_daily("25:00")


COMMAND = ["/usr/bin/python3", "-m", "netscope", "scan", "--out", "/home/me/net scans", "--alert"]


def test_cron_line_every_and_daily():
    line = schedule.cron_line(COMMAND, 30, None)
    assert line.startswith("*/30 * * * * /usr/bin/python3 -m netscope scan --out '/home/me/net scans'")
    assert line.endswith(schedule.CRON_MARKER)
    assert schedule.cron_line(COMMAND, 120, None).startswith("0 */2 * * * ")
    assert schedule.cron_line(COMMAND, None, (8, 5)).startswith("5 8 * * * ")
    with pytest.raises(schedule.ScheduleError):
        schedule.cron_line(COMMAND, 90, None)


def test_merge_crontab_replaces_only_our_line():
    current = f"0 1 * * * backup\n*/5 * * * * old {schedule.CRON_MARKER}\n"
    merged = schedule.merge_crontab(current, f"new {schedule.CRON_MARKER}")
    assert merged == f"0 1 * * * backup\nnew {schedule.CRON_MARKER}\n"
    assert schedule.merge_crontab(merged, None) == "0 1 * * * backup\n"


def test_windows_task_command():
    command = ["C:\\Program Files\\NetScope\\netscope.exe", "scan", "--out", "C:\\Net Scans"]
    create = schedule.windows_create(command, 30, None)
    assert create[:5] == ["schtasks", "/Create", "/F", "/TN", "NetScope"]
    assert create[5:9] == ["/SC", "MINUTE", "/MO", "30"]
    assert create[-1] == '"C:\\Program Files\\NetScope\\netscope.exe" scan --out "C:\\Net Scans"'
    assert schedule.windows_create(command, 120, None)[5:9] == ["/SC", "HOURLY", "/MO", "2"]
    assert schedule.windows_create(command, None, (7, 0))[5:9] == ["/SC", "DAILY", "/ST", "07:00"]


def test_launcher_for_package_and_pyz(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["netscope"])
    assert schedule.launcher() == [sys.executable, "-m", "netscope"]
    archive = tmp_path / "netscope.pyz"
    archive.write_bytes(b"")
    monkeypatch.setattr(sys, "argv", [str(archive)])
    assert schedule.launcher() == [sys.executable, str(archive.resolve())]


def test_schedule_dry_run_from_cli(capsys, tmp_path):
    from netscope import cli

    code = cli.main(["schedule", "--every", "1h", "--alert", "--quick",
                     "--out", str(tmp_path), "--dry-run"])
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "scan --out" in out and "--quick" in out and "--alert" in out


# ---------------------------------------------------------------- packaging


def test_pyz_contains_the_package_and_template(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "tools"))
    import build

    monkeypatch.setattr(build, "DIST", tmp_path)
    archive = build.build_pyz()
    names = zipfile.ZipFile(archive).namelist()
    assert "__main__.py" in names
    assert "netscope/templates/report.html" in names
    assert not any("__pycache__" in name for name in names)


def test_release_notes_section():
    sys.path.insert(0, str(ROOT / "tools"))
    import release_notes

    text = "# Changelog\n\n## 1.2.0 - 2026-11-20\n\n- New thing\n\n## 1.1.0\n\n- Old\n"
    assert release_notes.section("1.2.0", text) == "- New thing"
    with pytest.raises(SystemExit):
        release_notes.section("9.9.9", text)
