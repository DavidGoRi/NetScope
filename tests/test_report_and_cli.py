import ipaddress
import json
import re
import sys
from pathlib import Path

from netscope import cli, report, scanner
from netscope.network import LocalInterface

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import make_demo  # noqa: E402


def extract_data(html):
    match = re.search(r"const SCAN = (.*?);\n", html)
    return json.loads(match.group(1))


def test_report_embeds_the_scan():
    scan = make_demo.build_scan()
    html = report.render(scan)
    assert "/*NETSCOPE_DATA*/" not in html
    assert extract_data(html)["network"] == "10.20.0.0/24"


def test_hostile_host_names_cannot_break_out_of_the_script():
    scan = make_demo.build_scan()
    scan["devices"][0]["hostname"] = "</script><img src=x onerror=alert(1)>"
    html = report.render(scan)
    assert "</script><img" not in html
    assert extract_data(html)["devices"][0]["hostname"].startswith("</script>")


def test_every_type_and_finding_is_translated():
    template = report.render(make_demo.build_scan())
    from netscope import classify

    for code in classify.FINDINGS:
        assert template.count(f"{code}:") >= 2, code  # English and Spanish
    for device_type in classify.DEVICE_TYPES:
        key = f'"{device_type}":' if "-" in device_type else f"{device_type}:"
        assert template.count(key) >= 2, device_type


def test_public_target_is_refused_before_scanning(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "run_scan", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert cli.main(["scan", "--cidr", "8.8.8.0/24"]) == cli.EXIT_USAGE
    assert "not a private network" in capsys.readouterr().err


def test_bad_port_list_is_a_usage_error(capsys):
    assert cli.main(["scan", "--ports", "0"]) == cli.EXIT_USAGE


def test_no_command_prints_help(capsys):
    assert cli.main([]) == cli.EXIT_USAGE
    assert "scan" in capsys.readouterr().out


def fake_network(monkeypatch):
    """Replace every network call with a tiny fictional LAN."""
    from netscope import discovery, ports

    monkeypatch.setattr(
        cli, "detect_interface",
        lambda: LocalInterface("192.168.50.2", 24, "AA:BB:CC:00:00:02", "192.168.50.1"),
    )
    monkeypatch.setattr(discovery, "ping_sweep", lambda ips, timeout_ms: {"192.168.50.1"})
    monkeypatch.setattr(
        discovery, "read_neighbors",
        lambda: {"192.168.50.1": "B8:27:EB:00:00:01", "192.168.50.9": "D2:00:00:00:00:09",
                 "10.9.9.9": "AA:AA:AA:AA:AA:AA"},
    )
    monkeypatch.setattr(discovery, "resolve_names", lambda ips: {"192.168.50.1": "router.lan"})
    monkeypatch.setattr(
        ports, "scan_ports",
        lambda hosts, port_list, timeout: {h: [23, 80] if h.endswith(".1") else [] for h in hosts},
    )


def test_full_scan_end_to_end(monkeypatch, tmp_path, capsys):
    fake_network(monkeypatch)
    code = cli.main(["scan", "--out", str(tmp_path), "--fail-on", "crit"])
    assert code == cli.EXIT_FINDINGS  # telnet on the router
    out = capsys.readouterr().out
    assert "192.168.50.1" in out and "10.9.9.9" not in out
    saved = json.loads(next((tmp_path / "scans").glob("scan-*.json")).read_text("utf-8"))
    by_ip = {d["ip"]: d for d in saved["devices"]}
    assert set(by_ip) == {"192.168.50.1", "192.168.50.2", "192.168.50.9"}
    assert by_ip["192.168.50.1"]["type"] == "router"
    assert by_ip["192.168.50.1"]["vendor"] == "Raspberry Pi Foundation"
    assert by_ip["192.168.50.2"]["is_self"]
    assert by_ip["192.168.50.9"]["randomized_mac"]
    assert saved["baseline"] is True
    assert (tmp_path / "netscope-report.html").exists()
    assert (tmp_path / "known_devices.json").exists()


def test_report_command_rebuilds_dashboard(tmp_path):
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(make_demo.build_scan()), encoding="utf-8")
    assert cli.main(["report", str(scan_file)]) == cli.EXIT_OK
    assert (tmp_path / "scan.html").exists()


def test_should_fail_levels():
    scan = {"devices": [{"new": False, "findings": [{"severity": "warn"}]}]}
    assert not cli.should_fail(scan, None)
    assert not cli.should_fail(scan, "crit")
    assert cli.should_fail(scan, "warn")
    assert not cli.should_fail(scan, "new")


def test_run_scan_ignores_hosts_outside_target(monkeypatch):
    fake_network(monkeypatch)
    result = scanner.run_scan(ipaddress.ip_network("192.168.50.0/24"), oui={}, port_list=[])
    assert all(d["ip"].startswith("192.168.50.") for d in result["devices"])
