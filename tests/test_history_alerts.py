import json

import pytest

from netscope import alerts, history


def device(ip, mac, ports=(), name=None, new=False, findings=()):
    return {"ip": ip, "mac": mac, "open_ports": list(ports), "hostname": name, "new": new,
            "vendor": None, "findings": list(findings)}


def scan(*devices, finished="2026-11-17T10:00:00+01:00", network="192.168.1.0/24"):
    return {"network": network, "finished": finished, "devices": list(devices)}


# ---------------------------------------------------------------- history


def test_diff_detects_every_kind_of_change():
    before = scan(
        device("192.168.1.10", "AA:00:00:00:00:01", [80], name="nas"),
        device("192.168.1.11", "AA:00:00:00:00:02", [22, 445]),
        device("192.168.1.12", "AA:00:00:00:00:03"),
    )
    after = scan(
        device("192.168.1.20", "AA:00:00:00:00:01", [80], name="nas-01"),
        device("192.168.1.11", "AA:00:00:00:00:02", [22, 3389]),
        device("192.168.1.13", "AA:00:00:00:00:04", new=True),
        device("192.168.1.14", "AA:00:00:00:00:05"),
    )
    kinds = {(c["kind"], c["ip"]) for c in history.diff_scans(before, after)}
    assert kinds == {
        ("ip_changed", "192.168.1.20"), ("name_changed", "192.168.1.20"),
        ("ports_opened", "192.168.1.11"), ("ports_closed", "192.168.1.11"),
        ("new_device", "192.168.1.13"), ("appeared", "192.168.1.14"),
        ("disappeared", "192.168.1.12"),
    }


def test_risky_opened_port_is_a_warning():
    before = scan(device("192.168.1.11", "AA:00:00:00:00:02", [22]))
    after = scan(device("192.168.1.11", "AA:00:00:00:00:02", [22, 3389]))
    (change,) = history.diff_scans(before, after)
    assert change["severity"] == "warn" and change["ports"] == [3389]


def test_apply_history_with_and_without_previous_scans():
    current = scan(device("192.168.1.10", "AA:00:00:00:00:01"))
    history.apply_history(current, [])
    assert current["changes"] == {"since": None, "items": []}

    older = scan(finished="2026-11-16T10:00:00+01:00")
    older["changes"] = {"since": "2026-11-15T10:00:00+01:00",
                        "items": [{"kind": "appeared", "ip": "192.168.1.9"}]}
    history.apply_history(current, [older])
    assert current["changes"]["since"] == "2026-11-16T10:00:00+01:00"
    assert current["changes"]["items"][0]["kind"] == "appeared"
    assert current["history"][0]["scan"] == "2026-11-16T10:00:00+01:00"


def test_load_scans_filters_network_and_sorts_newest_first(tmp_path):
    for stamp, network in (("20261115-100000", "192.168.1.0/24"),
                           ("20261116-100000", "10.0.0.0/24"),
                           ("20261117-100000", "192.168.1.0/24")):
        (tmp_path / f"scan-{stamp}.json").write_text(
            json.dumps(scan(finished=stamp, network=network)), encoding="utf-8")
    (tmp_path / "scan-broken.json").write_text("{", encoding="utf-8")
    found = history.load_scans(tmp_path, "192.168.1.0/24")
    assert [s["finished"] for s in found] == ["20261117-100000", "20261115-100000"]


# ---------------------------------------------------------------- alerts

TELNET = {"code": "telnet_open", "severity": "crit", "message": "Telnet open.", "port": 23}
SMB = {"code": "smb_open", "severity": "info", "message": "SMB.", "port": 445}


def config(**overrides):
    return {**alerts.DEFAULT_CONFIG, **overrides}


def test_candidates_respect_level_and_new_devices():
    current = scan(
        device("192.168.1.5", "AA:00:00:00:00:05", findings=[TELNET, SMB]),
        device("192.168.1.6", "AA:00:00:00:00:06", new=True),
    )
    found = alerts.candidates(current, config(minLevel="crit"))
    assert {a["key"] for a in found} == {
        "finding|AA:00:00:00:00:05|telnet_open|23", "new|AA:00:00:00:00:06",
    }
    assert len(alerts.candidates(current, config(minLevel="info", newDevices=False))) == 2


def test_alerts_are_not_repeated_and_return_when_issue_comes_back():
    current = scan(device("192.168.1.5", "AA:00:00:00:00:05", findings=[TELNET]))
    first, state = alerts.select_new(alerts.candidates(current, config()), [])
    assert len(first) == 1
    again, state = alerts.select_new(alerts.candidates(current, config()), state)
    assert again == []
    fixed = scan(device("192.168.1.5", "AA:00:00:00:00:05"))
    _, state = alerts.select_new(alerts.candidates(fixed, config()), state)
    assert state == []
    back, _ = alerts.select_new(alerts.candidates(current, config()), state)
    assert len(back) == 1


def test_new_device_events_are_remembered():
    current = scan(device("192.168.1.6", "AA:00:00:00:00:06", new=True))
    _, state = alerts.select_new(alerts.candidates(current, config()), [])
    assert state == ["new|AA:00:00:00:00:06"]
    later = scan(device("192.168.1.6", "AA:00:00:00:00:06"))
    _, state = alerts.select_new(alerts.candidates(later, config()), state)
    assert state == ["new|AA:00:00:00:00:06"]


def test_message_lists_the_worst_first():
    current = scan(
        device("192.168.1.6", "AA:00:00:00:00:06", new=True, name="tablet"),
        device("192.168.1.5", "AA:00:00:00:00:05", findings=[TELNET]),
    )
    text = alerts.format_message(alerts.candidates(current, config()), current, "Office")
    lines = text.splitlines()
    assert lines[0] == "Office: 2 alert(s) on 192.168.1.0/24"
    assert lines[1].startswith("[CRITICAL] 192.168.1.5")
    assert lines[2] == "[WARNING] 192.168.1.6 (tablet): New device on the network"


def test_run_alerts_sends_once_and_saves_state(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setenv(alerts.TOKEN_ENV, "test-token")
    monkeypatch.setattr(alerts, "send_telegram", lambda token, chat, text: sent.append(text))
    settings = tmp_path / "alerts.json"
    settings.write_text(json.dumps({"telegram": {"enabled": True, "chatId": "42"}}), "utf-8")
    state = tmp_path / "state.json"
    current = scan(device("192.168.1.5", "AA:00:00:00:00:05", findings=[TELNET]))
    assert alerts.run_alerts(current, settings, state) == (1, ["telegram"])
    assert alerts.run_alerts(current, settings, state) == (0, [])
    assert len(sent) == 1


def test_missing_token_is_reported(tmp_path, monkeypatch):
    monkeypatch.delenv(alerts.TOKEN_ENV, raising=False)
    with pytest.raises(alerts.AlertError, match=alerts.TOKEN_ENV):
        alerts.deliver(config(telegram={"enabled": True, "chatId": "1"}), "hi")


def test_no_channel_enabled_is_an_error():
    with pytest.raises(alerts.AlertError, match="no alert channel"):
        alerts.deliver(config(), "hi")


def test_invalid_settings(tmp_path):
    bad = tmp_path / "alerts.json"
    bad.write_text('{"minLevel": "loud"}', "utf-8")
    with pytest.raises(alerts.AlertError):
        alerts.load_config(bad)
    with pytest.raises(alerts.AlertError):
        alerts.load_config(tmp_path / "missing.json")


def test_email_uses_starttls_and_password_from_environment(monkeypatch):
    events = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            events.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context):
            events.append(("starttls",))

        def login(self, user, password):
            events.append(("login", user, password))

        def send_message(self, message):
            events.append(("send", message["To"], message["Subject"]))

    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv(alerts.PASSWORD_ENV, "secret")
    alerts.send_email({"server": "smtp.example.com", "port": 587, "user": "me@example.com",
                       "from": "me@example.com", "to": ["it@example.com"]}, "Subject", "Body")
    assert events == [("connect", "smtp.example.com", 587), ("starttls",),
                      ("login", "me@example.com", "secret"),
                      ("send", "it@example.com", "Subject")]
