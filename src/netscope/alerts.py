"""Telegram and email alerts for new devices, risky ports and serious findings.

Settings live in a JSON file (see ``alerts.example.json``); secrets only in
environment variables:

* ``NETSCOPE_TELEGRAM_TOKEN``: the bot token from @BotFather.
* ``NETSCOPE_SMTP_PASSWORD``: the SMTP password (or app password).

Each alert has a key. Keys already sent are stored in ``alerts-state.json`` so
nothing is reported twice; a finding that goes away leaves the state and is
reported again if it comes back.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from netscope.classify import SEVERITY_ORDER
from netscope.inventory import device_key

TOKEN_ENV = "NETSCOPE_TELEGRAM_TOKEN"
PASSWORD_ENV = "NETSCOPE_SMTP_PASSWORD"
MAX_REMEMBERED_EVENTS = 1000

DEFAULT_CONFIG = {
    "title": "NetScope",
    "minLevel": "crit",
    "newDevices": True,
    "openedRiskyPorts": True,
    "telegram": {"enabled": False, "chatId": ""},
    "email": {"enabled": False, "server": "", "port": 587, "security": "starttls",
              "user": "", "from": "", "to": []},
}


class AlertError(RuntimeError):
    pass


def load_config(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AlertError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:
        raise AlertError(f"{path} is not valid JSON: {exc}") from exc
    config = {**DEFAULT_CONFIG, **data}
    if config["minLevel"] not in ("crit", "warn", "info"):
        raise AlertError("minLevel must be 'crit', 'warn' or 'info'")
    return config


def _label(item: dict) -> str:
    name = item.get("name") or item.get("vendor")
    return f"{item['ip']} ({name})" if name else item["ip"]


def candidates(scan: dict, config: dict) -> list[dict]:
    """Every alert the scan could raise, each with a stable key."""
    limit = SEVERITY_ORDER[config["minLevel"]]
    alerts: list[dict] = []
    for device in scan["devices"]:
        key = device_key(device)
        name = device.get("label") or device.get("hostname")
        if device.get("new") and config.get("newDevices", True):
            alerts.append({
                "key": f"new|{key}", "event": True, "severity": "warn", "ip": device["ip"],
                "name": name, "vendor": device.get("vendor"),
                "text": "New device on the network"
                + (f" - {device['vendor']}" if device.get("vendor") else ""),
            })
        for item in device["findings"]:
            if item["code"] == "new_device" or SEVERITY_ORDER[item["severity"]] > limit:
                continue
            alerts.append({
                "key": f"finding|{key}|{item['code']}|{item.get('port', '')}", "event": False,
                "severity": item["severity"], "ip": device["ip"], "name": name,
                "vendor": device.get("vendor"), "text": item["message"],
            })
    if config.get("openedRiskyPorts", True):
        for change in (scan.get("changes") or {}).get("items", []):
            if change["kind"] == "ports_opened" and change["severity"] == "warn":
                ports = ", ".join(map(str, change["ports"]))
                alerts.append({
                    "key": f"opened|{change['key']}|{ports}|{scan['finished']}", "event": True,
                    "severity": "warn", "ip": change["ip"], "name": change.get("name"),
                    "vendor": change.get("vendor"), "text": f"Ports opened: {ports}",
                })
    return alerts


def select_new(alerts: list[dict], sent: list[str]) -> tuple[list[dict], list[str]]:
    """Alerts not sent before, and the state to save afterwards."""
    sent_set = set(sent)
    new = [a for a in alerts if a["key"] not in sent_set]
    current = [a["key"] for a in alerts if not a["event"]]
    events = [k for k in sent if not k.startswith("finding|")]
    events += [a["key"] for a in alerts if a["event"] and a["key"] not in sent_set]
    return new, current + events[-MAX_REMEMBERED_EVENTS:]


def format_message(alerts: list[dict], scan: dict, title: str) -> str:
    marks = {"crit": "[CRITICAL]", "warn": "[WARNING]", "info": "[INFO]"}
    ordered = sorted(alerts, key=lambda a: SEVERITY_ORDER[a["severity"]])
    lines = [f"{title}: {len(alerts)} alert(s) on {scan['network']}"]
    lines += [f"{marks[a['severity']]} {_label(a)}: {a['text']}" for a in ordered]
    return "\n".join(lines)


def send_telegram(token: str, chat_id: str, text: str, timeout: float = 20) -> None:
    body = json.dumps({"chat_id": chat_id, "text": text, "disable_web_page_preview": True})
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed host)
        if response.status != 200:
            raise AlertError(f"Telegram answered HTTP {response.status}")


def send_email(settings: dict, subject: str, text: str, timeout: float = 30) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings["from"]
    message["To"] = ", ".join(settings["to"])
    message.set_content(text)
    context = ssl.create_default_context()
    security = settings.get("security", "starttls")
    port = int(settings.get("port") or (465 if security == "ssl" else 587))
    if security == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            settings["server"], port, timeout=timeout, context=context
        )
    else:
        client = smtplib.SMTP(settings["server"], port, timeout=timeout)
    with client:
        if security == "starttls":
            client.starttls(context=context)
        if settings.get("user"):
            password = os.environ.get(PASSWORD_ENV)
            if not password:
                raise AlertError(f"set the {PASSWORD_ENV} environment variable")
            client.login(settings["user"], password)
        client.send_message(message)


def deliver(config: dict, text: str) -> list[str]:
    """Send ``text`` through every enabled channel; returns the channels used."""
    used: list[str] = []
    telegram, email = config.get("telegram") or {}, config.get("email") or {}
    if telegram.get("enabled"):
        token = os.environ.get(TOKEN_ENV)
        if not token:
            raise AlertError(f"set the {TOKEN_ENV} environment variable")
        send_telegram(token, str(telegram["chatId"]), text)
        used.append("telegram")
    if email.get("enabled"):
        send_email(email, text.split("\n", 1)[0], text)
        used.append("email")
    if not used:
        raise AlertError("no alert channel is enabled in the settings file")
    return used


def run_alerts(scan: dict, config_path: Path, state_path: Path) -> tuple[int, list[str]]:
    """Send the new alerts of ``scan``. Returns (alerts sent, channels used)."""
    config = load_config(config_path)
    try:
        sent = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        sent = []
    new, state = select_new(candidates(scan, config), [str(k) for k in sent])
    channels: list[str] = []
    if new:
        channels = deliver(config, format_message(new, scan, config["title"]))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")
    return len(new), channels
