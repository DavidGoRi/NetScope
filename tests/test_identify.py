"""Identification probes: wire-format parsers offline, live probes on loopback."""

import contextlib
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

import pytest

from netscope import identify

DATA = Path(__file__).parent / "data"


# ---------------------------------------------------------------- DNS / mDNS


def rr(name, rtype, rdata):
    return identify.encode_name(name) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def txt(**values):
    return b"".join(bytes([len(f"{k}={v}")]) + f"{k}={v}".encode() for k, v in values.items())


def mdns_response(*records, questions=()):
    header = struct.pack("!HHHHHH", 0, 0x8400, len(questions), len(records), 0, 0)
    body = b"".join(identify.encode_name(q) + struct.pack("!HH", 12, 1) for q in questions)
    return header + body + b"".join(records)


def test_dns_query_round_trip():
    packet = identify.dns_query([("_services._dns-sd._udp.local", 12)])
    assert struct.unpack("!H", packet[4:6])[0] == 1
    assert identify.read_name(packet, 12) == ("_services._dns-sd._udp.local", 12 + 30)


def test_compressed_names_are_followed():
    # "tv.local" at offset 12, then a pointer to it
    data = b"\x00" * 12 + identify.encode_name("tv.local") + b"\xc0\x0c"
    assert identify.read_name(data, 22) == ("tv.local", 24)


def test_compression_loop_is_rejected():
    data = b"\x00" * 12 + b"\xc0\x0c"
    with pytest.raises(ValueError):
        identify.read_name(data, 12)


def test_mdns_cast_device_is_summarised():
    packet = mdns_response(
        rr("_services._dns-sd._udp.local", 12, identify.encode_name("_googlecast._tcp.local")),
        rr("_googlecast._tcp.local", 12, identify.encode_name("Chromecast-abc._googlecast._tcp.local")),
        rr("Chromecast-abc._googlecast._tcp.local", 16, txt(md="Chromecast", fn="Living room TV")),
        rr("chromecast-abc.local", 1, socket.inet_aton("192.168.1.30")),
    )
    info = identify.summarize_mdns({"192.168.1.30": identify.parse_dns(packet)})["192.168.1.30"]
    assert info["services"] == ["googlecast._tcp"]
    assert info["friendly_name"] == "Living room TV"
    assert info["model"] == "Chromecast"
    assert info["mdns_name"] == "chromecast-abc"


def test_mdns_records_about_other_hosts_do_not_name_the_sender():
    packet = mdns_response(rr("other.local", 1, socket.inet_aton("192.168.1.99")))
    assert "mdns_name" not in identify.summarize_mdns(
        {"192.168.1.30": identify.parse_dns(packet)}
    ).get("192.168.1.30", {})


def test_txt_parsing():
    assert identify.parse_txt(txt(model="MacBookPro18,3", ty="HP LaserJet")) == {
        "model": "MacBookPro18,3", "ty": "HP LaserJet",
    }


# ---------------------------------------------------------------- SSDP / UPnP

UPNP_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Office router</friendlyName>
    <manufacturer>Example Networks</manufacturer>
    <modelName>XR-500</modelName>
    <modelNumber>XR500-EU</modelNumber>
    <deviceList><device><friendlyName>WAN device</friendlyName></device></deviceList>
  </device>
</root>"""


def test_upnp_description_uses_the_root_device():
    assert identify.parse_upnp_description(UPNP_XML) == {
        "device_type": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "friendly_name": "Office router",
        "manufacturer": "Example Networks",
        "model_name": "XR-500",
        "model_number": "XR500-EU",
    }


def test_ssdp_headers():
    raw = b"HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1:1900/d.xml\r\nSERVER: Linux UPnP/1.0\r\n\r\n"
    headers = identify.parse_ssdp(raw)
    assert headers["location"] == "http://10.0.0.1:1900/d.xml"
    assert headers["server"] == "Linux UPnP/1.0"


# ---------------------------------------------------------------- NetBIOS


def nbstat_reply(*names):
    entries = b"".join(
        name.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags)
        for name, suffix, flags in names
    )
    rdata = bytes([len(names)]) + entries + b"\x00" * 6
    answer = b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack("!HHIH", 0x21, 1, 0, len(rdata))
    return struct.pack("!HHHHHH", 0x4E53, 0x8400, 0, 1, 0, 0) + answer + rdata


def test_nbstat_names_and_workgroup():
    reply = nbstat_reply(("OFFICE", 0x00, 0x8400), ("DESKTOP-IT", 0x00, 0x0400),
                         ("DESKTOP-IT", 0x20, 0x0400))
    assert identify.parse_nbstat(reply) == {"netbios_name": "DESKTOP-IT", "workgroup": "OFFICE"}


def test_nbstat_query_asks_for_the_wildcard_name():
    assert identify.NBSTAT_QUERY[12:46] == b"\x20CK" + b"A" * 30 + b"\x00"


# ---------------------------------------------------------------- banners, TLS, SMB


def test_parse_http_title_and_server():
    raw = (b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4\r\n\r\n"
           b"<html><head><TITLE>\n  Router &amp; Admin </TITLE></head></html>")
    assert identify.parse_http(raw) == {"status": 200, "server": "lighttpd/1.4",
                                        "title": "Router & Admin"}


def test_cert_info_detects_self_signed_and_expiry():
    der = ssl.PEM_cert_to_DER_cert((DATA / "selfsigned.pem").read_text())
    info = identify.cert_info(der)
    assert info["subject"] == "netscope-test"
    assert info["self_signed"] is True
    assert info["days_left"] > 300
    expired = identify.cert_info(der, now=time.time() + 20 * 365 * 86400)
    assert expired["days_left"] < 0


@pytest.fixture
def server():
    """A loopback TCP server; the test gives it a handler(conn) function."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    handler = {"fn": lambda conn: None}
    stop = threading.Event()

    def loop():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            with conn, contextlib.suppress(OSError):
                handler["fn"](conn)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield sock.getsockname()[1], handler
    stop.set()
    thread.join(1)
    sock.close()


def http_handler(conn):
    conn.recv(4096)
    conn.sendall(b"HTTP/1.0 200 OK\r\nServer: test-httpd\r\n\r\n<title>NAS login</title>")


def test_http_probe_reads_title(server):
    port, handler = server
    handler["fn"] = http_handler
    assert identify.http_probe("127.0.0.1", port, tls=False) == {
        "status": 200, "server": "test-httpd", "title": "NAS login",
    }


def test_https_probe_reads_certificate(server):
    port, handler = server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(DATA / "selfsigned.pem", DATA / "selfsigned.key")

    def tls_handler(conn):
        with context.wrap_socket(conn, server_side=True) as tls:
            http_handler(tls)

    handler["fn"] = tls_handler
    info = identify.http_probe("127.0.0.1", port, tls=True)
    assert info["title"] == "NAS login"
    assert info["cert"]["self_signed"] is True


def test_greeting_line(server):
    port, handler = server
    handler["fn"] = lambda conn: conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
    assert identify.greeting("127.0.0.1", port) == "SSH-2.0-OpenSSH_9.6"


def test_smb1_accepted(server):
    port, handler = server

    def smb1(conn):
        conn.recv(1024)
        body = b"\xffSMB\x72" + b"\x00" * 4 + b"\x98" + b"\x00" * 30
        conn.sendall(struct.pack("!I", len(body)) + body)

    handler["fn"] = smb1
    assert identify.smb1_enabled("127.0.0.1", port) is True


def test_smb1_refused_when_server_answers_smb2(server):
    port, handler = server

    def smb2(conn):
        conn.recv(1024)
        body = b"\xfeSMB" + b"\x00" * 60
        conn.sendall(struct.pack("!I", len(body)) + body)

    handler["fn"] = smb2
    assert identify.smb1_enabled("127.0.0.1", port) is False


def test_smb1_refused_when_server_hangs_up(server):
    port, handler = server
    handler["fn"] = lambda conn: conn.recv(1024)
    assert identify.smb1_enabled("127.0.0.1", port) is False


def test_identify_skips_non_private_hosts(monkeypatch):
    monkeypatch.setattr(identify, "mdns_discover", lambda hosts, timeout, local_ip: {})
    monkeypatch.setattr(identify, "ssdp_discover", lambda hosts, timeout, local_ip: {})
    monkeypatch.setattr(identify, "netbios_discover", lambda hosts, timeout, local_ip: {})
    calls = []
    monkeypatch.setattr(identify, "banners_for", lambda ip, ports: calls.append(ip) or {"ssh": "x"})
    result = identify.identify(["8.8.8.8", "192.168.1.5"], {"8.8.8.8": [22], "192.168.1.5": [22]})
    assert calls == ["192.168.1.5"]
    assert result == {"192.168.1.5": {"ssh": "x"}}
