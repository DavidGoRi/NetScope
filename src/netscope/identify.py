"""Extra identification probes, all read-only and unprivileged.

* mDNS / DNS-SD: phones, Macs, printers, TVs and smart speakers announce their
  name, model and services (``_googlecast._tcp``, ``_ipp._tcp``...).
* SSDP / UPnP: routers, TVs and NAS describe themselves in an XML document.
* NetBIOS name service: Windows PCs and Samba servers tell their computer name
  and workgroup.
* Service banners: the <title> and Server header of web interfaces, the SSH and
  FTP greeting lines and the HTTPS certificate.
* SMBv1: whether a file server still accepts the protocol WannaCry used.

Every probe has a short timeout and failures are silent: a device that does
not answer simply keeps the information discovery already gave.
"""

from __future__ import annotations

import contextlib
import html
import ipaddress
import os
import re
import socket
import ssl
import struct
import tempfile
import time
import urllib.parse
import urllib.request
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from xml.etree import ElementTree

from netscope import __version__

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
USER_AGENT = f"NetScope/{__version__}"

HTTP_PORTS = {80, 5000, 8008, 8080, 8123, 32400}
HTTPS_PORTS = {443, 5001, 8443}

# ---------------------------------------------------------------- DNS wire format


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(questions: Iterable[tuple[str, int]], query_id: int = 0) -> bytes:
    items = list(questions)
    header = struct.pack("!HHHHHH", query_id, 0, len(items), 0, 0, 0)
    return header + b"".join(encode_name(n) + struct.pack("!HH", t, 1) for n, t in items)


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; returns the name and the next offset."""
    labels: list[str] = []
    end: int | None = None
    for _ in range(64):  # bounded: compression loops in hostile packets
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    raise ValueError("DNS name too long or looping")


def parse_txt(rdata: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    pos = 0
    while pos < len(rdata):
        length = rdata[pos]
        chunk = rdata[pos + 1 : pos + 1 + length].decode("utf-8", "replace")
        pos += 1 + length
        key, _, value = chunk.partition("=")
        if key:
            values[key.lower()] = value
    return values


def parse_dns(data: bytes) -> list[tuple[str, int, object]]:
    """Answer, authority and additional records as (name, type, value).

    Only A (1), PTR (12), TXT (16) and SRV (33, value = target host) are kept.
    """
    _qid, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4
    records: list[tuple[str, int, object]] = []
    for _ in range(an + ns + ar):
        name, offset = read_name(data, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        start, offset = offset, offset + rdlen
        if rtype == 1 and rdlen == 4:
            records.append((name, 1, socket.inet_ntoa(rdata)))
        elif rtype == 12:
            records.append((name, 12, read_name(data, start)[0]))
        elif rtype == 16:
            records.append((name, 16, parse_txt(rdata)))
        elif rtype == 33 and rdlen > 6:
            records.append((name, 33, read_name(data, start + 6)[0]))
    return records


def _strip_local(name: str) -> str:
    return re.sub(r"\.local\.?$", "", name, flags=re.IGNORECASE)


MODEL_KEYS = ("md", "model", "am", "ty", "usb_mdl", "product")


def summarize_mdns(records_by_ip: dict[str, list[tuple[str, int, object]]]) -> dict[str, dict]:
    """Turn the records each device sent about itself into names, services and model."""
    result: dict[str, dict] = {}
    for ip, records in records_by_ip.items():
        info: dict = {"services": set()}
        for name, rtype, value in records:
            if rtype == 1 and value == ip:
                info.setdefault("mdns_name", _strip_local(name))
            elif rtype == 12 and name.lower().startswith("_services._dns-sd"):
                info["services"].add(_strip_local(str(value)))
            elif rtype == 12 and str(value).lower().endswith(name.lower()):
                info["services"].add(_strip_local(name))
                instance = str(value)[: -len(name) - 1]
                if instance and not instance.startswith("_"):
                    info.setdefault("friendly_name", instance.replace("\\032", " "))
            elif rtype == 16 and isinstance(value, dict):
                if value.get("fn"):
                    info["friendly_name"] = value["fn"]
                for key in MODEL_KEYS:
                    if value.get(key) and "model" not in info:
                        info["model"] = value[key]
        info["services"] = sorted(s.lstrip("_") for s in info["services"] if s)
        if info["services"] or len(info) > 1:
            result[ip] = info
    return result


def _udp_socket(timeout: float, local_ip: str | None = None) -> socket.socket:
    """UDP socket for queries. With ``local_ip`` multicast leaves through that
    interface: on computers with several adapters (VPN, Hyper-V, WSL) the OS may
    otherwise pick the wrong one and no device ever answers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if local_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            sock.bind((local_ip, 0))
            return sock
        except OSError:
            pass
    sock.bind(("", 0))
    return sock


def _receive(sock: socket.socket, deadline: float):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        sock.settimeout(remaining)
        try:
            yield sock.recvfrom(9000)
        except TimeoutError:
            return
        except OSError:
            continue


def mdns_discover(
    hosts: set[str], timeout: float = 2.5, local_ip: str | None = None
) -> dict[str, dict]:
    """Ask the LAN which DNS-SD services exist, then who offers each one.

    Queries come from an ephemeral port, so responders answer by unicast
    ("legacy unicast") and port 5353 does not need to be free.
    """
    records_by_ip: dict[str, list] = {}
    asked: set[str] = set()
    try:
        sock = _udp_socket(timeout, local_ip)
    except OSError:
        return {}
    with sock:
        try:
            sock.sendto(dns_query([("_services._dns-sd._udp.local", 12)]), MDNS_GROUP)
        except OSError:
            return {}
        deadline = time.monotonic() + timeout
        for data, (ip, _port) in _receive(sock, deadline):
            if ip not in hosts:
                continue
            try:
                records = parse_dns(data)
            except (ValueError, IndexError, struct.error):
                continue
            records_by_ip.setdefault(ip, []).extend(records)
            new_types = {
                str(v) for n, t, v in records
                if t == 12 and n.lower().startswith("_services._dns-sd") and str(v) not in asked
            }
            if new_types:
                asked |= new_types
                with contextlib.suppress(OSError):
                    sock.sendto(dns_query((t, 12) for t in sorted(new_types)), MDNS_GROUP)
    return summarize_mdns(records_by_ip)


# ---------------------------------------------------------------- SSDP / UPnP


def parse_ssdp(data: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def parse_upnp_description(xml_text: str) -> dict[str, str]:
    """Root device fields from a UPnP description, ignoring XML namespaces."""
    root = ElementTree.fromstring(xml_text)
    device = next((el for el in root.iter() if el.tag.split("}")[-1] == "device"), None)
    if device is None:
        return {}
    fields = {"friendlyName": "friendly_name", "manufacturer": "manufacturer",
              "modelName": "model_name", "modelNumber": "model_number", "deviceType": "device_type"}
    info: dict[str, str] = {}
    for child in device:
        key = fields.get(child.tag.split("}")[-1])
        if key and child.text and child.text.strip():
            info[key] = " ".join(child.text.split())[:100]
    return info


def _fetch(url: str, limit: int = 65536, timeout: float = 2.5) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (LAN URL, checked)
        return response.read(limit).decode("utf-8", "replace")


def ssdp_discover(
    hosts: set[str], timeout: float = 2.5, local_ip: str | None = None
) -> dict[str, dict]:
    messages = [
        (
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {target}\r\n\r\n'
        ).encode()
        for target in (
            "ssdp:all",
            "upnp:rootdevice",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        )
    ]
    found: dict[str, dict] = {}
    try:
        sock = _udp_socket(timeout, local_ip)
    except OSError:
        return {}
    with sock:
        try:
            for message in messages:
                sock.sendto(message, SSDP_GROUP)
        except OSError:
            return {}
        for data, (ip, _port) in _receive(sock, time.monotonic() + timeout):
            if ip not in hosts:
                continue
            headers = parse_ssdp(data)
            entry = found.setdefault(ip, {"locations": [], "igd": False})
            if headers.get("server"):
                entry["server"] = headers["server"][:120]
            if "internetgatewaydevice" in (headers.get("st", "") + headers.get("nt", "")).lower():
                entry["igd"] = True
            location = headers.get("location", "")
            if location and location not in entry["locations"] and len(entry["locations"]) < 3:
                entry["locations"].append(location)

    for ip, entry in found.items():
        for location in entry.pop("locations"):
            # Only follow descriptions served by the device itself, over plain HTTP.
            parsed = urllib.parse.urlparse(location)
            if parsed.scheme != "http" or parsed.hostname != ip:
                continue
            try:
                entry.update(parse_upnp_description(_fetch(location)))
                break
            except (OSError, ValueError, ElementTree.ParseError):
                continue
    return found


# ---------------------------------------------------------------- NetBIOS

NBSTAT_QUERY = (
    struct.pack("!HHHHHH", 0x4E53, 0, 1, 0, 0, 0)
    + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    + struct.pack("!HH", 0x21, 1)
)


def parse_nbstat(data: bytes) -> dict[str, str]:
    _qid, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4
    if not an:
        return {}
    _, offset = read_name(data, offset)
    offset += 10  # type, class, ttl, rdlength
    count = data[offset]
    offset += 1
    info: dict[str, str] = {}
    for _ in range(count):
        raw = data[offset : offset + 18]
        offset += 18
        if len(raw) < 18:
            break
        name = raw[:15].decode("ascii", "replace").strip()
        suffix, flags = raw[15], struct.unpack("!H", raw[16:18])[0]
        is_group = bool(flags & 0x8000)
        if suffix == 0x00 and not is_group and "netbios_name" not in info:
            info["netbios_name"] = name
        elif suffix == 0x00 and is_group and "workgroup" not in info:
            info["workgroup"] = name
    return info


def netbios_discover(
    hosts: Iterable[str], timeout: float = 1.5, local_ip: str | None = None
) -> dict[str, dict]:
    targets = set(hosts)
    found: dict[str, dict] = {}
    try:
        sock = _udp_socket(timeout, local_ip)
    except OSError:
        return {}
    with sock:
        for ip in targets:
            with contextlib.suppress(OSError):
                sock.sendto(NBSTAT_QUERY, (ip, 137))
        for data, (ip, _port) in _receive(sock, time.monotonic() + timeout):
            if ip in targets:
                with contextlib.suppress(ValueError, IndexError, struct.error):
                    info = parse_nbstat(data)
                    if info:
                        found[ip] = info
    return found


# ---------------------------------------------------------------- banners and TLS

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def parse_http(raw: bytes) -> dict:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    info: dict = {}
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if match:
        info["status"] = int(match.group(1))
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "server" and value.strip():
            info["server"] = value.strip()[:100]
    title = _TITLE_RE.search(body)
    if title:
        text = " ".join(html.unescape(title.group(1).decode("utf-8", "replace")).split())
        if text:
            info["title"] = text[:100]
    return info


def _tls_context() -> ssl.SSLContext:
    # We inspect certificates, we do not trust them: verification is off on purpose
    # and the certificate is judged by cert_info() instead.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def cert_info(der: bytes, now: float | None = None) -> dict:
    """Subject, issuer and expiry of a DER certificate (standard library only)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    handle, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(handle, "w") as file:
            file.write(pem)
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)

    def flat(rdns) -> dict[str, str]:
        return {key: value for rdn in rdns or () for key, value in rdn}

    subject, issuer = flat(decoded.get("subject")), flat(decoded.get("issuer"))
    expires = ssl.cert_time_to_seconds(decoded["notAfter"])
    now = time.time() if now is None else now
    return {
        "subject": subject.get("commonName") or subject.get("organizationName") or "",
        "issuer": issuer.get("commonName") or issuer.get("organizationName") or "",
        "self_signed": subject == issuer,
        "not_after": datetime.fromtimestamp(expires, timezone.utc).date().isoformat(),
        "days_left": int((expires - now) // 86400),
    }


def _connect(ip: str, port: int, timeout: float, tls: bool):
    sock = socket.create_connection((ip, port), timeout=timeout)
    if tls:
        try:
            return _tls_context().wrap_socket(sock)
        except Exception:
            sock.close()
            raise
    return sock


def _read_all(sock, limit: int) -> bytes:
    chunks, size = [], 0
    while size < limit:
        try:
            chunk = sock.recv(4096)
        except (OSError, ssl.SSLError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def http_probe(ip: str, port: int, tls: bool, timeout: float = 3.0) -> dict:
    with _connect(ip, port, timeout, tls) as sock:
        info: dict = {}
        if tls:
            der = sock.getpeercert(binary_form=True)
            if der:
                with contextlib.suppress(Exception):
                    info["cert"] = cert_info(der)
        request = (
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: text/html\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii", "replace"))
        info.update(parse_http(_read_all(sock, 65536)))
        return info


def greeting(ip: str, port: int, timeout: float = 3.0) -> str | None:
    """First line a server sends on connect (SSH, FTP)."""
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        line = sock.recv(256).split(b"\n", 1)[0]
    text = line.decode("utf-8", "replace").strip()
    return text[:100] or None


SMB1_NEGOTIATE = (
    b"\xffSMB\x72" + b"\x00" * 4 + b"\x18" + b"\x53\xc8" + b"\x00" * 12
    + b"\x00\x00" + b"\xff\xfe" + b"\x00\x00" + b"\x00\x00"
    + b"\x00" + struct.pack("<H", 12) + b"\x02NT LM 0.12\x00"
)


def smb1_enabled(ip: str, port: int = 445, timeout: float = 3.0) -> bool | None:
    """True if the server accepts an SMBv1-only negotiation, False if it refuses it."""
    packet = struct.pack("!I", len(SMB1_NEGOTIATE)) + SMB1_NEGOTIATE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(packet)
            reply = sock.recv(512)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return False  # servers without SMBv1 usually drop the connection
    except OSError:
        return None
    if len(reply) < 13:
        return False
    return reply[4:8] == b"\xffSMB" and reply[8] == 0x72 and reply[9:13] == b"\x00\x00\x00\x00"


def banners_for(ip: str, open_ports: list[int]) -> dict:
    info: dict = {}
    for port in open_ports:
        try:
            if port in HTTP_PORTS or port in HTTPS_PORTS:
                result = http_probe(ip, port, tls=port in HTTPS_PORTS)
                if result:
                    info.setdefault("http", {})[str(port)] = result
            elif port in (21, 22):
                line = greeting(ip, port)
                if line:
                    info["ftp" if port == 21 else "ssh"] = line
        except (OSError, ssl.SSLError, ValueError):
            continue
    if 445 in open_ports:
        smb1 = smb1_enabled(ip)
        if smb1 is not None:
            info["smb1"] = smb1
    return info


# ---------------------------------------------------------------- orchestration


def identify(
    hosts: list[str],
    open_ports: dict[str, list[int]],
    timeout: float = 2.5,
    local_ip: str | None = None,
) -> dict:
    """Run every probe in parallel; returns {ip: {...extra facts...}}."""
    targets = {ip for ip in hosts if ipaddress.ip_address(ip).is_private}
    results: dict[str, dict] = {ip: {} for ip in targets}
    with ThreadPoolExecutor(max_workers=32) as pool:
        mdns = pool.submit(mdns_discover, targets, timeout, local_ip)
        ssdp = pool.submit(ssdp_discover, targets, timeout, local_ip)
        netbios = pool.submit(netbios_discover, targets, min(timeout, 1.5), local_ip)
        banners = {
            ip: pool.submit(banners_for, ip, open_ports.get(ip, []))
            for ip in targets if open_ports.get(ip)
        }
        for ip, info in mdns.result().items():
            results[ip].update(info)
        for ip, info in ssdp.result().items():
            results[ip]["upnp"] = info
        for ip, info in netbios.result().items():
            results[ip].update(info)
        for ip, future in banners.items():
            results[ip].update(future.result())
    return {ip: info for ip, info in results.items() if info}
