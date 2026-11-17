import ipaddress

from netscope import discovery

# Windows "arp -a" in Spanish, with broadcast and multicast entries that must be dropped.
WINDOWS_ARP = """
Interfaz: 192.168.1.20 --- 0x5
  Dirección de Internet          Dirección física      Tipo
  192.168.1.1           00-1a-2b-3c-4d-5e     dinámico
  192.168.1.150         b8-27-eb-00-00-01     dinámico
  192.168.1.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  239.255.255.250       01-00-5e-7f-ff-fa     estático
"""

LINUX_IP_NEIGH = """
192.168.1.1 dev eth0 lladdr 00:1a:2b:3c:4d:5e REACHABLE
192.168.1.150 dev eth0 lladdr b8:27:eb:00:00:01 STALE
192.168.1.99 dev eth0  FAILED
fe80::1 dev eth0 lladdr 00:1a:2b:3c:4d:5e router STALE
"""

MACOS_ARP = """
? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]
? (192.168.1.40) at (incomplete) on en0 ifscope [ethernet]
"""


def test_windows_arp_table_in_any_language():
    assert discovery.parse_neighbors(WINDOWS_ARP) == {
        "192.168.1.1": "00:1A:2B:3C:4D:5E",
        "192.168.1.150": "B8:27:EB:00:00:01",
    }


def test_linux_ip_neigh_skips_failed_entries():
    assert discovery.parse_neighbors(LINUX_IP_NEIGH) == {
        "192.168.1.1": "00:1A:2B:3C:4D:5E",
        "192.168.1.150": "B8:27:EB:00:00:01",
    }


def test_macos_short_octets_are_padded():
    assert discovery.parse_neighbors(MACOS_ARP) == {"192.168.1.1": "00:1A:2B:3C:4D:5E"}


def test_normalize_mac():
    assert discovery.normalize_mac("a-b-cc-dd-ee-f") == "0A:0B:CC:DD:EE:0F"


def test_usable_mac_rejects_broadcast_zero_and_multicast():
    assert discovery.usable_mac("00:1A:2B:3C:4D:5E")
    assert not discovery.usable_mac("FF:FF:FF:FF:FF:FF")
    assert not discovery.usable_mac("00:00:00:00:00:00")
    assert not discovery.usable_mac("01:00:5E:00:00:16")


def test_in_network_excludes_network_and_broadcast_addresses():
    net = ipaddress.ip_network("192.168.1.0/24")
    assert discovery.in_network("192.168.1.10", net)
    assert not discovery.in_network("192.168.1.0", net)
    assert not discovery.in_network("192.168.1.255", net)
    assert not discovery.in_network("192.168.2.10", net)


def test_ping_requires_a_real_echo_reply(monkeypatch):
    unreachable = "Respuesta desde 192.168.1.20: Host de destino inaccesible."
    monkeypatch.setattr(discovery, "run", lambda cmd, timeout: unreachable)
    assert not discovery.ping("192.168.1.50")
    monkeypatch.setattr(discovery, "run", lambda cmd, timeout: "bytes=32 tiempo<1m TTL=64")
    assert discovery.ping("192.168.1.50")


def test_ping_sweep_collects_answering_hosts(monkeypatch):
    monkeypatch.setattr(discovery, "ping", lambda ip, timeout_ms: ip != "10.0.0.2")
    calls = []
    alive = discovery.ping_sweep(
        ["10.0.0.1", "10.0.0.2", "10.0.0.11"], progress=lambda d, t: calls.append((d, t))
    )
    assert alive == {"10.0.0.1", "10.0.0.11"}
    assert calls[-1] == (3, 3)


def test_resolve_names_skips_unknown(monkeypatch):
    def fake(ip):
        if ip == "10.0.0.1":
            return ("router.lan", [], [ip])
        raise OSError("unknown host")

    monkeypatch.setattr(discovery.socket, "gethostbyaddr", fake)
    assert discovery.resolve_names(["10.0.0.1", "10.0.0.2"]) == {"10.0.0.1": "router.lan"}
