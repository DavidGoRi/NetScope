import socket
import threading

import pytest

from netscope import ports


@pytest.fixture
def listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    stop = threading.Event()

    def accept():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join(1)
    server.close()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_open_and_closed_ports_are_told_apart(listening_port):
    closed = free_port()
    result = ports.scan_ports(["127.0.0.1"], [listening_port, closed], timeout=1.0)
    assert result == {"127.0.0.1": [listening_port]}


def test_empty_port_list_scans_nothing():
    assert ports.scan_ports(["127.0.0.1"], []) == {"127.0.0.1": []}


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("none", []),
        ("22,80", [22, 80]),
        ("8000-8002, 22", [22, 8000, 8001, 8002]),
        ("10-8", [8, 9, 10]),
    ],
)
def test_parse_ports(spec, expected):
    assert ports.parse_ports(spec) == expected


def test_parse_common_ports():
    assert ports.parse_ports("common") == sorted(ports.COMMON_PORTS)


@pytest.mark.parametrize("spec", ["0", "70000", "1-2000", "abc"])
def test_parse_ports_rejects_bad_input(spec):
    with pytest.raises(ValueError):
        ports.parse_ports(spec)
