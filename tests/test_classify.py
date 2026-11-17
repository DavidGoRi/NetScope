import pytest

from netscope import classify


def dev(**kw):
    base = {"open_ports": [], "vendor": None, "hostname": None, "randomized_mac": False}
    base.update(kw)
    return base


@pytest.mark.parametrize(
    "device, expected",
    [
        (dev(is_gateway=True, open_ports=[53, 80]), "router"),
        (dev(open_ports=[80, 9100]), "printer"),
        (dev(open_ports=[80, 554]), "camera"),
        (dev(vendor="Synology Incorporated", open_ports=[5000]), "nas"),
        (dev(hostname="truenas.lan", open_ports=[21, 139, 445]), "nas"),
        (dev(hostname="XBOXONE.lan"), "console"),
        (dev(open_ports=[53, 80, 443]), "router"),
        (dev(open_ports=[135, 139, 445]), "windows"),
        (dev(open_ports=[3389]), "windows"),
        (dev(open_ports=[62078]), "apple-mobile"),
        (dev(vendor="Apple, Inc."), "apple"),
        (dev(open_ports=[8008, 8009]), "media"),
        (dev(vendor="Espressif Inc."), "home-automation"),
        (dev(vendor="VMware, Inc.", open_ports=[22]), "virtual-machine"),
        (dev(open_ports=[22]), "linux"),
        (dev(randomized_mac=True), "mobile"),
        (dev(), "unknown"),
    ],
)
def test_guess_type(device, expected):
    assert classify.guess_type(device) == expected


def test_every_guess_is_a_declared_type():
    assert classify.guess_type(dev()) in classify.DEVICE_TYPES


def codes(device):
    device["type"] = classify.guess_type(device)
    return [f["code"] for f in classify.findings_for(device)]


def test_telnet_is_critical_and_sorted_first():
    found = classify.findings_for(dev(open_ports=[445, 23], type="unknown"))
    assert [f["code"] for f in found] == ["telnet_open", "smb_open"]
    assert found[0]["severity"] == "crit"
    assert found[0]["port"] == 23


def test_http_only_admin_on_appliances():
    assert "http_only_admin" in codes(dev(open_ports=[80, 554]))


def test_https_available_means_no_http_only_finding():
    assert "http_only_admin" not in codes(dev(open_ports=[80, 443, 554]))


def test_http_on_a_pc_is_not_an_admin_interface():
    assert "http_only_admin" not in codes(dev(open_ports=[80, 135, 445]))


def test_private_mac_finding():
    assert codes(dev(randomized_mac=True)) == ["private_mac"]


def test_every_finding_has_a_known_severity():
    for severity, message in classify.FINDINGS.values():
        assert severity in classify.SEVERITY_ORDER
        assert message.endswith(".")
