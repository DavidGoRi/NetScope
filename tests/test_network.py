import pytest

from netscope.network import LocalInterface, TargetError, clamp_network, validate_target


@pytest.mark.parametrize(
    "cidr",
    ["192.168.1.0/24", "10.0.0.0/22", "172.16.5.0/24", "192.168.1.77/24", "169.254.10.0/24"],
)
def test_private_networks_are_accepted(cidr):
    net = validate_target(cidr)
    assert net.is_private


def test_host_address_is_normalised_to_its_network():
    assert str(validate_target("192.168.1.77/24")) == "192.168.1.0/24"


@pytest.mark.parametrize("cidr", ["8.8.8.0/24", "1.1.1.1/32", "100.64.0.0/24", "127.0.0.0/24"])
def test_public_and_loopback_networks_are_refused(cidr):
    with pytest.raises(TargetError):
        validate_target(cidr)


def test_range_that_straddles_into_public_space_is_refused():
    with pytest.raises(TargetError):
        validate_target("172.0.0.0/8")


def test_networks_larger_than_the_limit_are_refused():
    with pytest.raises(TargetError, match="limit"):
        validate_target("10.0.0.0/16")


@pytest.mark.parametrize("cidr", ["fe80::/64", "not-a-network", "192.168.1.0/33"])
def test_invalid_targets_are_refused(cidr):
    with pytest.raises(TargetError):
        validate_target(cidr)


def test_single_host_is_allowed():
    assert validate_target("192.168.1.10/32").num_addresses == 1


def test_large_interface_network_is_clamped_to_a_24():
    iface = LocalInterface(ip="10.1.2.3", prefix=8)
    assert str(clamp_network(iface)) == "10.1.2.0/24"


def test_small_interface_network_is_kept():
    iface = LocalInterface(ip="192.168.1.20", prefix=24)
    assert str(clamp_network(iface)) == "192.168.1.0/24"
