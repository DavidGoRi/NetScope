from netscope import vendor

IEEE_SAMPLE = """Registry,Assignment,Organization Name,Organization Address
MA-L,B827EB,Raspberry Pi Foundation,Mitchell Wood House Caldecote GB CB23 7NU
MA-L,00000C,"Cisco  Systems, Inc",170 WEST TASMAN DRIVE SAN JOSE CA US 95134
MA-L,BAD,Broken Row,
"""


def test_parse_ieee_csv():
    table = vendor.parse_ieee_csv(IEEE_SAMPLE)
    assert table == {"B827EB": "Raspberry Pi Foundation", "00000C": "Cisco Systems, Inc"}


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "oui.txt"
    vendor.save_oui({"00000C": "Cisco Systems, Inc"}, path)
    table = vendor.load_oui(path)
    assert table["00000C"] == "Cisco Systems, Inc"
    assert table["000C29"] == "VMware"  # built-in entries are always present


def test_missing_cache_falls_back_to_builtin(tmp_path):
    assert vendor.load_oui(tmp_path / "missing.txt") == vendor.BUILTIN_OUI


def test_lookup():
    table = {"B827EB": "Raspberry Pi Foundation"}
    assert vendor.lookup("B8:27:EB:00:00:01", table) == "Raspberry Pi Foundation"
    assert vendor.lookup("00:11:22:33:44:55", table) is None
    assert vendor.lookup(None, table) is None


def test_randomized_mac_detection():
    assert vendor.is_randomized("D2:00:00:00:00:01")
    assert vendor.is_randomized("02:00:00:00:00:01")
    assert not vendor.is_randomized("B8:27:EB:00:00:01")
    assert vendor.lookup("D2:00:00:00:00:01", {"D20000": "Nope"}) is None


def test_cache_path_override(monkeypatch, tmp_path):
    monkeypatch.setenv("NETSCOPE_OUI", str(tmp_path / "x.txt"))
    assert vendor.cache_path() == tmp_path / "x.txt"
