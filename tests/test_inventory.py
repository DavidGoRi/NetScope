from netscope import inventory


def scan(*macs, finished="2026-11-17T10:00:00+01:00"):
    return {
        "network": "192.168.1.0/24",
        "finished": finished,
        "devices": [
            {"ip": f"192.168.1.{i + 10}", "mac": mac, "findings": [], "type": "unknown"}
            for i, mac in enumerate(macs)
        ],
    }


def test_first_scan_is_a_baseline_and_flags_nothing():
    first = scan("AA:00:00:00:00:01", "AA:00:00:00:00:02")
    known = inventory.apply_known(first, {"devices": {}})
    assert first["baseline"] is True
    assert not any(d["new"] for d in first["devices"])
    assert len(known["devices"]) == 2


def test_later_scan_flags_only_unknown_devices():
    known = inventory.apply_known(scan("AA:00:00:00:00:01"), {"devices": {}})
    second = scan("AA:00:00:00:00:01", "AA:00:00:00:00:99", finished="2026-11-18T10:00:00+01:00")
    inventory.apply_known(second, known)
    old, new = second["devices"]
    assert second["baseline"] is False
    assert not old["new"] and old["first_seen"] == "2026-11-17T10:00:00+01:00"
    assert new["new"] and [f["code"] for f in new["findings"]] == ["new_device"]
    assert known["devices"]["AA:00:00:00:00:01"]["last_seen"] == "2026-11-18T10:00:00+01:00"


def test_device_without_mac_is_keyed_by_ip():
    assert inventory.device_key({"ip": "10.0.0.5", "mac": None}) == "ip:10.0.0.5"


def test_labels_survive_between_scans(tmp_path):
    path = tmp_path / "known.json"
    known = inventory.apply_known(scan("AA:00:00:00:00:01"), {"devices": {}})
    known["devices"]["AA:00:00:00:00:01"]["label"] = "Reception printer"
    inventory.save_known(known, path)
    second = scan("AA:00:00:00:00:01")
    inventory.apply_known(second, inventory.load_known(path))
    assert second["devices"][0]["label"] == "Reception printer"


def test_corrupt_register_starts_over(tmp_path):
    path = tmp_path / "known.json"
    path.write_text("{not json", encoding="utf-8")
    assert inventory.load_known(path) == {"devices": {}}
