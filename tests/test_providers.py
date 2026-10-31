import copy
import pytest
from commander.providers import dns_plan


def test_dns_plan_lossless_and_write_blocked():
    snapshot = {
        "ttl": 300,
        "dns_main_list": [
            {
                "record_type": "mx",
                "record_value1": "mail.example.com",
                "record_value2": "10",
            },
            {"record_type": "txt", "record_value1": "v=spf1 -all"},
        ],
        "dns_sub_list": [
            {"sub_host": "proxy", "record_type": "a", "record_value1": "8.8.8.8"},
            {
                "sub_host": "other",
                "record_type": "cname",
                "record_value1": "target.example.com",
            },
        ],
    }
    before = copy.deepcopy(snapshot)
    plan = dns_plan(snapshot, "vetka.rest", "proxy.vetka.rest", "8.8.8.8", "1.1.1.1")
    assert snapshot == before
    expected = copy.deepcopy(before)
    expected["dns_sub_list"][0]["record_value1"] = "1.1.1.1"
    assert plan["planned"] == expected
    assert not plan["auto_apply_allowed"]
    with pytest.raises(ValueError):
        dns_plan(snapshot, "vetka.rest", "proxy.vetka.rest", "9.9.9.9", "1.1.1.1")
    with pytest.raises(ValueError):
        dns_plan(snapshot, "vetka.rest", "foreign.example.net", "8.8.8.8", "1.1.1.1")
    snapshot["dns_sub_list"].append(copy.deepcopy(snapshot["dns_sub_list"][0]))
    with pytest.raises(ValueError):
        dns_plan(snapshot, "vetka.rest", "proxy.vetka.rest", "8.8.8.8", "1.1.1.1")
