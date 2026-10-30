import copy

import pytest

from agent.network_pilot import validate_plan, verify_invariants

RESOURCE = "bd78a549-bac4-9292-a301-1cda169990ca"


def baseline():
    return {
        "addresses": [
            {"ifname": "eth0", "addr_info": [{"local": "8.8.8.8", "prefixlen": 32}]}
        ],
        "defaults": [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"}],
        "egress": [{"prefsrc": "8.8.8.8"}],
        "telemt_hash": "unchanged",
    }


def test_additional_address_is_allowed_without_changing_management():
    before = baseline()
    after = copy.deepcopy(before)
    after["addresses"][0]["addr_info"].append({"local": "1.1.1.1", "prefixlen": 32})
    assert validate_plan("1.1.1.1", "8.8.8.8", RESOURCE, before)[-1] == "eth0"
    verify_invariants(before, after, "8.8.8.8")


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "127.0.0.1", "10.0.0.2", "1.1.1.1; reboot"]
)
def test_primary_private_and_shell_input_are_rejected(address):
    with pytest.raises(ValueError):
        validate_plan(address, "8.8.8.8", RESOURCE, baseline())


@pytest.mark.parametrize("changed", ["defaults", "egress", "addresses", "telemt_hash"])
def test_route_source_management_or_telemt_changes_trigger_rollback(changed):
    before = baseline()
    after = copy.deepcopy(before)
    after[changed] = "changed" if changed == "telemt_hash" else []
    with pytest.raises((RuntimeError, ValueError)):
        verify_invariants(before, after, "8.8.8.8")


def test_already_present_candidate_or_wrong_source_is_not_applied_again():
    before = baseline()
    before["addresses"][0]["addr_info"].append({"local": "1.1.1.1"})
    with pytest.raises(ValueError):
        validate_plan("1.1.1.1", "8.8.8.8", RESOURCE, before)
    before = baseline()
    before["egress"][0]["prefsrc"] = "9.9.9.9"
    with pytest.raises(ValueError):
        validate_plan("1.1.1.1", "8.8.8.8", RESOURCE, before)
