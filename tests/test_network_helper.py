import json
import pytest
from agent import network_helper as helper


def test_management_address_cannot_be_removed(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {"management": "8.8.8.8", "address": "8.8.8.8", "status": "COMMITTED"}
        )
    )
    active = tmp_path / "active.json"
    active.write_text(json.dumps({"address": "1.1.1.1"}))
    monkeypatch.setattr(helper, "policy", lambda: {"management": "8.8.8.8"})
    monkeypatch.setattr(helper.net, "snapshot", lambda: {})
    monkeypatch.setattr(helper.net, "device_for_management", lambda *a: "eth0")
    monkeypatch.setattr(helper.net, "state_file", lambda *a: state)
    monkeypatch.setattr(helper, "ACTIVE", active)
    with pytest.raises(RuntimeError, match="management or active"):
        helper.operate(
            {"action": "remove", "resource_id": "11111111-1111-4111-8111-111111111111"}
        )


def test_unknown_parameters_and_management_mismatch_rejected(monkeypatch):
    monkeypatch.setattr(helper, "policy", lambda: {"management": "8.8.8.8"})
    with pytest.raises(ValueError, match="Unexpected"):
        helper.operate({"action": "inspect", "shell": "anything"})
    monkeypatch.setattr(helper.net, "snapshot", lambda: {})
    monkeypatch.setattr(helper.net, "device_for_management", lambda *a: "eth0")
    with pytest.raises(ValueError, match="Management mismatch"):
        helper.operate({"action": "inspect", "address": "1.1.1.1"})


def test_cleanup_reconciles_removed_unit_after_independent_config_edit(
    tmp_path, monkeypatch
):
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "management": "8.8.8.8",
                "address": "9.9.9.9",
                "status": "REMOVING",
                "unit": "owned.service",
                "before": {"telemt_hash": "original"},
            }
        )
    )
    active = tmp_path / "active.json"
    active.write_text(json.dumps({"address": "1.1.1.1"}))
    snapshot = {
        "addresses": [
            {
                "ifname": "eth0",
                "addr_info": [{"local": "8.8.8.8"}, {"local": "1.1.1.1"}],
            }
        ],
        "defaults": [],
        "egress": [{"prefsrc": "8.8.8.8"}],
        "telemt_hash": "owner-edited",
    }
    monkeypatch.setattr(helper, "policy", lambda: {"management": "8.8.8.8"})
    monkeypatch.setattr(helper.net, "snapshot", lambda: snapshot)
    monkeypatch.setattr(helper.net, "state_file", lambda *a: state)
    monkeypatch.setattr(helper.net, "UNIT_DIR", tmp_path)
    monkeypatch.setattr(helper, "ACTIVE", active)

    def forbidden(*args):
        pytest.fail("No system command needed to reconcile an absent unit/address")

    monkeypatch.setattr(helper.net, "command", forbidden)
    request = {
        "action": "remove",
        "resource_id": "11111111-1111-4111-8111-111111111111",
    }
    assert helper.operate(request)["status"] == "REMOVED"
    assert helper.operate(request)["status"] == "REMOVED"
    assert json.loads(state.read_text())["before"]["telemt_hash"] == "original"
