import asyncio
import copy
import json

import httpx
import pytest

from commander.dns_pilot import DNSPilot, DNSPilotError, assert_records
from commander.dynadot import signature

OLD = "8.8.8.8"
NEW = "1.1.1.1"


def fixture_zone():
    return {
        "glue_type": "DNS",
        "ttl": 300,
        "dns_main_list": [
            {
                "record_type": "mx",
                "record_value1": "mail.example.net",
                "record_value2": "10",
            }
        ],
        "dns_sub_list": [
            {"sub_host": "lt", "record_type": "a", "record_value1": OLD},
            {"sub_host": "admin", "record_type": "txt", "record_value1": "keep-me"},
        ],
    }


@pytest.fixture
def provider(monkeypatch):
    state = {"zone": fixture_zone(), "calls": []}

    async def records(self, zone):
        assert zone == "vetka.rest"
        return {"glue_info": copy.deepcopy(state["zone"])}

    async def mutate(self, method, record, ttl):
        state["calls"].append((method, copy.deepcopy(record)))
        if method == "POST":
            state["zone"]["dns_sub_list"].append(copy.deepcopy(record))
        else:
            state["zone"]["dns_sub_list"].remove(record)

    monkeypatch.setattr(DNSPilot, "records", records)
    monkeypatch.setattr(DNSPilot, "mutate", mutate)
    return state


def test_targeted_roundtrip_preserves_other_records_and_ttl(provider):
    client = DNSPilot("key", "secret")
    stages = []
    report = asyncio.run(
        client.replace_a(
            "lt.vetka.rest",
            OLD,
            NEW,
            approved=True,
            checkpoint=lambda stage, **kw: stages.append(stage),
        )
    )
    assert report["provider_verified"]
    assert stages == ["ADD_PENDING", "REMOVE_OLD_PENDING", "PROVIDER_VERIFIED"]
    assert provider["calls"][0][0] == "POST" and provider["calls"][1][0] == "DELETE"
    assert provider["zone"]["dns_main_list"] == fixture_zone()["dns_main_list"]
    asyncio.run(client.replace_a("lt.vetka.rest", NEW, OLD, approved=True))
    assert_records(provider["zone"], fixture_zone())


def test_missing_approval_never_contacts_provider(provider):
    with pytest.raises(DNSPilotError):
        asyncio.run(DNSPilot("key", "secret").replace_a("lt.vetka.rest", OLD, NEW))
    assert not provider["calls"]


@pytest.mark.parametrize("host", ["vetka.rest", "other.example", "lt.vetka.rest/evil"])
def test_other_zones_and_apex_refused(provider, host):
    with pytest.raises(ValueError):
        asyncio.run(DNSPilot("key", "secret").replace_a(host, OLD, NEW, approved=True))
    assert not provider["calls"]


def test_ambiguous_target_or_changed_record_prevents_mutation(provider):
    provider["zone"]["dns_sub_list"].append(
        {"sub_host": "lt", "record_type": "txt", "record_value1": "keep"}
    )
    with pytest.raises(DNSPilotError):
        asyncio.run(
            DNSPilot("key", "secret").replace_a(
                "lt.vetka.rest", OLD, NEW, approved=True
            )
        )
    assert not provider["calls"]


def test_wire_mutations_are_exact_append_and_exact_remove_with_body_signature(
    monkeypatch,
):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def request(self, method, url, content, headers):
            payload = json.loads(content)
            assert headers["X-Signature"] == signature(
                "key",
                "secret",
                "/restful/v2/domains/vetka.rest/records",
                headers["X-Request-ID"],
                content.decode(),
            )
            assert (
                url == "https://api.dynadot.com/restful/v2/domains/vetka.rest/records"
            )
            assert payload["dns_sub_list"] == [
                {"sub_host": "lt", "record_type": "a", "record_value1": NEW}
            ]
            assert "dns_main_list" not in payload
            if method == "POST":
                assert (
                    payload["add_dns_to_current_setting"] is True
                    and payload["ttl"] == 300
                )
            else:
                assert set(payload) == {"dns_sub_list"}
            calls.append(method)
            return httpx.Response(
                200, json={"code": 200}, request=httpx.Request(method, url)
            )

    monkeypatch.setattr("commander.dns_pilot.httpx.AsyncClient", Client)
    c = DNSPilot("key", "secret")
    r = {"sub_host": "lt", "record_type": "a", "record_value1": NEW}
    asyncio.run(c.mutate("POST", r, 300))
    asyncio.run(c.mutate("DELETE", r, 300))
    assert calls == ["POST", "DELETE"]


def test_interrupted_append_restores_without_second_add(provider):
    client = DNSPilot("key", "secret")
    before = fixture_zone()
    provider["zone"]["dns_sub_list"].append(
        {"sub_host": "lt", "record_type": "a", "record_value1": NEW}
    )
    asyncio.run(client.restore_a("lt.vetka.rest", OLD, NEW, before, approved=True))
    assert provider["calls"] == [
        ("DELETE", {"sub_host": "lt", "record_type": "a", "record_value1": NEW})
    ]
    assert_records(provider["zone"], before)


def test_restore_never_replays_old_zone_over_concurrent_changes(provider):
    before = fixture_zone()
    provider["zone"]["dns_sub_list"][1]["record_value1"] = "changed-by-owner"
    provider["zone"]["dns_sub_list"][0]["record_value1"] = NEW
    with pytest.raises(DNSPilotError):
        asyncio.run(
            DNSPilot("key", "secret").restore_a(
                "lt.vetka.rest", OLD, NEW, before, approved=True
            )
        )
    assert not provider["calls"]


def test_provider_string_ttl_is_normalized_without_change():
    from commander.dns_pilot import snapshot

    zone = fixture_zone()
    zone["ttl"] = "300"
    assert snapshot({"glue_info": zone})["ttl"] == 300


def test_roundtrip_restore_keeps_original_snapshot_and_direction(monkeypatch):
    from contextlib import nullcontext
    from commander import dns_roundtrip as runner

    baseline = fixture_zone()
    state = {
        "stage": "PROVIDER_VERIFIED",
        "before": baseline,
        "agent_id": "node",
        "integration_id": "dns",
        "host": "lt.vetka.rest",
        "old": OLD,
        "new": NEW,
        "return_authorized": True,
    }

    class Client:
        async def restore_a(self, host, old, new, before, **kw):
            kw["checkpoint"]("ADD_PENDING", before={"changed": True}, old=new, new=old)
            return {"restored": True}

    monkeypatch.setattr(runner, "serialized", nullcontext)
    monkeypatch.setattr(runner, "load", lambda _: state.copy())
    monkeypatch.setattr(runner, "client_for", lambda _: Client())

    def checkpoint(operation, stage, **values):
        state.update(stage=stage, **values)

    monkeypatch.setattr(runner, "checkpoint", checkpoint)
    asyncio.run(runner.change("operation", restore=True))
    assert state["before"] == baseline and state["old"] == OLD and state["new"] == NEW
    assert state["stage"] == "RESTORED_PROVIDER"


def test_started_switch_is_not_blindly_repeated(monkeypatch):
    from contextlib import nullcontext
    from commander import dns_roundtrip as runner

    monkeypatch.setattr(runner, "serialized", nullcontext)
    monkeypatch.setattr(
        runner, "load", lambda _: {"stage": "ADD_PENDING", "integration_id": "dns"}
    )
    monkeypatch.setattr(runner, "client_for", lambda _: object())
    with pytest.raises(DNSPilotError):
        asyncio.run(runner.change("operation"))


def test_dns_verification_checks_every_ipv4_of_each_authoritative_ns(monkeypatch):
    from types import SimpleNamespace
    import dns.flags
    import dns.message
    import dns.rrset
    from commander import dns_roundtrip as runner

    called = []
    addresses = {
        "ns1.example": ["9.9.9.9", "8.8.4.4"],
        "ns2.example": ["208.67.222.222"],
    }

    def resolve(name, kind, **kwargs):
        if kind == "NS":
            return [SimpleNamespace(target=n) for n in addresses]
        return addresses[name]

    def query(q, address, **kwargs):
        called.append(address)
        r = dns.message.make_response(q)
        r.flags |= dns.flags.AA
        r.answer.append(dns.rrset.from_text("lt.vetka.rest.", 300, "IN", "A", NEW))
        return r

    class Resolver:
        def __init__(self, **kwargs):
            pass

        def resolve(self, *args, **kwargs):
            return [NEW]

    monkeypatch.setattr(runner.dns.resolver, "resolve", resolve)
    monkeypatch.setattr(runner.dns.resolver, "Resolver", Resolver)
    monkeypatch.setattr(runner.dns.query, "udp", query)
    report = runner.dns_observations("lt.vetka.rest")
    assert set(called) == {ip for items in addresses.values() for ip in items}
    assert len(report["authoritative"]) == 3
    assert all(row["aa"] and row["ips"] == [NEW] for row in report["authoritative"])


def test_cli_incomplete_verification_returns_nonzero(monkeypatch, capsys):
    import sys
    from commander import manage, dns_roundtrip

    async def not_ready(*args, **kwargs):
        return {"verified": False, "authoritative_ok": False}

    monkeypatch.setattr(dns_roundtrip, "verify", not_ready)
    monkeypatch.setattr(
        sys, "argv", ["manage", "dns-pilot", "verify", "--operation-id", "operation"]
    )
    with pytest.raises(SystemExit) as e:
        manage.main()
    assert e.value.code == 2
    assert json.loads(capsys.readouterr().out)["verified"] is False


def test_dns_quorum_accepts_majority_without_claiming_every_authority_updated():
    from commander.dns_roundtrip import dns_quorum

    rows = {
        "authoritative": [{"aa": True, "ips": [NEW]}] * 3
        + [{"aa": True, "ips": [OLD]}],
        "recursive": [{"ips": [NEW]}] * 2,
    }
    report = dns_quorum(rows, NEW)
    assert report["authoritative_ok"] and report["recursive_ok"]
    assert not report["all_authorities_updated"]
    assert report["dns_votes"]["authoritative"] == [3, 4]
    rows["authoritative"] = [{"aa": True, "ips": [NEW]}] * 2 + [
        {"error": "timeout"}
    ] * 2
    assert not dns_quorum(rows, NEW)["authoritative_ok"]
    assert not dns_quorum({"authoritative": [], "recursive": []}, NEW)["recursive_ok"]


def test_noop_restore_preserves_new_unrelated_record(provider):
    before = fixture_zone()
    extra = {"sub_host": "other", "record_type": "a", "record_value1": "9.9.9.9"}
    provider["zone"]["dns_sub_list"].append(extra)
    report = asyncio.run(
        DNSPilot("key", "secret").restore_a(
            "lt.vetka.rest", OLD, NEW, before, approved=True, allow_mutation=False
        )
    )
    assert report["already_original"] and report["other_records_changed"]
    assert provider["calls"] == [] and extra in provider["zone"]["dns_sub_list"]


def test_completed_pilot_cannot_reuse_old_approval_for_a_new_restore(provider):
    before = fixture_zone()
    provider["zone"]["dns_sub_list"][0]["record_value1"] = NEW
    with pytest.raises(DNSPilotError):
        asyncio.run(
            DNSPilot("key", "secret").restore_a(
                "lt.vetka.rest", OLD, NEW, before, approved=True, allow_mutation=False
            )
        )
    assert provider["calls"] == []
