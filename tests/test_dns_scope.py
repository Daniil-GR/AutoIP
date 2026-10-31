import asyncio

import pytest
from pydantic import ValidationError

from commander.dns_scope import managed_record
from commander.dynadot import Dynadot
from commander.providers import dns_plan
from commander.schemas import AgentConfiguration, CommanderPolicy


@pytest.mark.parametrize(
    "zone", ["example.com", "evil.vetka.rest", "vetka.rest.evil.com", "other.rest"]
)
def test_settings_cannot_expand_dns_zone(zone):
    with pytest.raises(ValidationError):
        CommanderPolicy(default_dns_zone=zone)
    with pytest.raises(ValidationError):
        AgentConfiguration(dns_zone=zone)
    with pytest.raises(ValueError):
        dns_plan({}, zone, "lt." + zone, "8.8.8.8", "1.1.1.1")


@pytest.mark.parametrize(
    "host",
    [
        "vetka.rest",
        "evilvetka.rest",
        "lt.vetka.rest.evil.com",
        "*.vetka.rest",
        "-bad.vetka.rest",
        "lt.vetka.rest/path",
        "lt..vetka.rest",
    ],
)
def test_only_actual_subdomains_are_managed(host):
    with pytest.raises(ValidationError):
        AgentConfiguration(dns_zone="vetka.rest", dns_record=host)
    with pytest.raises(ValueError):
        managed_record(host)


def test_allowed_names_are_normalized_and_future_node_subdomains_work():
    config = AgentConfiguration(dns_zone=" VETKA.REST. ", dns_record=" LT.VETKA.REST. ")
    assert (config.dns_zone, config.dns_record) == ("vetka.rest", "lt.vetka.rest")
    assert managed_record("new-node.vetka.rest") == "new-node.vetka.rest"


@pytest.mark.parametrize(
    "path",
    [
        "/domains",
        "/domains/example.com/records",
        "/domains/lt.vetka.rest/records",
        "/domains/vetka.rest/records?domain=example.com",
    ],
)
def test_out_of_scope_provider_calls_stop_before_http(monkeypatch, path):
    def forbidden_client(*args, **kwargs):
        raise AssertionError("Out-of-scope request reached HTTP")

    monkeypatch.setattr("commander.dynadot.httpx.AsyncClient", forbidden_client)
    with pytest.raises(ValueError):
        asyncio.run(Dynadot("key", "secret").get(path))
    with pytest.raises(ValueError):
        asyncio.run(Dynadot("key", "secret").records("example.com"))
    with pytest.raises(ValueError):
        asyncio.run(
            Dynadot("key", "secret").get(
                "/domains/vetka.rest/records", {"domain": "example.com"}
            )
        )
