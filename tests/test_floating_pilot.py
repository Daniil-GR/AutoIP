import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from commander import floating_pilot as pilot
from commander.database import Agent, FloatingIP, Integration, SystemSetting

IP_ID = "5907b143-4a9c-4359-b027-f8a9291b9b3a"
PRIMARY_ID = "03a2cb73-cf88-4545-85d6-d8b39cd366c4"


@pytest.fixture
def setup(db, monkeypatch):
    db.add(
        Integration(
            id="cherry",
            name="Cherry",
            kind="cherry",
            status="verified",
            ciphertext="fake",
        )
    )
    db.add(
        Agent(
            id="node",
            name="Node",
            token_hash="test",
            configuration={
                "cherry_integration_id": "cherry",
                "cherry_project_id": "12",
                "cherry_server_id": "34",
                "management_ip": "8.8.8.8",
                "region": "LT-Siauliai",
            },
        )
    )
    db.commit()
    monkeypatch.setattr(
        pilot, "SessionLocal", sessionmaker(db.bind, expire_on_commit=False)
    )
    monkeypatch.setattr(pilot, "decrypt", lambda _: {"api_key": "fake"})

    class API:
        def __init__(self):
            self.calls = []
            self.allocated = False
            self.target = None
            self.fail = None
            self.project = 12

        def candidate(self):
            return {
                "id": IP_ID,
                "address": "1.1.1.1",
                "type": "floating-ip",
                "targeted_to": {"id": self.target} if self.target else None,
            }

        async def request(self, method, path, payload=None):
            self.calls.append((method, path, payload))
            if method == "POST":
                assert "routed_to" not in payload and "assigned_to" not in payload
                self.allocated = True
                if self.fail == "POST":
                    raise pilot.PilotError("uncertain")
                return self.candidate()
            if method == "PUT":
                assert payload == {"routed_to": PRIMARY_ID}
                self.target = 34
                if self.fail == "PUT":
                    raise pilot.PilotError("uncertain")
                return self.candidate()
            if path == "/servers/34":
                return {
                    "project": {"id": self.project},
                    "region": {"slug": "LT-Siauliai"},
                }
            if path == "/projects/12/ips":
                return [
                    {
                        "id": PRIMARY_ID,
                        "address": "8.8.8.8",
                        "type": "primary-ip",
                        "assigned_to": {"id": 34},
                    }
                ] + ([self.candidate()] if self.allocated else [])
            if path == "/ips/" + IP_ID:
                return self.candidate()
            raise AssertionError("Unexpected request")

    api = API()
    monkeypatch.setattr(pilot, "CherryPilotAPI", lambda _: api)
    return api


def purchase(operation):
    return asyncio.run(pilot.purchase_one("node", operation, approved=True))


def test_purchase_requires_approval_before_provider(setup):
    with pytest.raises(pilot.PilotError):
        asyncio.run(pilot.purchase_one("node", str(uuid4())))
    assert setup.calls == []


def test_one_order_is_durable_and_not_repeated(db, setup):
    operation = str(uuid4())
    assert purchase(operation)["status"] == "ALLOCATED"
    assert purchase(operation)["resource_id"] == IP_ID
    assert sum(c[0] == "POST" for c in setup.calls) == 1
    row = db.scalar(select(FloatingIP))
    assert row.managed and row.ipv4 == "1.1.1.1" and row.status == "candidate"
    assert setup.target is None


def test_lost_purchase_response_is_never_automatically_retried(db, setup):
    operation = str(uuid4())
    setup.fail = "POST"
    with pytest.raises(pilot.PilotError):
        purchase(operation)
    assert purchase(operation)["status"] == "SUBMISSION_UNCERTAIN"
    assert sum(c[0] == "POST" for c in setup.calls) == 1
    assert db.query(FloatingIP).count() == 0


def test_blocked_reissue_is_recorded_but_never_attached(db, setup):
    db.add(
        FloatingIP(
            agent_id="node",
            integration_id="cherry",
            resource_id="old-resource",
            ipv4="1.1.1.1",
            status="blocked",
            released_at=pilot.utcnow(),
        )
    )
    db.commit()
    operation = str(uuid4())
    result = purchase(operation)
    assert result["status"] == "REJECTED_HISTORY" and result["seen_before"]
    with pytest.raises(pilot.PilotError):
        asyncio.run(pilot.attach_one(operation, approved=True))
    assert not any(c[0] == "PUT" for c in setup.calls)
    assert db.query(FloatingIP).count() == 2


def test_attach_routes_to_primary_uuid_and_reads_back_without_ordering_again(setup):
    operation = str(uuid4())
    purchase(operation)
    for _ in range(2):
        state = asyncio.run(pilot.attach_one(operation, approved=True))
        assert state["status"] == "ATTACHED" and state["dns_changed"] is False
    assert sum(c[0] == "PUT" for c in setup.calls) == 1
    assert sum(c[0] == "POST" for c in setup.calls) == 1


def test_lost_attach_response_reconciles_without_second_put(setup):
    operation = str(uuid4())
    purchase(operation)
    setup.fail = "PUT"
    with pytest.raises(pilot.PilotError):
        asyncio.run(pilot.attach_one(operation, approved=True))
    setup.fail = None
    assert (
        asyncio.run(pilot.attach_one(operation, approved=True))["status"] == "ATTACHED"
    )
    assert sum(c[0] == "PUT" for c in setup.calls) == 1


@pytest.mark.parametrize(
    "failure", ["other_project", "other_server", "unmanaged", "late_block"]
)
def test_attach_rejects_unsafe_targets(db, setup, failure):
    operation = str(uuid4())
    purchase(operation)
    if failure == "other_project":
        setup.project = 99
    elif failure == "other_server":
        setup.target = 99
    else:
        row = db.scalar(select(FloatingIP))
        if failure == "unmanaged":
            row.managed = False
        else:
            row.status = "blocked"
        db.commit()
    with pytest.raises(pilot.PilotError):
        asyncio.run(pilot.attach_one(operation, approved=True))
    assert not any(c[0] == "PUT" for c in setup.calls)


def test_existing_in_progress_operation_does_not_send_post(db, setup):
    operation = str(uuid4())
    db.add(
        SystemSetting(
            key=pilot.operation_key(operation),
            value={"agent_id": "node", "status": "SUBMITTING"},
        )
    )
    db.commit()
    assert purchase(operation)["status"] == "SUBMITTING"
    assert setup.calls == []


@pytest.mark.parametrize(
    "raw",
    [
        {"type": "primary-ip"},
        {"type": "floating-ip", "id": IP_ID, "address": "127.0.0.1"},
    ],
)
def test_primary_or_private_addresses_never_accepted(raw):
    with pytest.raises(pilot.PilotError):
        pilot.resource_summary(raw)
