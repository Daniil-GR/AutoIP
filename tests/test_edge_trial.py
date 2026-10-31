import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock

import pytest

from commander import edge_trial
from commander.database import Integration, SystemSetting, utcnow
from commander.vault import encrypt


@pytest.mark.parametrize(
    "service,count,identifier,origin,expected",
    [
        ("trial", 1, 5, "8.8.8.8", True),
        ("active", 1, 5, "8.8.8.8", False),
        ("trial", 2, 5, "8.8.8.8", False),
        ("trial", 1, 6, "8.8.8.8", False),
        ("trial", 1, 5, "9.9.9.9", False),
    ],
)
def test_trial_stop_scope(service, count, identifier, origin, expected):
    assert (
        edge_trial.can_stop(
            {"status": service},
            {
                "count": count,
                "results": [{"id": identifier, "origin_host": origin, "name": "pilot"}],
            },
            {
                "edge_profile_id": 5,
                "origin": "8.8.8.8",
                "configuration": {"name": "pilot"},
            },
        )
        is expected
    )


def test_trial_guard_waits_and_stops_only_own_trial(client, monkeypatch):
    factory = client.factory
    monkeypatch.setattr(edge_trial, "SessionLocal", factory)
    call = AsyncMock(
        side_effect=[
            {"serviceStatuses": {"SHIELD_PROXY": {"status": "trial"}}},
            {
                "count": 1,
                "results": [{"id": 5, "origin_host": "8.8.8.8", "name": "pilot"}],
            },
            {},
            {"serviceStatuses": {"SHIELD_PROXY": {"status": "paused"}}},
        ]
    )
    monkeypatch.setattr(edge_trial.Gcore, "call", call)
    with factory() as db:
        db.add(
            Integration(
                id="g",
                kind="gcore",
                name="gcore",
                ciphertext=encrypt("g", "gcore", {"api_key": "test-key"}),
            )
        )
        db.add(
            SystemSetting(
                key="gcore-edge-pilot",
                value={
                    "stop_trial_before_paid": True,
                    "stop_at": (utcnow() + timedelta(days=1)).isoformat(),
                    "gcore_id": "g",
                    "edge_profile_id": 5,
                    "origin": "8.8.8.8",
                    "configuration": {"name": "pilot"},
                },
            )
        )
        db.commit()
    assert not asyncio.run(edge_trial.tick())
    assert call.await_count == 0
    with factory() as db:
        s = db.get(SystemSetting, "gcore-edge-pilot")
        s.value = {**s.value, "stop_at": (utcnow() - timedelta(seconds=1)).isoformat()}
        db.commit()
    assert asyncio.run(edge_trial.tick())
    assert call.await_args_list[2].args == (
        "PATCH",
        "/billing/client/v1/me/products/SHIELD_PROXY",
    )
    assert call.await_args_list[2].kwargs == {"json": {"plan_id": None}}
    assert not asyncio.run(edge_trial.tick())
    with factory() as db:
        assert (
            db.get(SystemSetting, "gcore-edge-pilot").value["guard_status"] == "stopped"
        )
