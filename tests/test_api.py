"""API smoke tests: administration, one-time enrollment, agent isolation."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from commander.app import app
from commander.config import settings
from commander.database import Base, get_db


def test_agent_onboarding_and_settings():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine, expire_on_commit=False)

    def override():
        with Session() as db:
            yield db

    app.dependency_overrides[get_db] = override
    try:
        with TestClient(app) as client:
            wrong = client.get("/api/agents", auth=("admin", "wrong-pass"))
            assert wrong.status_code == 401
            auth = (settings.admin_user, settings.admin_password)
            ticket_response = client.post(
                "/api/enrollments", json={"name": "PL-Agent-01"}, auth=auth
            )
            assert ticket_response.status_code == 200
            ticket = ticket_response.json()["token"]
            assert len(ticket) >= 32
            enrolled = client.post(
                "/api/agent/enroll",
                json={
                    "token": ticket,
                    "machine_id": "unique-machine-id-1",
                    "facts": {"os": "Linux"},
                },
            )
            assert enrolled.status_code == 200
            token = enrolled.json()["agent_token"]
            agent_id = enrolled.json()["agent_id"]
            replay = client.post(
                "/api/agent/enroll",
                json={"token": ticket, "machine_id": "different-machine"},
            )
            assert replay.status_code == 401
            headers = {"Authorization": "Bearer " + token}
            hb = client.post(
                "/api/agent/heartbeat",
                headers=headers,
                json={
                    "facts": {"hostname": "agent-01"},
                    "public_host": "proxy.example.com",
                    "proxy_port": 443,
                },
            )
            assert hb.status_code == 200
            agents = client.get("/api/agents", auth=auth).json()
            assert len(agents) == 1 and agents[0]["online"] is True
            config = {
                "provider": "cherry",
                "region": "PL",
                "cherry_project_id": "123",
                "cherry_server_id": "456",
                "sponsor_channel": "https://t.me/example",
                "notes": "testing",
                "max_candidates_per_incident": 3,
            }
            saved = client.put(
                "/api/agents/" + agent_id + "/configuration", json=config, auth=auth
            )
            assert saved.status_code == 200
            loaded = client.get(
                "/api/agents/" + agent_id + "/configuration", auth=auth
            ).json()
            assert loaded["cherry_project_id"] == "123"
            queued = client.post(
                "/api/agents/" + agent_id + "/jobs", json={"kind": "status"}, auth=auth
            )
            assert queued.status_code == 200
            leased = client.get("/api/agent/jobs", headers=headers)
            assert leased.status_code == 200 and len(leased.json()["jobs"]) == 1
            job = leased.json()["jobs"][0]
            assert job["kind"] == "status"
            result = client.post(
                "/api/agent/jobs/" + job["id"] + "/result",
                headers=headers,
                json={"status": "succeeded", "result": {"message": "ok"}},
            )
            assert result.status_code == 200
            assert (
                client.get(
                    "/api/agent/jobs", headers={"Authorization": "Bearer invalid"}
                ).status_code
                == 401
            )
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_default_dns_zone_is_copied_once_without_selecting_proxy_record(client):
    auth = client.auth_pair
    policy = client.get("/api/settings", auth=auth).json()
    assert policy["default_dns_zone"] == ""
    for invalid in (
        "https://example.com",
        "*.example.com",
        "example.com/records",
        "-bad.example",
    ):
        assert (
            client.put(
                "/api/settings", json={"default_dns_zone": invalid}, auth=auth
            ).status_code
            == 422
        )
    assert (
        client.put(
            "/api/settings", json={"default_dns_zone": "  EXAMPLE.COM. "}, auth=auth
        ).status_code
        == 200
    )
    assert (
        client.get("/api/settings", auth=auth).json()["default_dns_zone"]
        == "example.com"
    )
    ticket = client.post(
        "/api/enrollments", json={"name": "DNS defaults"}, auth=auth
    ).json()["token"]
    agent = client.post(
        "/api/agent/enroll", json={"token": ticket, "machine_id": "dns-defaults"}
    ).json()["agent_id"]
    path = f"/api/agents/{agent}/configuration"
    config = client.get(path, auth=auth).json()
    assert config["dns_zone"] == "example.com"
    assert (
        config["dns_record"]
        == config["floating_ip"]
        == config["dns_integration_id"]
        == ""
    )
    assert (
        client.put(
            "/api/settings", json={"default_dns_zone": "another.example"}, auth=auth
        ).status_code
        == 200
    )
    assert client.get(path, auth=auth).json()["dns_zone"] == "example.com"
    config["dns_zone"] = "individual.example"
    assert client.put(path, json=config, auth=auth).status_code == 200
    assert client.get(path, auth=auth).json()["dns_zone"] == "individual.example"
