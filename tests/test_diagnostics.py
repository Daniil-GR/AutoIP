import json
import logging
from contextlib import contextmanager

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from commander import diagnostics
from commander.database import Audit


def test_correlated_failure_is_persistent_without_exception_secrets(
    db, monkeypatch, caplog
):
    monkeypatch.setattr(diagnostics, "SessionLocal", sessionmaker(db.bind))
    secret = "rf_confidential-key-do-not-log"
    try:
        raise RuntimeError("https://provider.invalid?api_key=" + secret)
    except RuntimeError as error:
        with caplog.at_level(logging.ERROR):
            error_id = diagnostics.record_failure(
                "worker",
                "collect",
                error,
                agent_id="node",
                task_id="task",
                operation_id="operation",
            )
    row = db.scalar(select(Audit))
    assert row.details["error_id"] == error_id
    assert row.target == "node"
    assert row.details["task_id"] == "task"
    assert row.details["operation_id"] == "operation"
    assert row.details["error_type"] == "RuntimeError"
    assert row.details["frames"][-1]["file"] == "test_diagnostics.py"
    assert secret not in caplog.text + json.dumps(row.details)
    assert "provider.invalid" not in caplog.text


def test_database_failure_keeps_original_error_id_and_safe_log(monkeypatch, caplog):
    @contextmanager
    def unavailable():
        raise RuntimeError("postgres://admin:secret-password@database")
        yield

    monkeypatch.setattr(diagnostics, "SessionLocal", unavailable)
    with caplog.at_level(logging.ERROR):
        error_id = diagnostics.record_failure(
            "worker", "iteration", ValueError("private")
        )
    records = [json.loads(r.message) for r in caplog.records]
    assert len(records) == 2
    assert all(r["error_id"] == error_id for r in records)
    assert records[-1]["stage"] == "diagnostic_storage_failed"
    assert "secret-password" not in caplog.text
    assert "private" not in caplog.text


def test_provider_http_status_is_recorded_without_response_body(db, monkeypatch):
    from commander.floating_pilot import PilotError

    monkeypatch.setattr(diagnostics, "SessionLocal", sessionmaker(db.bind))
    diagnostics.record_failure(
        "recovery", "ATTACH", PilotError("private provider body", provider_status=400)
    )
    row = db.scalar(select(Audit))
    assert row.details["provider_status"] == 400
    assert "private provider body" not in json.dumps(row.details)


def test_api_unexpected_error_returns_only_correlation_id(client, monkeypatch, caplog):
    from commander.app import app

    monkeypatch.setattr(diagnostics, "SessionLocal", client.factory)

    async def broken():
        raise RuntimeError("telegram-session-secret")

    app.add_api_route("/diagnostic-test-failure", broken)
    try:
        with caplog.at_level(logging.ERROR):
            response = client.get(
                "/diagnostic-test-failure?api_key=hidden-query-secret"
            )
        assert response.status_code == 500
        error_id = response.json()["error_id"]
        with client.factory() as db:
            row = db.scalar(select(Audit).where(Audit.action == "operation_error"))
            assert row.details["error_id"] == error_id
        assert "telegram-session-secret" not in response.text + caplog.text
        assert "hidden-query-secret" not in response.text + caplog.text
    finally:
        app.router.routes[:] = [
            r
            for r in app.router.routes
            if getattr(r, "path", "") != "/diagnostic-test-failure"
        ]


def test_network_cli_records_safe_failure_in_existing_journal(
    tmp_path, monkeypatch, capsys
):
    import sys
    from agent import network_pilot

    path = tmp_path / "journal.json"
    path.write_text(json.dumps({"status": "PREPARING"}))
    monkeypatch.setattr(network_pilot, "state_file", lambda _: path)

    def failed(*args):
        raise RuntimeError("private-network-output")

    monkeypatch.setattr(network_pilot, "prepare", failed)
    monkeypatch.setattr(
        sys, "argv", ["network_pilot", "prepare", "--resource-id", "id"]
    )
    import pytest

    with pytest.raises(SystemExit):
        network_pilot.main()
    saved = json.loads(path.read_text())
    assert saved["status"] == "PREPARING"
    assert saved["last_error"]["stage"] == "prepare"
    assert saved["last_error"]["error_type"] == "RuntimeError"
    assert "private-network-output" not in path.read_text() + capsys.readouterr().err
