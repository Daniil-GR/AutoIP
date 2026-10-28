import os
import tempfile
from pathlib import Path

import pytest

# All test databases and key files are isolated from development and production.
TEST_DIR = tempfile.TemporaryDirectory(prefix="autoip-tests-")
os.environ["AUTOIP_ADMIN_PASSWORD"] = "testing-only-password-123"
os.environ["AUTOIP_DATABASE_URL"] = "sqlite:///" + str(
    Path(TEST_DIR.name) / "commander.sqlite3"
)
os.environ["AUTOIP_WORKER_ENABLED"] = "false"
os.environ["AUTOIP_MONITOR_ENABLED"] = "false"


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")


@pytest.fixture
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from commander.database import Base

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from commander.app import app
    from commander.config import settings
    from commander.database import Base, get_db
    from commander.vault import initialize

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def foreign_keys(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def override():
        with factory() as session:
            yield session

    initialize(tmp_path / "key")
    monkeypatch.setattr(settings, "vault_key_file", str(tmp_path / "key"))
    monkeypatch.setattr(settings, "public_url", "")
    monkeypatch.setattr(settings, "totp_secret_file", "")
    app.dependency_overrides[get_db] = override
    with TestClient(app) as instance:
        instance.factory = factory
        instance.auth_pair = (settings.admin_user, settings.admin_password)
        yield instance
    app.dependency_overrides.clear()
    engine.dispose()
