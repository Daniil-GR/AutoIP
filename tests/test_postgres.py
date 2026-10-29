"""Run only against an explicitly named disposable autoip_test database."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from commander.config import settings
from commander.database import Agent, ControlTask
from commander.services import request_check


@pytest.mark.skipif(
    not os.environ.get("AUTOIP_TEST_POSTGRES_URL"),
    reason="isolated PostgreSQL URL not configured",
)
def test_populated_v01_upgrade_and_concurrent_check_dedup(monkeypatch):
    url = os.environ["AUTOIP_TEST_POSTGRES_URL"]
    assert make_url(url).database == "autoip_test", (
        "Only the disposable test database is allowed"
    )
    engine = create_engine(url)
    with engine.connect() as conn:
        assert not conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        ).all()
    monkeypatch.setattr(settings, "database_url", url)
    cfg = Config("alembic.ini")
    command.upgrade(cfg, "0001_baseline")
    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO agents (id,name,token_hash,machine_id,proxy_port,facts,configuration,last_seen,created_at,paused)
                           VALUES ('legacy','Legacy preserved','hash','legacy-machine',443,'{}','{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,false)""")
        )
    command.upgrade(cfg, "head")
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db:
        agent = db.get(Agent, "legacy")
        assert agent.name == "Legacy preserved" and agent.revoked is False
    barrier = Barrier(2)

    def enqueue(index):
        with factory() as db:
            barrier.wait(timeout=10)
            task = request_check(
                db, "legacy", "test:" + str(index), key="parallel:" + str(index)
            )
            db.commit()
            return task.id

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(enqueue, range(2)))
    assert results[0] == results[1]
    with factory() as db:
        assert len(db.scalars(select(ControlTask)).all()) == 1
    from commander.database import utcnow
    from commander.monitoring import rate_slot

    instant = utcnow()

    def reserve(_):
        with factory() as db:
            allowed, _ = rate_slot(db, "postgres-shared-key", instant)
            db.commit()
            return allowed

    with ThreadPoolExecutor(max_workers=8) as pool:
        slots = list(pool.map(reserve, range(40)))
    assert sum(slots) == 25  # One shared key cannot exceed its budget across workers.
    # Migrating a second time is harmless and does not remove legacy data.
    command.upgrade(cfg, "head")
    with factory() as db:
        assert db.get(Agent, "legacy").name == "Legacy preserved"
    engine.dispose()
