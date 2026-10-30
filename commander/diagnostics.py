"""Persistent, correlated failures without exception text, locals or requests."""

import json
import logging
import re
import traceback
from pathlib import Path
from uuid import uuid4

from .database import Audit, SessionLocal, utcnow

log = logging.getLogger(__name__)


def label(value):
    return re.sub(r"[^a-zA-Z0-9_.:-]", "_", str(value))[:100]


def record_failure(
    component, stage, error, *, agent_id="", task_id="", operation_id=""
):
    event = {
        "error_id": str(uuid4()),
        "time": utcnow().isoformat(),
        "level": "error",
        "component": label(component),
        "stage": label(stage),
        "agent_id": label(agent_id),
        "task_id": label(task_id),
        "operation_id": label(operation_id),
        "error_type": label(type(error).__name__),
        # extract_tb's source text is deliberately discarded, as are locals.
        "frames": [
            {
                "file": label(Path(f.filename).name),
                "line": f.lineno,
                "function": label(f.name),
            }
            for f in traceback.extract_tb(error.__traceback__)[-8:]
        ],
    }
    log.error(json.dumps(event, ensure_ascii=False))
    try:
        with SessionLocal() as db:
            db.add(
                Audit(
                    actor="system",
                    action="operation_error",
                    target=label(agent_id),
                    details=event,
                )
            )
            db.commit()
    except Exception as storage_error:
        # DB failures must not suppress the original event or cause recursion.
        log.error(
            json.dumps(
                {
                    "error_id": event["error_id"],
                    "stage": "diagnostic_storage_failed",
                    "error_type": label(type(storage_error).__name__),
                }
            )
        )
    return event["error_id"]
