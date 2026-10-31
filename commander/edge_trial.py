"""Stop the explicitly approved single Edge Proxy trial before paid usage."""

from datetime import datetime, timedelta

from .cdn_domains import Gcore, credentials
from .database import Notification, SessionLocal, SystemSetting, utcnow
from .security import audit, aware


def can_stop(service, profiles, state):
    rows = profiles.get("results", [])
    return (
        service.get("status") == "trial"
        and profiles.get("count") == 1
        and len(rows) == 1
        and rows[0].get("id") == state.get("edge_profile_id")
        and rows[0].get("origin_host") == state.get("origin")
        and rows[0].get("name") == state.get("configuration", {}).get("name")
    )


async def tick():
    with SessionLocal() as db:
        item = db.get(SystemSetting, "gcore-edge-pilot", with_for_update=True)
        if not item:
            return False
        state = dict(item.value)
        if (
            not state.get("stop_trial_before_paid")
            or state.get("paid_activation_approved")
            or state.get("guard_status") in ("stopped", "manual")
        ):
            return False
        if aware(datetime.fromisoformat(state["stop_at"])) > utcnow():
            return False
        if state.get("guard_lease") and aware(
            datetime.fromisoformat(state["guard_lease"])
        ) > utcnow() - timedelta(minutes=2):
            return False
        if state.get("guard_attempts", 0) >= 3:
            item.value = {**state, "guard_status": "manual"}
            db.add(
                Notification(
                    topic="edge_trial",
                    target="gcore-edge-pilot",
                    text="Не удалось подтвердить остановку пробного Edge Proxy. Проверьте сервис в Gcore до окончания trial; платное продолжение AutoIP не разрешал.",
                )
            )
            db.commit()
            return True
        state.update(
            guard_lease=utcnow().isoformat(),
            guard_attempts=state.get("guard_attempts", 0) + 1,
        )
        item.value = state
        db.commit()
        client = Gcore(credentials(db, state["gcore_id"], "gcore")["api_key"])
        try:
            service = (await client.call("GET", "/iam/clients/me"))["serviceStatuses"][
                "SHIELD_PROXY"
            ]
            if service.get("status") in ("paused", "trialend", "deleted"):
                stopped = True
            else:
                profiles = await client.call(
                    "GET", "/security/sifter/v3/edge_proxy/profiles?limit=100&offset=0"
                )
                if not can_stop(service, profiles, state):
                    item.value = {**state, "guard_status": "manual"}
                    db.add(
                        Notification(
                            topic="edge_trial",
                            target="gcore-edge-pilot",
                            text="Настройки Edge Proxy изменились: автоматическая остановка теста требует сверки. Другие ресурсы или активированный вручную платный сервис не затронуты.",
                        )
                    )
                    db.commit()
                    return True
                await client.call(
                    "PATCH",
                    "/billing/client/v1/me/products/SHIELD_PROXY",
                    json={"plan_id": None},
                )
                service = (await client.call("GET", "/iam/clients/me"))[
                    "serviceStatuses"
                ]["SHIELD_PROXY"]
                stopped = service.get("status") in ("paused", "trialend", "deleted")
            if stopped:
                item.value = {**state, "guard_status": "stopped"}
                audit(db, "system", "gcore_edge_trial_stopped", "gcore-edge-pilot")
                db.add(
                    Notification(
                        topic="edge_trial",
                        target="gcore-edge-pilot",
                        text="Пробный Edge Proxy остановлен до платного продолжения. VPS и DNS не изменялись.",
                    )
                )
            else:
                item.value = {**state, "guard_status": "pending"}
        except Exception as error:
            from .diagnostics import record_failure

            error_id = record_failure("edge_trial", "stop", error)
            item.value = {
                **state,
                "guard_status": "pending",
                "guard_error_id": error_id,
            }
        db.commit()
        return True
