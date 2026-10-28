from .config import settings
from .database import SystemSetting
from .schemas import CommanderPolicy


def get_policy(db):
    stored = db.get(SystemSetting, "commander")
    if stored:
        return CommanderPolicy(**stored.value)
    return CommanderPolicy(
        monitor_enabled=settings.monitor_enabled,
        monitor_interval_seconds=settings.monitor_interval_seconds,
        telegram_admin_ids=settings.telegram_admin_ids,
    )
