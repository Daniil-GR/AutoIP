from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTOIP_")
    admin_user: str = "admin"
    admin_password: str
    database_url: str = "sqlite:///./autoip-dev.sqlite3"
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    monitor_enabled: bool = False
    monitor_interval_seconds: int = 180

settings = Settings()
if len(settings.admin_password) < 12:
    raise RuntimeError("AUTOIP_ADMIN_PASSWORD must be at least 12 characters")
