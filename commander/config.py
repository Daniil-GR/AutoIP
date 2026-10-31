from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTOIP_", extra="ignore")
    admin_user: str = "admin"
    admin_password: str
    database_url: str = "sqlite:///./autoip-dev.sqlite3"
    public_url: str = ""
    agent_git_ref: str = "main"
    display_timezone: str = "UTC"
    vault_key_file: str = ""
    telegram_bot_token: str = ""  # Legacy environment fallback; prefer vault.
    telegram_chat_id: str = ""
    telegram_admin_ids: list[int] = Field(default_factory=list)
    totp_secret_file: str = ""
    monitor_enabled: bool = False
    monitor_interval_seconds: int = Field(default=300, ge=30)
    worker_enabled: bool = False
    session_hours: int = Field(default=8, ge=1, le=24)


settings = Settings()
if len(settings.admin_password) < 12:
    raise RuntimeError("AUTOIP_ADMIN_PASSWORD must be at least 12 characters")
