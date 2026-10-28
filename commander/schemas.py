import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["cherry", "other"] = "cherry"
    region: str = Field(default="", max_length=80)
    management_ip: str = ""
    floating_ip: str = ""
    cherry_integration_id: str = ""
    cherry_project_id: str = Field(default="", max_length=100)
    cherry_server_id: str = Field(default="", max_length=100)
    dns_integration_id: str = ""
    sni_domain: str = Field(default="", max_length=253)
    dns_zone: str = Field(default="", max_length=253)
    dns_record: str = Field(default="", max_length=253)
    telethon_integration_id: str = ""
    mtproto_integration_id: str = ""
    sponsor_channel: str = Field(default="", max_length=250)
    notes: str = Field(default="", max_length=800)
    max_candidates_per_incident: int = Field(default=3, ge=1, le=10)
    max_ips_per_day: int = Field(default=6, ge=0, le=100)
    max_billed_ips: int = Field(default=2, ge=1, le=10)
    monthly_budget_cents: int = Field(default=0, ge=0, le=10000000)
    automation_mode: Literal["manual", "paused"] = "manual"

    @field_validator("management_ip", "floating_ip")
    @classmethod
    def valid_ip(cls, value):
        if value:
            addr = ipaddress.ip_address(value)
            if addr.version != 4 or not addr.is_global:
                raise ValueError("Требуется публичный IPv4")
        return value

    @field_validator("sponsor_channel")
    @classmethod
    def channel(cls, value):
        if value and not re.fullmatch(
            r"(?:https://t\.me/|@)[A-Za-z][A-Za-z0-9_]{3,31}", value
        ):
            raise ValueError("Требуется публичный Telegram-канал")
        return value


class IntegrationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=100)
    kind: Literal[
        "cherry", "dynadot", "telegram_bot", "telethon", "ripe_atlas", "mtproto"
    ]
    credentials: dict[str, str] = Field(repr=False)
    metadata: dict = Field(default_factory=dict)

    @field_validator("credentials")
    @classmethod
    def bounded(cls, value):
        if len(value) > 6 or any(len(v) > 8192 for v in value.values()):
            raise ValueError("Слишком большой набор ключей")
        return value

    def validate_keys(self):
        keys = {
            "cherry": {"api_key"},
            "dynadot": {"api_key", "api_secret"},
            "telegram_bot": {"token"},
            "telethon": {"api_id", "api_hash", "session"},
            "ripe_atlas": {"api_key"},
            "mtproto": {"secret"},
        }[self.kind]
        if set(self.credentials) != keys or not all(self.credentials.values()):
            raise ValueError("Необходимы поля: " + ", ".join(sorted(keys)))
        if self.kind == "mtproto" and not re.fullmatch(
            r"[a-fA-F0-9]{32}", self.credentials["secret"]
        ):
            raise ValueError("Секрет MTProto должен содержать 32 hex-символа")
        if self.metadata:
            raise ValueError(
                "Произвольные метаданные интеграции пока не поддерживаются"
            )


SAFE_FACTS = {
    "hostname",
    "os",
    "telemt_version",
    "telemt_service",
    "config_found",
    "config_readable",
    "ad_tag_present",
    "middle_proxy_nat_ip_set",
    "middle_proxy_nat_ip",
    "interfaces",
    "routes",
    "listeners",
    "tls_domain",
    "outbound_bind_configured",
    "mtproto_fix_present",
}


def safe_facts(facts):
    # Never accept an arbitrary config or credentials in agent inventory.
    import json

    clean = {k: v for k, v in facts.items() if k in SAFE_FACTS}
    if len(json.dumps(clean)) > 32768:
        raise ValueError("Слишком большой отчёт агента")
    return clean


class CommanderPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    monitor_enabled: bool = False
    monitor_interval_seconds: int = Field(default=180, ge=30, le=86400)
    telegram_admin_ids: list[int] = Field(default_factory=list, max_length=20)
    monthly_budget_cents: int = Field(default=0, ge=0, le=10000000)
    account_budget_cents: dict[str, int] = Field(default_factory=dict)

    @field_validator("telegram_admin_ids")
    @classmethod
    def admin_ids(cls, values):
        if any(value <= 0 for value in values):
            raise ValueError("Требуется положительный Telegram User ID")
        return sorted(set(values))

    @field_validator("account_budget_cents")
    @classmethod
    def budgets(cls, values):
        if (
            any(value < 0 or value > 10000000 for value in values.values())
            or len(values) > 100
        ):
            raise ValueError("Некорректный бюджет")
        return values
