import json

import pytest
import tomlkit

from agent import main, telemt_helper


def test_agent_discovery_never_exposes_secrets(tmp_path, monkeypatch):
    cfg = tmp_path / "telemt.toml"
    cfg.write_text("""[general]
ad_tag = "1234"
middle_proxy_nat_ip = "8.8.8.8"
[general.links]
public_host = "proxy.example.com"
[server]
port = 8443
[access.users]
admin = "SECRET-MUST-STAY-LOCAL"
""")
    monkeypatch.setattr(main, "TELEMT_PATH", cfg)
    detected = main.read_config_facts()
    assert detected["public_host"] == "proxy.example.com"
    assert detected["proxy_port"] == 8443
    assert "SECRET-MUST-STAY-LOCAL" not in json.dumps(detected)
    assert main.proxy_endpoint() == ("proxy.example.com", 8443)


def test_agent_retries_reuse_durable_result(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATE_PATH", tmp_path / "identity.json")
    calls = []

    def execute(job):
        calls.append(job["id"])
        return {
            "status": "succeeded",
            "result": {"written": True, "reload_verified": False},
        }

    monkeypatch.setattr(main, "execute", execute)
    job = {"id": "job-one", "kind": "apply_ad_tag", "payload": {"ad_tag": "a" * 32}}
    one = main.execute_durable(job)
    two = main.execute_durable(job)
    assert one == two and calls == ["job-one"]
    assert (tmp_path / "jobs.sqlite3").stat().st_mode & 0o777 == 0o600


def test_telemt_atomic_write_preserves_other_fields_and_mode(tmp_path, monkeypatch):
    config = tmp_path / "telemt.toml"
    config.write_text("""# existing comment
[general]
ad_tag = "00000000000000000000000000000000"
[general.links]
public_host = "proxy.example.com"
[access.users]
user = "PRIVATE-USER-SECRET"
""")
    config.chmod(0o640)
    monkeypatch.setattr(telemt_helper, "CONFIG", config)
    monkeypatch.setattr(telemt_helper.os, "geteuid", lambda: 0)
    # fchown is irrelevant to the content test and may be restricted on CI.
    monkeypatch.setattr(telemt_helper.os, "fchown", lambda *args: None)
    telemt_helper.apply_ad_tag("a" * 32)
    data = tomlkit.parse(config.read_text())
    assert data["general"]["ad_tag"] == "a" * 32
    assert data["general"]["links"]["public_host"] == "proxy.example.com"
    assert data["access"]["users"]["user"] == "PRIVATE-USER-SECRET"
    assert "# existing comment" in config.read_text()
    assert config.stat().st_mode & 0o777 == 0o640
    backup = config.with_name(config.name + ".autoip.bak")
    assert backup.stat().st_mode & 0o777 == 0o600
    original_backup = backup.read_text()
    telemt_helper.apply_ad_tag("a" * 32)
    assert backup.read_text() == original_backup
    with pytest.raises(ValueError):
        telemt_helper.apply_ad_tag("$(bad-command)")


def test_helper_rejects_symlink_backup(tmp_path, monkeypatch):
    config = tmp_path / "telemt.toml"
    config.write_text('[general]\nad_tag=""\n')
    other = tmp_path / "other"
    other.write_text("do not change")
    config.with_name(config.name + ".autoip.bak").symlink_to(other)
    monkeypatch.setattr(telemt_helper, "CONFIG", config)
    monkeypatch.setattr(telemt_helper.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError):
        telemt_helper.apply_ad_tag("b" * 32)
    assert other.read_text() == "do not change"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://",
        "http://localhost:8000@evil.example",
        "http://127.0.0.1:8000@evil.example",
    ],
)
def test_transport_validation(monkeypatch, url):
    monkeypatch.setattr(main, "COMMANDER", url)
    with pytest.raises(RuntimeError):
        main.check_transport()


def test_unreadable_config_parent_does_not_prevent_heartbeat(monkeypatch):
    from agent import main

    class Unreadable:
        def is_file(self):
            raise PermissionError("private parent")

    monkeypatch.setattr(main, "TELEMT_PATH", Unreadable())
    monkeypatch.setattr(main, "run", lambda *args, **kwargs: "inactive")
    monkeypatch.setattr(main, "read_config_facts", lambda: {"config_readable": False})
    monkeypatch.setattr(main, "network_facts", lambda: {})
    result = main.facts()
    assert result["config_found"] is None
    assert result["config_readable"] is False
