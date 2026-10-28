import pytest

from commander.config import settings
from commander.database import Audit, Integration
from commander.vault import VaultError, decrypt, encrypt, initialize


def test_sessions_require_csrf_and_logout_revokes(client):
    assert client.get("/api/agents").status_code == 401
    result = client.post(
        "/api/session",
        json={"username": settings.admin_user, "password": settings.admin_password},
    )
    assert result.status_code == 200
    cookie = result.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert client.get("/api/agents").status_code == 200
    assert client.post("/api/enrollments", json={"name": "Agent"}).status_code == 403
    csrf = {"X-CSRF-Token": result.json()["csrf"]}
    assert (
        client.post(
            "/api/enrollments", headers=csrf, json={"name": "Agent"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/enrollments",
            headers=csrf | {"Origin": "https://evil.example"},
            json={"name": "Agent"},
        ).status_code
        == 403
    )
    assert client.delete("/api/session", headers=csrf).status_code == 200
    assert client.get("/api/agents").status_code == 401


def test_login_throttled_and_password_not_logged(client):
    secret = "invalid-password-that-must-not-appear"
    for _ in range(10):
        assert (
            client.post(
                "/api/session", json={"username": "admin", "password": secret}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/session", json={"username": "admin", "password": secret}
        ).status_code
        == 429
    )
    with client.factory() as db:
        assert secret not in str([(e.action, e.details) for e in db.query(Audit)])


def test_totp_disables_basic_bypass(client, tmp_path, monkeypatch):
    import pyotp

    secret = pyotp.random_base32()
    path = tmp_path / "totp"
    path.write_text(secret)
    monkeypatch.setattr(settings, "totp_secret_file", str(path))
    assert client.get("/api/agents", auth=client.auth_pair).status_code == 401
    body = {
        "username": settings.admin_user,
        "password": settings.admin_password,
        "otp": "000000",
    }
    assert client.post("/api/session", json=body).status_code == 401
    body["otp"] = pyotp.TOTP(secret).now()
    assert client.post("/api/session", json=body).status_code == 200


def test_integrations_encrypt_and_never_echo(client):
    secret = "unique-fake-token-for-encryption-test"
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "Cherry test",
            "kind": "cherry",
            "credentials": {"api_key": secret},
        },
    )
    assert response.status_code == 200
    assert secret not in response.text
    assert secret not in client.get("/api/integrations", auth=client.auth_pair).text
    with client.factory() as db:
        item = db.get(Integration, response.json()["id"])
        assert secret not in item.ciphertext
        assert decrypt(item) == {"api_key": secret}
        item.id = "different-owner"
        with pytest.raises(VaultError):
            decrypt(item)


def test_validation_errors_do_not_echo_secrets(client):
    secret = "never-echo-this-value"
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={"name": "n", "kind": secret, "credentials": {"api_key": secret}},
    )
    assert response.status_code == 422
    assert secret not in response.text


def test_vault_permissions(tmp_path, monkeypatch):
    path = tmp_path / "key"
    initialize(path)
    assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(settings, "vault_key_file", str(path))
    ciphertext = encrypt("id", "cherry", {"api_key": "example"})
    assert ciphertext
    with pytest.raises(FileExistsError):
        initialize(path)
    path.chmod(0o644)
    with pytest.raises(VaultError):
        encrypt("id", "cherry", {})


def test_body_size_and_security_headers(client):
    assert client.post("/api/session", content="x" * 70000).status_code == 413
    result = client.get("/")
    assert result.status_code == 200
    assert "frame-ancestors 'none'" in result.headers["content-security-policy"]
    assert "no-store" in result.headers["cache-control"]
