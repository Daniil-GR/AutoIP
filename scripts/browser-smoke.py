"""Real browser checks against a disposable local Commander, without external calls."""

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="autoip-browser-") as folder:
        folder = Path(folder)
        key = folder / "key"
        key.write_bytes(Fernet.generate_key())
        key.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {
            **os.environ,
            "AUTOIP_ADMIN_PASSWORD": "isolated-browser-password",
            "AUTOIP_DATABASE_URL": "sqlite:///" + str(folder / "db.sqlite3"),
            "AUTOIP_MONITOR_ENABLED": "false",
            "AUTOIP_PUBLIC_URL": "",
            "AUTOIP_VAULT_KEY_FILE": str(key),
            "AUTOIP_TOTP_SECRET_FILE": "",
            "AUTOIP_TELEGRAM_ADMIN_IDS": "[]",
        }
        subprocess.run(
            [sys.executable, "-m", "commander.manage", "migrate"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
        )
        seed = """from commander.database import Agent, SessionLocal, utcnow
with SessionLocal() as db:
 for index in range(3):
  db.add(Agent(name=['Москва · основной','Франкфурт · резерв','Хельсинки · тест'][index],token_hash='browser-fake-'+str(index),machine_id='browser-'+str(index),public_host='browser'+str(index)+'.vetka.rest',last_seen=utcnow(),facts={'telemt_service':'active','os':'Ubuntu 24.04'},configuration={}))
 db.commit()
"""
        subprocess.run(
            [sys.executable, "-c", seed],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
        )
        with open(folder / "server.log", "w") as output:
            server = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "commander.app:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--no-access-log",
                ],
                cwd=ROOT,
                env=env,
                stdout=output,
                stderr=output,
            )
            try:
                base = f"http://127.0.0.1:{port}"
                for _ in range(100):
                    try:
                        urllib.request.urlopen(base + "/health", timeout=1)
                        break
                    except OSError:
                        if server.poll() is not None:
                            raise RuntimeError("Disposable Commander failed to start")
                        time.sleep(0.1)
                artifacts = ROOT / "artifacts"
                artifacts.mkdir(exist_ok=True)
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                    page = browser.new_page(viewport={"width": 1440, "height": 1050})
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(base)
                    page.get_by_label("Логин", exact=True).fill("admin")
                    page.get_by_label("Пароль", exact=True).fill(
                        "isolated-browser-password"
                    )
                    page.get_by_role("button", name="Войти", exact=True).click()
                    page.locator(
                        "#agents"
                    ).count()  # navigation is populated before first data load
                    page.get_by_text("Всего агентов", exact=True).wait_for()
                    page.screenshot(
                        path=str(artifacts / "commander-desktop.png"), full_page=True
                    )
                    for key in [
                        "agents",
                        "monitoring",
                        "ips",
                        "sponsorship",
                        "integrations",
                        "incidents",
                        "settings",
                    ]:
                        page.locator("#nav-" + key).click()
                        page.wait_for_timeout(300)
                        assert page.locator("#screen").inner_text().strip(), key
                    page.get_by_label("Интервал проверок, сек.").fill("210")
                    page.get_by_role(
                        "button", name="Сохранить настройки", exact=True
                    ).click()
                    page.get_by_text("Настройки сохранены в БД", exact=True).wait_for()
                    page.reload()
                    page.locator("#nav-settings").click()
                    assert (
                        page.get_by_label("Интервал проверок, сек.").input_value()
                        == "210"
                    )
                    page.locator("#nav-agents").click()
                    page.get_by_role(
                        "button", name="Открыть агента", exact=True
                    ).first.click()
                    page.get_by_role(
                        "button", name="Настройки и готовность", exact=True
                    ).click()
                    page.get_by_label("Постоянный Management IPv4").fill("8.8.8.8")
                    page.get_by_label("Клиентский Floating IPv4").fill("1.1.1.1")
                    page.get_by_role("button", name="Сохранить", exact=True).click()
                    page.get_by_text("Настройки сохранены", exact=True).wait_for()
                    page.locator("#nav-integrations").click()
                    page.get_by_role(
                        "button", name="+ Подключить интеграцию", exact=True
                    ).click()
                    page.get_by_label("Название", exact=True).fill(
                        "Тестовая интеграция браузера"
                    )
                    page.get_by_label("api_key", exact=True).fill("fake-browser-token")
                    page.get_by_role("button", name="Сохранить", exact=True).click()
                    page.get_by_text(
                        "Ключи зашифрованы и сохранены", exact=True
                    ).wait_for()
                    page.get_by_text(
                        "Тестовая интеграция браузера", exact=True
                    ).wait_for()
                    page.locator("#nav-dashboard").click()
                    page.set_viewport_size({"width": 390, "height": 844})
                    page.wait_for_timeout(400)
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    ), "Mobile page overflows viewport"
                    page.screenshot(
                        path=str(artifacts / "commander-mobile.png"), full_page=True
                    )
                    assert not errors, errors
                    browser.close()
                print(
                    "Browser checks passed: desktop, mobile, 8 sections, settings persistence, agent setup, encrypted integration form; no external mutations."
                )
            finally:
                server.terminate()
                server.wait(timeout=10)


if __name__ == "__main__":
    main()
