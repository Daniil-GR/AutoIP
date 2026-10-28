# Установка Agent на отдельный новый сервер

Не устанавливайте автоматически на работающий прокси. Сначала проверьте систему, config path и основной маршрут управления. Установщик не меняет адреса/маршруты/Telemt.

Требуется Python 3.12+, venv и Git. Корневой код `/opt/AutoIP` должен принадлежать root и быть недоступен для записи пользователю `autoip-agent`.

```sh
git clone https://github.com/Daniil-GR/AutoIP.git /opt/AutoIP
sudo bash /opt/AutoIP/agent/install.sh
```

Запишите HTTPS Commander URL в `/etc/autoip-agent/agent.env` (root:autoip-agent, 0640). Создайте код регистрации в панели:

```sh
cd /opt/AutoIP
sudo /opt/AutoIP/.venv/bin/python -m agent.main enroll-local https://commander.example.com
sudo systemctl enable --now autoip-agent
```

`enroll-local` читает код через getpass, сбрасывает root до `autoip-agent` перед HTTPS-запросом и сохраняет identity 0600. Токен не передаётся аргументом. Ключи провайдеров на Agent не нужны.

Если Telemt TOML закрыт для service user, опционально разрешите только ограниченный config reader:

```sh
sudo bash /opt/AutoIP/agent/install.sh --with-config-reader
```

Этот вариант запускает отдельный socket-activated root broker, проверяющий UID клиента. Через сокет доступны только безопасные факты Telemt. Запись ad_tag по умолчанию запрещена и требует отдельного аудита и root-owned флага `/etc/autoip-agent/allow-ad-tag-write`, а также `AUTOIP_ALLOW_AD_TAG_WRITE=true`. Не включайте на действующем сервере без согласования. Agent service сохраняет NoNewPrivileges и пустой набор capabilities.

При записи TOML сохраняются комментарии/секреты/public_host, используется блокировка, атомарная замена и backup 0600. Сохранение ad_tag не подтверждает hot reload; Commander показывает отдельный непроверенный статус. Root helper не выполняет shell, restart или сетевые команды.

Identity: `/var/lib/autoip-agent/identity.json`; результаты заданий: соседний `jobs.sqlite3`. Не переносите identity на другой сервер. При обновлении не удаляйте состояние; остановите только `autoip-agent`, обновите код/virtualenv и запустите заново.
