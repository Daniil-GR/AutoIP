# MTProto FakeTLS через Gcore Edge Proxy

Это отдельный от HTTP CDN пилот. Бот создания WEB-поддоменов не создаёт
Edge Proxy и не должен применяться к MTProto-only ноде.

На origin работает Telemt MTProto FakeTLS на TCP 443 с прежним секретом
и SNI `www.booking.com`. Nginx, собственный сертификат и сайт-заглушка
для этого режима не требуются. Gcore передаёт TCP без завершения FakeTLS.
Настройки: `Generic TCP Server` (`tcp-server`), TCP 443, PROXY protocol off.
До проверки защищённого IP DNS, конфигурация Telemt и firewall не меняются.

## Проверенные API

- `GET /iam/clients/me`: статус сервиса `SHIELD_PROXY`.
- `GET /billing/v1/clients/me/trials`: доступность, начало и остаток trial.
- `GET /billing/v4/plans?product_internal_name=SHIELD_PROXY`: тариф и условия.
- `PATCH /billing/client/v1/me/products/SHIELD_PROXY`, `{"plan_id": ID}`:
  активация выбранного тарифа, включая доступный trial. До запроса проверять
  trial_available, is_skip_trial и нулевой prepay_amount. Не повторять запрос
  после неопределённого ответа без сверки. Не активировать платный режим.
- `GET /security/sifter/v3/edge_proxy/templates`: поддерживаемые профили.
- `POST /security/sifter/v3/edge_proxy/profiles`: один согласованный тестовый
  профиль; сохранить checkpoint до запроса и ID после подтверждения.
- `GET /security/sifter/v3/edge_proxy/profiles/{id}`: ждать ACTIVE,
  is_processing=false и is_error=false. Адрес — protected_ip_address.

Тело создания:

```json
{
  "name": "AutoIP MTProto trial",
  "origin_host": "ORIGIN_IPV4",
  "template_id": 1,
  "rules": [{"policy": "tcp-server", "mappings": [{"protocol": "tcp", "port": 443}]}]
}
```

Template ID брать из актуального GET, а не считать неизменным. Отсутствующий
proxy_protocol означает off. Один TCP-порт — одно подключение; не создавать
другие правила при разрешении только одного теста.

Если Gcore возвращает `Can not start trial with non free plan without payment
resource or filled billing information`, администратор должен заполнить
Billing information в кабинете. Личные/банковские данные не придумываются и
не запрашиваются в Telegram. Это не разрешение оплаты или привязки карты.

## Проверки и остановка trial

Сравнить MTProto Checker на origin и на защищённом IP, отдельно сохранить
TCP/handshake/data по RU и внешней точке. Дополнить Check-Host из двух RU-сетей
и трёх зарубежных стран. TCP-успех и один успешный handshake не доказывают
стабильную передачу данных у всех пользователей. Перед изменением A-записи
получить отдельное подтверждение и сохранить прежнее назначение.

Журнал текущего согласованного пилота находится в зашифрованных интеграциях
и SystemSetting `gcore-edge-pilot`; приватные ключи, пароли и secret не
попадают в Git и обычные журналы. Интеграция бота Edge Proxy отложена.

`commander.edge_trial.tick` обрабатывается отдельным worker. При явно заданном
stop_trial_before_paid и наступлении stop_at проверяет, что сервис всё ещё
trial и в аккаунте ровно один профиль с сохранёнными ID, origin и именем.
Затем `PATCH /billing/client/v1/me/products/SHIELD_PROXY` с `plan_id: null`
останавливает пробный сервис по той же схеме, что кнопка Disable в Gcore.
После этого статус сверяется. DNS и VPS при остановке не меняются.
Если появились другие профили или пользователь активировал платный режим,
guard не выключает их, а уведомляет администратора о необходимости сверки.
Сбои сохраняются с error_id; после трёх попыток приходит отдельное уведомление.

Чтобы разрешить платное продолжение, нужно отдельное подтверждение владельца
и явное изменение paid_activation_approved в журнале пилота. Не делать этого
только из-за успешной сетевой проверки.
