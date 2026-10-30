# Одиночный пилот Floating IP — 30 октября 2026

По явному разрешению владельца куплен один Floating IP **84.32.51.178**
в проекте 296910, LT-Siauliai, и назначен node1 (1047751).
Ресурс: `bd78a549-bac4-9292-a301-1cda169990ca`.
Операция: `c689c9cd-e086-4d60-8c5e-2bc6479c31ae`.
Это оплачиваемый резерв; его удаление или DNS-переключение ожидает решения
владельца. Основной IPv4 остаётся 88.216.62.216.

## Реальные результаты

- История AutoIP проверена до Attach: новый адрес ранее не встречался.
- POST `/v1/projects/{project}/ips`: тело с полем region, без tags.
- PUT `/v1/ips/{floating_uuid}`: routed_to равен UUID основного IP сервера,
  не строке IPv4 и не ID сервера. Назначение подтверждено отдельным GET.
- Дополнительный /32 добавлен на eth0 отдельным systemd unit, включённым
  для загрузки ОС. Сама перезагрузка в пилоте не выполнялась.
- До commit действовал десятиминутный аварийный таймер удаления только
  добавленного адреса. После проверки таймер снят, unit активен и enabled.
- MTProto Checker (2026-10-30 09:52 UTC): OK. RU и внешняя точка подтвердили
  TCP, handshake и data. Секрет использован из защищённого хранилища.
- HTTPS с SNI lt.vetka.rest принудительно направлен на новый IP: HTTP 200,
  сертификат принят. Это не проверка полного потока данных WEB-прокси.
- Telemt и Agent активны; конфигурация Telemt и маршруты не изменены.
- DNS, активный адрес агента и ad_tag не переключались.

## Исполнение и границы

`commander.floating_pilot` — локальный CLI администратора:

```sh
python -m commander.manage floating-ip-pilot order --agent-id UUID --operation-id UUID --approved
python -m commander.manage floating-ip-pilot attach --operation-id UUID --approved
python -m commander.manage floating-ip-pilot status --operation-id UUID
```

Каждый новый заказ требует разрешения владельца; --approved сам по себе его
не даёт. Операция фиксируется в БД до POST. Повтор того же UUID не покупает
ещё адрес. При потере ответа нужна сверка провайдера, не новый заказ вслепую.
Начальный запрос с несовместимым tags не создал ресурс. Перед исправленным
заказом отсутствие нового ресурса сверено через API; платный ресурс создан один.
Ошибки не раскрывают ключи и тела ответов.

`agent.network_pilot` — root CLI пилота, пока не задание polling Agent.
Подключение использует выделенный SSH-ключ в закрытом каталоге secrets.
На ноде из каталога установки Agent:

```sh
.venv/bin/python -m agent.network_pilot prepare --resource-id UUID --address IPV4 --management MANAGEMENT_IPV4
.venv/bin/python -m agent.network_pilot commit --resource-id UUID
.venv/bin/python -m agent.network_pilot rollback --resource-id UUID
```

Prepare запрещает менять основной адрес или добавлять уже существующий.
Проверяются сохранность default route, исходящего адреса и хеша Telemt.
Журнал: /var/lib/autoip-floating-pilot/UUID.json; unit: autoip-floating-UUID.service.
Rollback останавливает только свой unit и не освобождает оплачиваемый ресурс
Cherry. Его удаление требует отдельного согласования и сохранения истории.

В Commander сохраняются FloatingIP, аудит и SystemSetting fip-pilot:UUID.
ready_standby не подменяет активный proxy_ip/floating_ip агента.
Автоматическое восстановление, безопасная запись Dynadot, удаление кандидатов
и перенос root CLI в ограниченный helper Agent ещё не завершены. Проверка
нынешнего пилота не доказывает весь этот цикл.
