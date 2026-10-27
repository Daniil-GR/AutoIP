# AutoIP — полное техническое задание

## 0. Текущий статус

На момент создания данного файла репозиторий содержит только ранний MVP v0.1: Commander, PostgreSQL, веб-панель, enrollment, агент, heartbeat, очередь разрешённых заданий, необработанные наблюдения Check-Host, сохранение несекретных настроек агента.

**НЕТ** работающего автоматического восстановления, Cherry API покупок, Dynadot смены DNS, взаимодействия с MTProxybot через Telethon, второго мониторинга, полноценного инцидент-менеджера, защищённого хранилища ключей или промышленной авторизации.

Не выдавать незавершённые функции за работающие. Не включать платные операции по умолчанию. Сохранять безопасность действующего Telemt.

## 1. Бизнес-задача

Один независимый управляющий VPS (Commander) обслуживает несколько серверов Agent с установленным Telemt. Каждый Agent имеет основной management IP и заменяемый Floating IP. Цель — обнаруживать недоступность MTProto из РФ, подтверждать инцидент вручную или по нескольким отложенным замерам, получать новый чистый Floating IP Cherry Servers, безопасно подключать и проверять, изменять единственную нужную A-запись и восстанавливать спонсорство канала через @MTProxybot.

Управление всей системой централизовано через русскоязычную адаптивную веб-панель и отдельного Telegram-бота.

Agent подключается к Commander исходящим HTTPS, не требует входящего SSH. Управление Agent не должно идти через его изменяемый Floating IP.

## 2. Обязательные объекты данных

- Commander administrators, roles, audit logs.
- Providers: Cherry accounts and projects; DNS providers and zones; Telegram accounts; monitoring services.
- Agent: UUID, display name, description, region, hoster, management address, machine identity, public_host, Telemt port, version, facts, last heartbeat, monitoring config and limits.
- Floating IP: provider resource ID, IPv4, project, assigned server, allocated/released at, paid lifecycle, status, last diagnostic evidence, origin, ownership of AutoIP.
- Check: source, country/ASN/node, target IP:port, DNS name, result tri-state and raw evidence, latency, timestamp.
- Incident: agent, observed IP, start/end, status, evidence, admin response, scheduled rechecks, deadlines, final verdict, recovery ID.
- Recovery: state machine, idempotency key, stages, input and verified outcomes, expenses, rollback data, partial-failure condition.
- Telegram bot registrations: per-agent ad_tag and status (do not confuse with users' MTProto secret).
- Command jobs: allowed kind, request, TTL, idempotency key, agent lease, acknowledgments, retry caps and audit.
- Budgets: global, per-Cherry-account and per-agent; resource count and estimated actual amounts.

All changes must be transactionally tracked, with PostgreSQL migrations and periodic backups.

## 3. Master of onboarding

In Commander panel button «Добавить агента» creates single-use enrollment token with 15-minute expiry. Local agent installation must verify identity via outbound TLS and local machine-id. Display one-time install/enroll instructions.

After enrollment auto-detect: OS, hostname, Telemt version, systemd unit, config path, listening port, public_host, agent main management IP, listener/bind rules, NAT override, installed MEKO fixes and basic network setup; never upload entire config or secret.

Commander asks missing information via web wizard and **remembers** it:
- Agent name and group, region and provider.
- Cherry credentials/project/server associations.
- DNS authoritative provider, zone and record.
- Telegram sponsoring public channel.
- Chosen MTProto user secret or safe way to request it, without sending it in Telegram chat.
- Monitoring sources, thresholds and budget.
- Whether manual or automatic restoration is permitted.

Reuse integrations across agents without sharing individual agent state. Provide test-connection buttons and readiness checklist. Secret input must go only to authenticated HTTPS form, encrypted at rest with external master key or encrypted vault. Never echo secrets in API, UI, logs or jobs.

## 4. Check-Host and second source

Check each agent every 3 minutes. Check TCP to public_host:port and resolved IPv4:port from several RU and non-RU nodes. Check-Host is asynchronous; poll /check-result until complete; null/unknown/timeout is NOT proof of IP blocking.

Second monitoring provider will be supplied later. Implement pluggable interface to permit real MTProto tests, distinct RU ASN observations, DNS vs IP diagnostics and network-level node data.

Do not classify service crash, routing error, DNS drift, unassigned IP or monitoring API outage as censorship. Prefer true protocol checks from independent RU points. Store evidence.

Until second source or equivalent independent evidence is available, do not allow automatic purchases.

## 5. Manual override and timeout

Suspected block -> Telegram notification to authorized admin, with affected agent/IP, RU probes, foreign probes, service status and buttons:
«Подтвердить блокировку», «Прокси работает», «Повторить проверку», «Отложить».

If admin confirms, execute a short final sanity check; start immediate recovery if evidence remains valid.

If no answer: run new independent checks at +15, +20 and +25 minutes after original alert. If all fail and safeguards hold, enter automatic recovery. A recovered agent cancels pending replacement. Admin deny/hold prevents purchase.

Callbacks signed/one-time, bound to a particular incident, admin ID and deadline; prevent stale clicks/double jobs. Timers survive Commander restarts.

## 6. Cherry Servers

Commander uses official Cherry API. Read-only integration first: list projects, servers, IP resources and valid routes. Verify actual method schemas and billing policy, including whether exact available IP can be selected *before* allocation (do not assume yes).

Typed paid mutations: create, route/assign, inspect, unroute, delete. After timeouts reconcile provider state before retry. Persist resource IDs before proceeding. Never act on IPs not explicitly owned by AutoIP.

IP ledger stores every acquired IPv4, including released/rejected/blocked. If Cherry reassigns an IP known as previously blocked, reject it without DNS swap, possibly allow manual retest later.

Enforce budget caps: defaults <= 3 candidates/incident, 6 new IP/day/agent, <=2 currently billed managed IPs/agent, explicit monthly budget. If unknown cost or insufficient funds/permissions, STOP with notification.

## 7. Network operations on Agent

Before live functionality, audit Cherry routing, main SSH path, NIC, default route, Netplan and firewall, Telemt and MEKO rules. Use a fixed-command restricted privileged helper; never execute arbitrary shell from JSON.

Configure only the selected Floating IP and proper routing. Keep SSH/management IP untouched. Test route/binding from local and remote monitors before DNS switch.

Use staged changes, timed automatic rollback, durable local record; survive network connectivity loss/reboots. Do not assume /32 or public egress behavior without verified provider guidance.

## 8. DNS update

Detect authoritative DNS provider. For Dynadot validate current REST and legacy APIs before choosing. Legacy set_dns2 may replace an entire DNS configuration; must guarantee preservation of ALL other RRsets (MX/TXT/NS/etc).

Stage a lossless DNS snapshot. Do precise single A RRset update or safe CAS revision of zone. If impossible with provider API, STOP and ask admin to change DNS provider or manually approve alternative.

Verify authoritative NS now return new IPv4, then propagation from several resolvers. Respect prior TTL and keep old IP until safe grace period or explicit policy.

If DNS update failed, do not blindly detach/release old IP. Never change public_host, client secrets or SNI merely because Floating IP rotates.

## 9. Telemt

All Agent fields discovered, not hardcoded, except known safe defaults. Standard config path /etc/telemt/telemt.toml.

- [general.links].public_host remains constant across IP changes.
- [general].ad_tag is Telegram promotion tag, not MTProto user secret.
- [access.user_ad_tags] can override global ad_tag.
- [general].middle_proxy_nat_ip and network egress binds need audit for stale IP references.
- In supported Telemt versions general.ad_tag is hot reloadable for subsequent connections; verify installed version and logs before marking successful.

Use TOML parser preserving formatting, atomic save and backup. Validate config. Avoid full restart if hot reload works. Roll back safely on failure.

## 10. Telegram / MTProxybot

Dedicated user-account Telethon session resides ONLY on Commander, alongside but separate from own notification Telegram Bot API token.

Test compatibility with @MTProxybot by conducting one real controlled registration. Do not assume a supported public bot automation API exists. Sessions are sensitive secrets; store safely and never sync to Agents.

Per new IP:
- Serial Telegram dialogs by account.
- /newproxy, new IP:port, existing user-secret, parse 32-hex ad_tag.
- /myproxies, select correct registered proxy, Set promotion with public Telegram channel.
- Track intermediate states, unexpected responses and flood waits.
- Pass verified ad_tag to correct Agent in a typed job, apply with hot reload, verify independently.
- If bot interface changed, mark SPONSOR_MANUAL_REQUIRED; do NOT disable already working proxy.

Test whether registration can use a hostname and survive A-record change; until verified, treat IP-specific registration as necessary. Sponsorship propagation may be delayed.

## 11. Multi-agent panel

Responsive dark/light interface (Russian):
- Dashboard: online/offline agents, RU availability, incidents, restoring, IP resource usage, spending, graph.
- Agent list: filters by region/provider/health/last heartbeat.
- Agent details: overview, monitoring history, Floating IP ledger, sponsorship status, recovery timeline, logs, settings.
- Onboarding wizard with incremental discovery and persisted answers.
- Integrations: Cherry accounts/project mapping, DNS credentials/zones, Telegram account/channel mapping, monitoring providers, test action and vault status.
- Settings and costs: permissions, thresholds and mandatory budgets.
- Incident controls: confirm, ignore, check now, pause, recover, review operations.

Use accessible buttons and real API callbacks, never decorative controls pretending to run actions.

## 12. State and recovery

Use explicit states: HEALTHY, SUSPECTED, WAITING_CONFIRMATION, RECHECKING, BLOCK_CONFIRMED, ALLOCATING, ATTACHING, TESTING, DNS_SWITCHING, VERIFYING, RECOVERED, SPONSOR_PENDING, MANUAL_REQUIRED, FAILED, PAUSED.

Jobs and state changes logged atomically, no concurrent purchases for same Agent or provider project. Recovery after process crash re-reads Cherry state and DNS before proceeding. Every external mutation uses an idempotency or reconcile-before-retry strategy. Notifications never claim success before it is confirmed.

## 13. Production security and CI

TLS, strong admin authentication, rate limiting, TOTP, CSRF, session security, agent credential revocation and rotation, vault encryption, audit logs, backup/restore, host firewalls.

Agent privileges scoped to fixed operations. No root long-running Python service or generic remote shell, no permanent trust in user-supplied values, no handling secrets via Telegram chat.

Tests: negative checks, independent monitor disagreement, admin yes/no, three delayed checks and restart, Cherry duplicate/timeout/budget, invalid/unavailable candidates, route rollback, DNS preservation, Telemt hot reload, Telethon unknown response, single-agent isolation, race/retries and actual MTProto connection tests in permitted controlled environments.

## 14. Delivery sequencing

Milestone A: harden working Commander/Agent MVP, on-boarding, CI and migrations.
Milestone B: second monitor adapter and incident confirmation UI/Telegram.
Milestone C: Cherry API and safe Agent network helper, manual paid pilot.
Milestone D: DNS provider and end-to-end dry-run of recovery.
Milestone E: Telethon sponsorship and ad_tag update with independent status.
Milestone F: budgets, automatic mode, production hardening and backup.

Every milestone must include tests and observed results. Paid or destructive operations ALWAYS disabled until explicit approval and verified prerequisites. Never break existing Telemt or management SSH while working.

## 15. Acceptance

On three test Agents, Commander can connect, collect diagnostics, ask missing values, persist independent configurations, monitor and display health and incidents.

For full production target: recover a blocked test Floating IP under budget after manual approval/timeout; verify DNS and actual MTProto availability from RU; collect/tag sponsorship or notify separate failure; release only managed old resources after grace period; recover safely from every intermediate crash. Document any unverified external behavior honestly.
