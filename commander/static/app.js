"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  page: "dashboard",
  agents: [],
  csrf: "",
  timer: null,
  ticketTimer: null,
  renderId: 0,
};
const pages = {
  dashboard: ["▦", "Обзор", "Состояние инфраструктуры и последние события"],
  agents: ["◈", "Агенты", "Серверы Telemt и индивидуальные настройки"],
  monitoring: ["⌁", "Мониторинг", "Наблюдения из России и других стран"],
  ips: ["◎", "Floating IP", "Учёт адресов и расходов"],
  vps: ["▣", "VPS Node Host", "Польские VPS, проверка SSH и перенос Telemt"],
  sponsorship: [
    "✦",
    "Спонсорство",
    "Регистрации Telegram и применение рекламных тегов",
  ],
  integrations: [
    "⛓",
    "Интеграции",
    "Общие подключения и защищённое хранение ключей",
  ],
  incidents: ["≋", "События", "Инциденты, решения и журнал операций"],
  settings: ["⚙", "Настройки", "Безопасность и готовность Commander"],
};
const statuses = {
  vps_access: "Доступ к VPS",
  telemt_profile: "Профиль Telemt",
  tls_lineage: "Сертификат польской ноды",
  existing_current: "Исходная польская нода",
  blocked: "Заблокирован",
  RECOVERING: "Восстановление выполняется",
  QUEUED: "В очереди",
  RUNNING: "Выполняется",
  ROLLING_BACK: "Возврат DNS",
  SUCCEEDED: "Завершено",
  CANCELLED: "Отменено: доступность восстановилась",
  ROLLED_BACK: "Выполнен возврат DNS",
  PREFLIGHT: "Подготовка",
  LIVE_EXECUTION: "Живое выполнение",
  FINAL_CHECK: "Финальная проверка блокировки",
  CANDIDATE_CHECK: "Проверка существующего резерва",
  DNS_ADD: "Добавление нового A-адреса",
  DNS_REMOVE: "Удаление старого A-адреса",
  DNS_VERIFY: "Проверка DNS и MTProto",
  COMMIT: "Сохранение нового активного IP",
  ROLLBACK: "Возврат исходной DNS-записи",
  active: "Работает",
  inactive: "Остановлен",
  available: "Доступен",
  unavailable: "Недоступен",
  partial: "Частично доступен",
  reachable: "Доступен",
  proxy_degraded: "Прокси недоступен или деградировал",
  tcp_only: "TCP доступен; MTProto не подтверждён",
  suspected: "Вероятная недоступность",
  unknown: "Неопределённо",
  local_fault: "Проблема агента или Telemt",
  observed: "Наблюдение",
  WAITING_CONFIRMATION: "Ждёт решения",
  RECHECKING: "Повторная проверка",
  MANUAL_REQUIRED: "Нужно вмешательство",
  RECOVERED: "Доступность восстановлена",
  DISMISSED: "Отклонён",
  PAUSED: "Приостановлен",
  BLOCK_CONFIRMED: "Подтверждён",
  NOT_CONFIGURED: "Не настроено",
  queued: "В очереди",
  running: "Выполняется",
  sni_available: "SNI-домен доступен",
  sni_unavailable: "SNI-домен недоступен",
  sni_partial: "SNI-домен: частичная доступность",
  sni_unknown: "SNI-домен: нет данных",
  TAG_WRITTEN_UNVERIFIED: "Тег записан; hot reload не проверен",
  TAG_APPLIED_AWAITING_CLIENT: "Тег применён; ожидается проверка канала в клиенте",
  TAG_APPLY_FAILED: "Тег не применён",
  PROMOTION_MANUAL_REQUIRED: "Нужна ручная настройка канала",
  AD_TAG_PENDING: "Ожидается применение тега",
  succeeded: "Завершено",
  failed: "Ошибка",
  authorization_required: "Нужна авторизация локально",
  authorization_in_progress: "Выполняется локальная авторизация",
  verified: "Проверено",
  not_tested: "Не проверено",
};
const title = (x) => statuses[x] || x;
function el(tag, text = "", cls = "") {
  const e = document.createElement(tag);
  e.textContent = String(text ?? "");
  e.className = cls;
  return e;
}
function button(text, fn, cls = "btn secondary") {
  const b = el("button", text, cls);
  b.type = "button";
  b.onclick = async () => {
    b.disabled = true;
    try {
      await fn();
    } catch (e) {
      toast(e.message);
    } finally {
      b.disabled = false;
    }
  };
  return b;
}
function toast(text) {
  $("toast").textContent = text;
  $("toast").style.display = "block";
  clearTimeout(state.timer);
  state.timer = setTimeout(() => ($("toast").style.display = "none"), 6500);
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": state.csrf,
      ...options.headers,
    },
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw Error("Сервер вернул некорректный ответ");
  }
  if (response.status === 401) {
    showLogin();
    throw Error("Войдите в панель");
  }
  if (!response.ok)
    throw Error(
      typeof data.detail === "string"
        ? data.detail
        : "Проверьте введённые значения",
    );
  return data;
}
const write = (path, data, method = "POST") =>
  api(path, { method, body: JSON.stringify(data) });
function showLogin() {
  $("workspace").hidden = true;
  $("workspace").style.display = "none";
  $("login").hidden = false;
  $("login").style.display = "grid";
}
function showWorkspace() {
  $("login").hidden = true;
  $("login").style.display = "none";
  $("workspace").hidden = false;
  $("workspace").style.display = "flex";
}
function field(label, value = "", type = "text") {
  const wrap = el("div", "", "field"),
    input = el("input");
  const id = "input-" + crypto.randomUUID();
  input.id = id;
  input.type = type;
  input.value = value;
  const lab = el("label", label);
  lab.htmlFor = id;
  wrap.append(lab, input);
  return { wrap, input };
}
function panel(heading) {
  const box = el("section", "", "panel"),
    head = el("div", "", "panel-head"),
    body = el("div", "", "panel-content");
  head.append(el("strong", heading));
  box.append(head, body);
  return { box, body };
}
function card(heading, body) {
  const c = el("section", "", "card");
  c.append(el("h3", heading), el("p", body));
  return c;
}
function kv(label, value) {
  const row = el("div", "", "detail-row");
  row.append(el("span", label), el("span", value || "—"));
  return row;
}
function modal(heading, description) {
  $("dialogTitle").textContent = heading;
  $("dialogDesc").textContent = description;
  $("dialogBody").replaceChildren();
  $("action").hidden = true;
  $("modal").classList.add("show");
  $("close").focus();
  clearInterval(state.ticketTimer);
}
function closeModal() {
  $("modal").classList.remove("show");
  clearInterval(state.ticketTimer);
  $("dialogBody").replaceChildren();
}
$("close").onclick = closeModal;
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});
$("modal").onclick = (e) => {
  if (e.target === $("modal")) closeModal();
};
$("loginForm").onsubmit = async (e) => {
  e.preventDefault();
  $("loginError").textContent = "";
  try {
    const result = await write("/api/session", {
      username: $("username").value,
      password: $("password").value,
      otp: $("otp").value,
    });
    state.csrf = result.csrf;
    $("password").value = "";
    $("otp").value = "";
    showWorkspace();
    await render();
  } catch (e) {
    $("loginError").textContent = e.message;
  }
};
$("logout").onclick = async () => {
  try {
    await api("/api/session", { method: "DELETE" });
  } finally {
    state.csrf = "";
    showLogin();
  }
};
for (const [key, [icon, name]] of Object.entries(pages)) {
  const b = button(
    "",
    async () => {
      state.page = key;
      await render();
    },
    "nav",
  );
  b.id = "nav-" + key;
  b.title = name;
  b.append(el("small", icon), el("span", name, "navtext"));
  $("navigation").append(b);
}
$("refresh").onclick = () => render().catch((e) => toast(e.message));
async function render() {
  const id = ++state.renderId;
  const page = state.page;
  $("pageTitle").textContent = pages[page][1];
  $("pageDescription").textContent = pages[page][2];
  document
    .querySelectorAll(".nav")
    .forEach((n) => n.classList.toggle("active", n.id === "nav-" + page));
  const agents = await api("/api/agents");
  state.agents = agents;
  if (page !== state.page) return;
  const root = el("div");
  await {
    dashboard,
    agents: agentsPage,
    monitoring,
    ips,
    vps,
    sponsorship,
    integrations,
    incidents,
    settings,
  }[page](root);
  if (id === state.renderId) $("screen").replaceChildren(root);
}
function agentName(id) {
  return state.agents.find((a) => a.id === id)?.name || id.slice(0, 8);
}
async function dashboard(root) {
  const o = await api("/api/overview");
  const stats = el("div", "", "stats");
  for (const [label, val] of [
    ["Всего агентов", o.total],
    ["На связи", o.online],
    ["Нет связи", o.offline],
    ["Открытых инцидентов", o.incidents],
    ["Агентов с автопокупкой", o.paid_agents || 0],
  ]) {
    const c = el("div", "", "stat");
    c.append(el("div", label, "label"), el("strong", val));
    stats.append(c);
  }
  root.append(stats);
  const grid = el("div", "", "grid");
  const health = panel("Доступность прокси из России");
  health.body.append(
    el(
      "p",
      "Последние сохранённые проверки MTProto. TCP и передача данных до DC показаны отдельно в мониторинге; веб-адрес проверяется независимо.",
      "note",
    ),
  );
  const checks = (
    await Promise.all(
      state.agents
        .slice(0, 12)
        .map((a) => api("/api/agents/" + a.id + "/checks")),
    )
  )
    .flat()
    .filter((c) => !c.result.startsWith("sni_"))
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
  if (checks.length) {
    const ns = "http://www.w3.org/2000/svg",
      svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 600 160");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Результаты последних проверок");
    checks.slice(-60).forEach((c, i, all) => {
      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", String((i * 600) / all.length));
      rect.setAttribute("y", c.result === "reachable" ? "20" : "85");
      rect.setAttribute("width", String(Math.max(2, 580 / all.length)));
      rect.setAttribute("height", c.result === "reachable" ? "110" : "45");
      rect.setAttribute(
        "fill",
        c.result === "reachable"
          ? "#67dab5"
          : c.result === "suspected"
            ? "#fb9ba4"
            : "#566b8e",
      );
      const t = document.createElementNS(ns, "title");
      t.textContent =
        title(c.result) +
        " · " +
        new Date(c.created_at).toLocaleString("ru-RU");
      rect.append(t);
      svg.append(rect);
    });
    health.body.append(svg);
  } else
    health.body.append(
      el("p", "Проверок пока нет. Запустите их из карточки агента.", "muted"),
    );
  const cost = card(
    "Расходы под контролем",
    `В журнале AutoIP: ${(o.costs.recorded_cents / 100).toFixed(2)} EUR. Активных управляемых IP: ${o.costs.active_managed}.`,
  );
  cost.append(
    el(
      "p",
      "Счёт Cherry не сверялся. Неизвестная стоимость не считается нулевой.",
      "note",
    ),
    button("Открыть учёт адресов", async () => {
      state.page = "ips";
      await render();
    }),
  );
  grid.append(health.box, cost);
  root.append(grid);
  await agentsPage(root, true);
}
async function agentsPage(root, compact = false) {
  const box = panel("Подключённые агенты");
  if (!compact) {
    const filters = el("div", "", "filters"),
      input = el("input");
    input.placeholder = "Найти по имени, домену или региону";
    input.setAttribute("aria-label", "Поиск агентов");
    filters.append(input);
    box.body.append(filters);
    input.oninput = () => {
      for (const c of grid.children)
        c.hidden = !c.dataset.search.includes(input.value.toLowerCase());
    };
  }
  const grid = el("div", "", "grid");
  for (const a of state.agents) {
    const c = card(
      a.name,
      a.public_host
        ? `${a.public_host}:${a.proxy_port}`
        : "Ожидается обнаружение домена",
    );
    c.dataset.search = [a.name, a.public_host, a.configuration.region]
      .join(" ")
      .toLowerCase();
    c.append(
      el(
        "span",
        a.revoked ? "Доступ отозван" : a.online ? "На связи" : "Нет связи",
        "badge " + (a.online ? "online" : "offline"),
      ),
      kv("Telemt", title(a.facts.telemt_service)),
      kv("Floating IP", a.configuration.floating_ip),
      kv("DNS-запись", a.configuration.dns_record),
      kv("Исходный IP прокси", a.configuration.proxy_ip),
      kv("Автоматизация", a.paused ? "Пауза" : "Ручной режим"),
      button("Открыть агента", () => agentDetails(a)),
    );
    grid.append(c);
  }
  box.body.append(grid);
  if (!state.agents.length)
    box.body.append(
      el(
        "p",
        "Добавьте первый агент: Commander выдаст одноразовый код регистрации.",
        "empty",
      ),
    );
  root.append(box.box);
}
async function agentDetails(a) {
  modal(a.name, "Данные агента и действия Commander");
  const b = $("dialogBody");
  b.append(
    kv("Домен", a.public_host),
    kv("Management IP", a.configuration.management_ip),
    kv("Floating IP", a.configuration.floating_ip),
    kv("DNS-запись", a.configuration.dns_record),
    kv("Исходный IP прокси", a.configuration.proxy_ip),
    kv("ОС", a.facts.os),
    kv("Telemt", a.facts.telemt_version),
    kv(
      "Последний сигнал",
      a.last_seen ? new Date(a.last_seen).toLocaleString("ru-RU") : "нет",
    ),
  );
  const tools = el("div", "", "toolbar");
  tools.append(
    button("Проверить доступность", () => queueCheck(a.id)),
    button("Настройки и готовность", () => editAgent(a)),
    button("Проверить SNI через RIPE Atlas", () => sniDialog(a)),
    button(a.paused ? "Возобновить" : "Приостановить", async () => {
      await write(
        "/api/agents/" + a.id + "/pause",
        { paused: !a.paused },
        "PUT",
      );
      closeModal();
      await render();
    }),
    button("Предпроверка восстановления", () => recovery(a)),
    button("Переименовать", async () => {
      modal("Имя агента", "Меняется только имя в Commander");
      const f = field("Название", a.name);
      $("dialogBody").append(f.wrap);
      saveButton(async () => {
        await write("/api/agents/" + a.id, { name: f.input.value }, "PATCH");
        closeModal();
        await render();
      });
    }),
    button("Отозвать доступ", async () => {
      modal(
        "Отозвать доступ агента?",
        "Агент потеряет доступ к Commander. Telemt и сеть останутся под локальным управлением.",
      );
      saveButton(async () => {
        await write("/api/agents/" + a.id + "/revoke", {});
        closeModal();
        await render();
      }, "Отозвать");
    }),
  );
  b.append(tools);
  const readiness = await api("/api/agents/" + a.id + "/readiness");
  b.append(el("h3", "Готовность"));
  renderReadiness(b, readiness);
  const jobs = await api("/api/agents/" + a.id + "/jobs");
  b.append(el("h3", "Последние задания"));
  for (const j of jobs.slice(0, 5)) b.append(kv(j.kind, title(j.status)));
}
function saveButton(fn, label = "Сохранить") {
  $("action").hidden = false;
  $("action").textContent = label;
  $("action").onclick = async () => {
    $("action").disabled = true;
    try {
      await fn();
    } catch (e) {
      toast(e.message);
    } finally {
      $("action").disabled = false;
    }
  };
}
const readinessLabels = {
  network_helper: "Сетевой помощник ноды проверен",
  stable_public_host: "Клиентский домен или исходный IP согласованы с Telemt",
  reserve_selected: "Выбран управляемый резерв",
  reserve_unblocked: "Резерв отсутствует в истории блокировок",
  reserve_separate: "Резерв отличается от активного и основного IP",
  reserve_on_interface: "Agent видит резерв и основной IP на интерфейсах",
  agent_unpaused: "Управление агентом не приостановлено",
  tested_roundtrip: "Для этого резерва завершён DNS-пилот с возвратом",
  dns_scoped: "Поддомен входит в разрешённую DNS-зону",
  mtproto_checker: "Подключён MTProto Checker",
  mtproto: "Сохранён секрет MTProto",
  agent_online: "Агент на связи",
  public_host: "Определён домен",
  telemt_active: "Telemt активен",
  management_ip: "Указан Management IP",
  floating_ip: "Указан Floating IP",
  separate_management_ip: "Адреса разделены",
  cherry_project: "Выбран Cherry Project",
  cherry_server: "Выбран Cherry Server",
  dns_zone: "Указана DNS-зона",
  budget: "Задан лимит расходов",
  cherry: "Проверен доступ Cherry",
  dynadot: "Проверен доступ Dynadot",
};
function renderReadiness(root, data) {
  const list = el("ul", "", "list");
  for (const [key, ok] of Object.entries(data.checks))
    list.append(
      el(
        "li",
        (ok ? "✓ " : "○ ") + (readinessLabels[key] || key),
        ok ? "ok" : "warn",
      ),
    );
  root.append(list);
  for (const blocker of data.live_blockers)
    root.append(el("p", blocker, "note"));
}
async function editAgent(a) {
  const [config, ints] = await Promise.all([
    api("/api/agents/" + a.id + "/configuration"),
    api("/api/integrations"),
  ]);
  modal(
    "Настройка: " + a.name,
    "Ответы сохраняются отдельно для этого агента. Ключи выбираются из общих интеграций.",
  );
  const schema = [
    ["provider", "Провайдер"],
    ["region", "Регион"],
    ["sni_domain", "SNI-домен Telemt"],
    ["management_ip", "Постоянный Management IPv4"],
    ["proxy_ip", "Исходный IPv4 прокси (до покупки Floating IP)"],
    ["floating_ip", "Клиентский Floating IPv4"],
    ["cherry_integration_id", "Интеграция Cherry"],
    ["cherry_project_id", "Cherry Project ID"],
    ["cherry_server_id", "Cherry Server ID"],
    ["dns_integration_id", "Интеграция Dynadot"],
    ["dns_zone", "DNS-зона — только vetka.rest"],
    ["dns_record", "Поддомен vetka.rest, например lt.vetka.rest"],
    ["telethon_integration_id", "Telegram-аккаунт Telethon"],
    ["vps_profile_integration_id", "Профиль Telemt для новых VPS"],
    ["mtproto_integration_id", "Секрет MTProto (из хранилища)"],
    ["checker_integration_id", "MTProto Checker (только MTProto)"],
    ["mtproto_secret_format", "Формат секрета MTProto: dd или ee"],
    ["web_proxy_host", "Веб-прокси: HTTPS-домен"],
    ["web_proxy_port", "Веб-прокси: HTTPS-порт"],
    ["ripe_atlas_integration_id", "RIPE Atlas для дополнительных проверок"],
    ["sponsor_channel", "Публичный спонсорский канал"],
    ["monthly_budget_cents", "Лимит EUR в месяц, в центах"],
    ["max_candidates_per_incident", "Кандидатов на инцидент"],
    ["max_ips_per_day", "Новых IP в день"],
    ["max_billed_ips", "Одновременно оплачиваемых IP"],
    ["notes", "Примечание без секретов"],
  ];
  const inputs = {};
  for (const [key, label] of schema) {
    let f;
    if (key.endsWith("integration_id") || key === "provider") {
      const wrap = el("div", "", "field"),
        select = el("select");
      wrap.append(el("label", label));
      select.setAttribute("aria-label", label);
      const opts =
        key === "provider"
          ? [
              ["cherry", "Cherry Servers"],
              ["nodehost", "Node Host — замена VPS через Telegram"],
              ["other", "Другой провайдер"],
            ]
          : [
              ["", "Не выбрано"],
              ...ints
                .filter(
                  (i) =>
                    i.kind ===
                    (key.startsWith("vps_profile")
                      ? "telemt_profile"
                      : key.startsWith("cherry")
                      ? "cherry"
                      : key.startsWith("telethon")
                        ? "telethon"
                        : key.startsWith("mtproto")
                          ? "mtproto"
                          : key.startsWith("checker")
                            ? "mtproto_checker"
                            : key.startsWith("ripe_atlas")
                              ? "ripe_atlas"
                              : "dynadot"),
                )
                .map((i) => [i.id, i.name + " · " + title(i.status)]),
            ];
      for (const [v, l] of opts) {
        const o = el("option", l);
        o.value = v;
        select.append(o);
      }
      select.value = config[key] || "";
      wrap.append(select);
      f = { wrap, input: select };
    } else
      f = field(
        label,
        config[key] ?? "",
        key.startsWith("max_") ||
          key === "monthly_budget_cents" ||
          key.endsWith("_port")
          ? "number"
          : "text",
      );
    inputs[key] = f.input;
    $("dialogBody").append(f.wrap);
  }
  if (!config.dns_record) inputs.dns_record.value = a.public_host || "";
  if (!config.sni_domain) inputs.sni_domain.value = a.facts.tls_domain || "";
  const ci = button("Получить проекты из Cherry", async () => {
    const id = inputs.cherry_integration_id.value;
    if (!id) throw Error("Выберите интеграцию Cherry");
    const data = await api("/api/integrations/" + id + "/inventory");
    const pre = el("pre", JSON.stringify(data, null, 2));
    $("dialogBody").append(pre);
  });
  $("dialogBody").append(ci);
  saveButton(async () => {
    const payload = { ...config };
    for (const [key] of schema)
      payload[key] =
        key.startsWith("max_") ||
        key === "monthly_budget_cents" ||
        key.endsWith("_port")
          ? Number(inputs[key].value)
          : inputs[key].value.trim();
    await write("/api/agents/" + a.id + "/configuration", payload, "PUT");
    toast("Настройки сохранены");
    closeModal();
    await render();
  });
}
async function queueCheck(id) {
  const t = await write("/api/agents/" + id + "/check", {});
  toast("Проверка в очереди. Результат появится в разделе «Мониторинг».");
  return t;
}
async function recovery(a) {
  modal(
    "Восстановление: " + a.name,
    "Предварительная проверка настроек. Покупки IP и изменения инфраструктуры заблокированы.",
  );
  saveButton(async () => {
    const r = await write("/api/agents/" + a.id + "/recovery-plan", {
      idempotency_key: crypto.randomUUID(),
    });
    $("dialogBody").replaceChildren(el("p", title(r.status), "warn"));
    for (const stage of r.stages) {
      $("dialogBody").append(kv(title(stage.stage), title(stage.status)));
      if (stage.readiness) renderReadiness($("dialogBody"), stage.readiness);
      if (stage.reason) $("dialogBody").append(el("p", stage.reason, "note"));
    }
    $("action").hidden = true;
  }, "Выполнить предпроверку");
}
async function monitoring(root) {
  root.append(
    card(
      "Основные источники · раз в 5 минут по умолчанию",
      "Check-Host проверяет TCP MTProto и HTTPS веб-адреса; MTProto Checker проверяет только MTProto-хендшейк и данные до DC. RIPE Atlas — дополнительная TLS/SNI-проверка при недоступном или неопределённом ответе основного источника.",
    ),
  );
  const coverage = panel("Дополнительно · RIPE Atlas: покрытие проверок");
  const details = el("div");
  coverage.body.append(
    el(
      "p",
      "Москва, Санкт-Петербург, Красноярск, Хабаровск; Мегафон, Билайн, МТС, Ростелеком. Контроль: Германия, Нидерланды, Финляндия. География зондов приблизительная; наличие зондов проверяется перед запуском.",
      "note",
    ),
    button("Показать актуальное покрытие", async () => {
      details.replaceChildren(el("p", "Загружаем список зондов…"));
      try {
        renderAtlasCoverage(details, await api("/api/atlas/probe-plan"));
      } catch (error) {
        details.replaceChildren(el("p", error.message, "warn"));
      }
    }),
    details,
  );
  root.append(coverage.box);
  for (const a of state.agents) {
    const p = panel(a.name + " · " + (a.public_host || "домен не определён"));
    p.body.append(button("Новая проверка из РФ", () => queueCheck(a.id)));
    const checks = await api("/api/agents/" + a.id + "/checks");
    const list = el("ul", "", "list");
    for (const c of checks.slice(0, 15)) {
      const item = el("li");
      item.append(
        el("strong", title(c.result)),
        el("div", new Date(c.created_at).toLocaleString("ru-RU"), "muted"),
      );
      if (c.details.mtproto_status)
        item.append(
          kv("MTProto Checker", checkerLabel(c.details.mtproto_status)),
        );
      if (c.details.web_endpoint)
        item.append(
          kv(
            "Веб-адрес HTTPS (данные прокси не проверены)",
            `${c.details.web_endpoint.target}:${c.details.web_endpoint.port} · ${title(c.details.web_endpoint.status)}`,
          ),
        );
      for (const report of c.details.reports || [])
        if (report.error)
          item.append(
            el("p", `${report.source}: ${providerError(report.error)}`, "warn"),
          );
      if (
        c.details.atlas_fallback &&
        c.details.atlas_fallback.status !== "standby"
      )
        item.append(
          kv(
            "RIPE Atlas · резерв",
            fallbackLabel(c.details.atlas_fallback.status),
          ),
        );
      for (const o of c.details.observations || [])
        item.append(
          el(
            "div",
            `${o.source} · ${o.scope === "web-endpoint" ? "Веб HTTPS" : o.protocol === "mtproto" ? "MTProto" : "MTProto TCP"} · ${o.country === "EXTERNAL" ? "Внешняя точка" : o.country} · ${o.asn || "ASN неизвестен"} · ${o.target || ""} → ${title(o.state)}${o.protocol === "mtproto" ? ` · хендшейк: ${boolLabel(o.handshake)} · данные: ${boolLabel(o.data)} · RTT: ${o.latency_ms ?? "—"} мс` : ""}`,
            "mono",
          ),
        );
      if (c.details.comparison)
        item.append(el("p", atlasComparison(c.details.comparison), "note"));
      for (const region of c.details.regions || [])
        item.append(
          el(
            "div",
            `${region.country} · ${region.city || region.name || ""} · ${region.provider || ""}: ${title(region.outcome)} (${region.successes}/${region.responded})`,
          ),
        );
      list.append(item);
    }
    p.body.append(list);
    if (!checks.length)
      p.body.append(el("p", "Сохранённых проверок нет", "muted"));
    root.append(p.box);
  }
  if (!state.agents.length)
    root.append(el("p", "Сначала подключите агент.", "empty"));
}
async function ips(root) {
  const [items, cost] = await Promise.all([
    api("/api/floating-ips"),
    api("/api/costs"),
  ]);
  root.append(
    card(
      "Учёт расходов",
      `${(cost.recorded_cents / 100).toFixed(2)} EUR · неизвестная стоимость у ${cost.unknown_cost_resources} ресурсов. Это данные журнала AutoIP, внешний счёт не сверялся.`,
    ),
  );
  const p = panel("История Floating IP");
  for (const i of items)
    p.body.append(
      kv(
        `${i.ipv4} · ${agentName(i.agent_id)}`,
        `${i.status} · ${i.managed ? "управляется AutoIP" : "только наблюдение"}`,
      ),
    );
  if (!items.length)
    p.body.append(
      el(
        "p",
        "Ресурсы ещё не импортированы. AutoIP не выполнял покупок.",
        "muted",
      ),
    );
  root.append(p.box);
}
async function sponsorship(root) {
  const items = await api("/api/sponsorship");
  const grid = el("div", "", "grid");
  for (const a of state.agents) {
    const s = items.find((i) => i.agent_id === a.id);
    const c = card(a.name, s ? title(s.status) : "Не настроено");
    c.append(
      kv("Канал", a.configuration.sponsor_channel),
      el(
        "p",
        "Авторизация отдельного Telegram-аккаунта и проверка диалога MTProxybot обязательны до реальной регистрации.",
        "note",
      ),
      button("Настройки агента", () => editAgent(a)),
    );
    grid.append(c);
  }
  root.append(grid);
  if (!state.agents.length)
    root.append(el("p", "Сначала подключите агент.", "empty"));
}
async function integrations(root) {
  const [items, settings] = await Promise.all([
    api("/api/integrations"),
    api("/api/settings"),
  ]);
  const top = panel("Подключения Commander");
  top.body.append(
    el(
      "p",
      settings.vault_ready
        ? "Хранилище открыто. Секреты шифруются, API возвращает только статус."
        : "Сначала создайте мастер-ключ локальной командой. Инструкция находится в документации развёртывания.",
      settings.vault_ready ? "ok" : "warn",
    ),
    button("+ Подключить интеграцию", () => integrationForm()),
  );
  root.append(top.box);
  const grid = el("div", "", "grid");
  for (const i of items) {
    const c = card(i.name, i.kind + " · " + title(i.status));
    c.append(
      button("Проверить соединение", async () => {
        toast("Проверка соединения…");
        const result = await write("/api/integrations/" + i.id + "/test", {});
        toast(result.message);
        await render();
      }),
    );
    if (i.kind === "cherry")
      c.append(
        button("Показать проекты", async () => {
          const d = await api("/api/integrations/" + i.id + "/inventory");
          modal(
            "Проекты Cherry",
            "Только чтение. Существующие ресурсы не изменяются.",
          );
          for (const p of d.projects) $("dialogBody").append(kv(p.name, p.id));
        }),
      );
    if (i.kind === "dynadot")
      c.append(
        button("Показать домены", async () => {
          const data = await api("/api/integrations/" + i.id + "/dns-domains");
          modal("Домены Dynadot", "Только чтение. Записи DNS не изменяются.");
          for (const domain of data.domains)
            $("dialogBody").append(kv(domain.domain_name, domain.status));
          if (!data.domains.length)
            $("dialogBody").append(el("p", "Доменов на этой странице нет."));
        }),
      );
    if (i.kind === "telethon")
      c.append(
        button("Как завершить вход", async () => {
          modal(
            "Локальная авторизация Telegram",
            "Выполните команду на Commander. Уже сохранённые API-данные повторно вводить не нужно. Код и пароль 2FA вводятся скрыто в локальном терминале.",
          );
          $("dialogBody").append(
            el(
              "pre",
              "cd /opt/autoip\ndocker compose run --rm -it migrate python -m commander.manage telethon-login --integration-id " +
                i.id,
            ),
          );
        }),
      );
    grid.append(c);
  }
  root.append(grid);
}
function integrationForm() {
  modal(
    "Подключить интеграцию",
    "Ключи передаются только по HTTPS или через localhost и никогда не возвращаются в ответе. Можно использовать локальную команду настройки.",
  );
  const name = field("Название");
  $("dialogBody").append(name.wrap);
  const wrapper = el("div", "", "field"),
    select = el("select");
  select.setAttribute("aria-label", "Сервис");
  for (const [v, t] of [
    ["cherry", "Cherry Servers"],
    ["dynadot", "Dynadot"],
    ["telegram_bot", "Telegram-бот"],
    ["telethon", "Telegram-аккаунт Telethon"],
    ["ripe_atlas", "RIPE Atlas (дополнительный источник)"],
    ["mtproto_checker", "MTProto Checker"],
    ["mtproto", "MTProto secret"],
    ["telemt_profile", "Профиль польского Telemt (секрет и ad_tag)"],
  ]) {
    const o = el("option", t);
    o.value = v;
    select.append(o);
  }
  wrapper.append(el("label", "Сервис"), select);
  $("dialogBody").append(wrapper);
  const secretsRoot = el("div");
  $("dialogBody").append(secretsRoot);
  let inputs = {};
  const rebuild = () => {
    secretsRoot.replaceChildren();
    inputs = {};
    const keys = {
      cherry: ["api_key"],
      dynadot: ["api_key", "api_secret"],
      telegram_bot: ["token"],
      telethon: ["api_id", "api_hash", "phone", "session"],
      ripe_atlas: ["api_key"],
      mtproto_checker: ["api_key"],
      mtproto: ["secret"],
      telemt_profile: ["domain", "secret", "ad_tag"],
    }[select.value];
    for (const key of keys) {
      const f = field(key, "", "password");
      f.input.autocomplete = "new-password";
      inputs[key] = f.input;
      secretsRoot.append(f.wrap);
    }
  };
  select.onchange = rebuild;
  rebuild();
  saveButton(async () => {
    const credentials = {};
    for (const [k, i] of Object.entries(inputs)) credentials[k] = i.value;
    await write("/api/integrations", {
      name: name.input.value,
      kind: select.value,
      credentials,
    });
    for (const i of Object.values(inputs)) i.value = "";
    closeModal();
    toast("Ключи зашифрованы и сохранены");
    await render();
  });
}
async function incidents(root) {
  const [items, history, recoveries] = await Promise.all([
    api("/api/incidents"),
    api("/api/audit"),
    api("/api/recoveries"),
  ]);
  for (const i of items) {
    const p = panel(agentName(i.agent_id) + " · " + title(i.status));
    p.body.append(
      kv("Начало", new Date(i.created_at).toLocaleString("ru-RU")),
      kv("IP", i.observed_ip),
      kv("Отложенных проверок", i.rechecks),
    );
    if (
      ["WAITING_CONFIRMATION", "RECHECKING", "BLOCK_CONFIRMED"].includes(
        i.status,
      )
    ) {
      const tools = el("div", "", "toolbar");
      for (const [key, label] of [
        ["confirm", "Подтвердить блокировку"],
        ["working", "Прокси работает"],
        ["recheck", "Повторить проверку"],
        ["hold", "Отложить"],
      ])
        tools.append(
          button(label, async () => {
            await write("/api/incidents/" + i.id + "/action", { action: key });
            await render();
          }),
        );
      p.body.append(tools);
    }
    root.append(p.box);
  }
  const p = panel("Журнал операций");
  for (const e of history)
    p.body.append(
      kv(
        new Date(e.created_at).toLocaleString("ru-RU"),
        `${e.actor} · ${e.action}`,
      ),
    );
  if (!history.length) p.body.append(el("p", "История пуста", "muted"));
  root.append(p.box);
  const r = panel("Проверки восстановления");
  for (const e of recoveries)
    r.body.append(kv(agentName(e.agent_id), title(e.status)));
  if (!recoveries.length) r.body.append(el("p", "Операций нет", "muted"));
  root.append(r.box);
}
async function settings(root) {
  const s = await api("/api/settings");
  const p = panel("Настройки Commander");
  p.body.append(
    kv("Адрес панели", s.public_url || "Не задан"),
    kv("Хранилище ключей", s.vault_ready ? "Настроено" : "Нужна инициализация"),
    kv("2FA", s.totp_enabled ? "Включена" : "Не настроена"),
    kv("Период мониторинга", s.monitor_interval_seconds + " сек."),
    kv("Плановые проверки", s.monitor_enabled ? "Включены" : "Выключены"),
    kv("Telegram User ID", s.telegram_admin_ids.join(", ") || "Не заданы"),
    kv("Платные операции", "Заблокированы"),
    el(
      "p",
      "Адрес панели и мастер-ключ задаются локально. Период мониторинга, Telegram User ID и общие лимиты сохраняются в БД. Индивидуальные лимиты и пауза доступны в настройках агента.",
      "note",
    ),
  );
  const form = el("div", "", "grid");
  const period = field(
    "Интервал проверок, сек.",
    s.monitor_interval_seconds,
    "number",
  );
  const admins = field(
    "Telegram User ID через запятую",
    s.telegram_admin_ids.join(", "),
  );
  const budget = field(
    "Общий месячный лимит, EUR в центах",
    s.monthly_budget_cents,
    "number",
  );
  const monitoring = field("Включить плановые проверки", "", "checkbox");
  const dnsZone = field("DNS-зона для новых агентов — только vetka.rest", s.default_dns_zone || "");
  const atlasFallback = field(
    "Разрешить резервный RIPE Atlas и расход его кредитов (не чаще раза в час на агента)",
    "",
    "checkbox",
  );
  atlasFallback.input.checked = s.atlas_fallback_enabled;
  monitoring.input.checked = s.monitor_enabled;
  form.append(
    period.wrap,
    admins.wrap,
    budget.wrap,
    monitoring.wrap,
    dnsZone.wrap,
    atlasFallback.wrap,
  );
  p.body.append(
    el(
      "p",
      "DNS-зона подставляется при регистрации нового агента. Поддомен задаётся отдельно в его настройках. Сохранение здесь не изменяет DNS-записи или настройки существующих агентов.",
      "note",
    ),
  );
  p.body.append(
    form,
    button("Сохранить настройки", async () => {
      const payload = {
        default_dns_zone: dnsZone.input.value,
        atlas_fallback_enabled: atlasFallback.input.checked,
        monitor_enabled: monitoring.input.checked,
        monitor_interval_seconds: Number(period.input.value),
        telegram_admin_ids: admins.input.value
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean)
          .map(Number),
        monthly_budget_cents: Number(budget.input.value),
        account_budget_cents: s.account_budget_cents,
      };
      await write("/api/settings", payload, "PUT");
      toast("Настройки сохранены в БД");
      await render();
    }),
  );
  root.append(p.box);
  root.append(
    card(
      "Первоначальная настройка",
      "1. Инициализируйте хранилище ключей. 2. Подключите и проверьте интеграции. 3. Добавьте агента и заполните обнаруженные пробелы. 4. Проверьте мониторинг. Реальные изменения согласуются отдельно.",
    ),
  );
}
function shellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}
$("add").onclick = () => {
  modal(
    "Новый агент",
    "Создайте одноразовый код. Он действует 15 минут и будет показан только здесь.",
  );
  const f = field("Название агента");
  $("dialogBody").append(f.wrap);
  saveButton(async () => {
    const t = await write("/api/enrollments", { name: f.input.value });
    const url = t.commander_url || location.origin;
    const command =
      "git clone --branch " +
      shellQuote(t.agent_git_ref || "main") +
      " https://github.com/Daniil-GR/AutoIP.git /opt/AutoIP\nsudo bash /opt/AutoIP/agent/install.sh --with-config-reader\n# Настройте AUTOIP_COMMANDER_URL в /etc/autoip-agent/agent.env\n# Введите одноразовый код в скрытом запросе, не в командной строке:\nsudo /opt/AutoIP/.venv/bin/python -m agent.main enroll-local " +
      shellQuote(url) +
      "\nsudo systemctl enable --now autoip-agent";
    $("dialogBody").replaceChildren(
      el("p", "Одноразовый код (сохраните до закрытия окна):"),
      el("pre", t.token),
      el("p", "Выполняется на новом сервере Agent после проверки установщика:"),
      el("pre", command),
    );
    const status = el("p", "Ожидаем подключения агента…", "warn");
    $("dialogBody").append(
      status,
      button("Скопировать код", async () => {
        await navigator.clipboard.writeText(t.token);
        toast("Код скопирован");
      }),
    );
    $("action").hidden = true;
    state.ticketTimer = setInterval(async () => {
      try {
        const result = await api("/api/enrollments/" + t.id);
        if (result.used) {
          clearInterval(state.ticketTimer);
          status.textContent =
            "Агент подключился. Откройте его настройки и проверьте готовность.";
          status.className = "ok";
          await render();
        } else if (result.expired) {
          clearInterval(state.ticketTimer);
          status.textContent = "Код истёк. Создайте новый.";
        }
      } catch (e) {
        clearInterval(state.ticketTimer);
        status.textContent = e.message;
      }
    }, 4000);
  }, "Создать код");
};
(async () => {
  try {
    const s = await api("/api/session");
    state.csrf = s.csrf;
    showWorkspace();
    await render();
  } catch {
    showLogin();
  }
})();

async function sniDialog(a) {
  const integrations = (await api("/api/integrations")).filter(
    (i) => i.kind === "ripe_atlas",
  );
  modal(
    "RIPE Atlas: SNI-домен",
    "Измерение использует кредиты RIPE Atlas. Один IPv4 прокси с заданным SNI проверяется из РФ, Германии, Нидерландов и Финляндии. Это диагностика TLS, не проверка MTProto и не команда покупки IP.",
  );
  if (!integrations.length) {
    $("dialogBody").append(
      el("p", "Сначала добавьте интеграцию RIPE Atlas в защищённом разделе."),
    );
    return;
  }
  const select = el("select");
  select.setAttribute("aria-label", "Интеграция RIPE Atlas");
  for (const i of integrations) {
    const o = el("option", i.name);
    o.value = i.id;
    select.append(o);
  }
  $("dialogBody").append(
    kv("SNI-домен", a.configuration.sni_domain || a.facts.tls_domain),
    kv(
      "IPv4 для всех стран",
      a.configuration.floating_ip || a.configuration.proxy_ip || "Не указан",
    ),
    select,
    button("Показать актуальное покрытие", async () => {
      const details = el("div");
      $("dialogBody").append(details);
      renderAtlasCoverage(details, await api("/api/atlas/probe-plan"));
    }),
  );
  saveButton(async () => {
    const task = await write("/api/agents/" + a.id + "/sni-check", {
      integration_id: select.value,
      approve_atlas_credits: true,
    });
    toast("Измерение поставлено в очередь: " + task.status);
    closeModal();
  }, "Подтвердить расход кредитов и проверить");
}

function atlasComparison(value) {
  return (
    {
      suspected_ru_filtering:
        "Возможна фильтрация в РФ: зарубежный контроль доступен. Нужны повторные независимые проверки.",
      ru_accessible: "SNI доступен на выбранных российских зондах.",
      inconclusive:
        "Недостаточно согласованных данных для вывода о фильтрации в РФ.",
    }[value] || value
  );
}
function renderAtlasCoverage(root, plan) {
  root.replaceChildren(
    el(
      "p",
      `Выбрано зондов: ${plan.probes.length}. Радиус поиска около города: ${plan.radius_km} км.`,
    ),
  );
  const table = el("table");
  const head = el("tr");
  for (const name of ["Страна / город", "Провайдер", "Зондов"])
    head.append(el("th", name));
  table.append(head);
  for (const group of plan.coverage) {
    const row = el("tr");
    row.append(
      el("td", group.city || group.name || group.country),
      el("td", group.provider || "Разные ASN"),
      el("td", group.probes ? String(group.probes) : "Нет доступных"),
    );
    table.append(row);
  }
  root.append(table, el("p", plan.note, "note"));
}

function checkerLabel(status) {
  return (
    {
      OK: "Работает: данные проходят из РФ и снаружи",
      DATA_CUT: "Из РФ хендшейк проходит, данные режутся",
      RKN_BLOCK: "Из РФ не проходит TCP/хендшейк, снаружи работает",
      MT_DEAD: "Снаружи TCP открыт, данные до DC не проходят",
      DOWN: "Недоступен из обеих точек",
      UNKNOWN: "Недостаточно данных",
    }[status] || status
  );
}
function fallbackLabel(value) {
  return (
    {
      queued: "Дополнительная проверка поставлена в очередь",
      running: "Дополнительная проверка уже выполняется",
      submission_uncertain:
        "Нужна ручная сверка RIPE Atlas; повторное измерение не создаётся",
      not_configured: "Не настроена интеграция RIPE Atlas у агента",
      cooldown: "Не запускаем повторно чаще раза в час",
      disabled: "Автоматический резерв отключён",
      paused: "Автоматизация приостановлена",
      configuration_error: "Проверьте настройки RIPE Atlas и SNI",
    }[value] || value
  );
}
function providerError(value) {
  return (
    {
      not_configured: "Не выбраны ключ сервиса и секрет MTProto",
      configuration_error: "Проверьте настройки источника",
      rate_limited: "Сервис ограничил частоту запросов",
      local_rate_limit: "Общий лимит ключа, запрос отложен",
      credentials_rejected: "Сервис отклонил ключ",
      service_unavailable: "Сервис не ответил",
      malformed_response: "Неизвестный формат ответа",
      target_mismatch: "Ответ относится к другой цели",
      stale_response: "Ответ устарел",
      inconsistent_response: "Статус противоречит данным ответа",
    }[value] || "Источник недоступен или вернул неполные данные"
  );
}

function boolLabel(value) {
  return value === true ? "да" : value === false ? "нет" : "нет данных";
}

async function vps(root) {
  const data = await api('/api/nodehost/resources');
  root.append(el('p', 'Замена VPS через Telegram готовится к пилоту. Автопокупки Node Host выключены. Доступы зашифрованы; пароли сюда не выводятся.', 'notice'));
  root.append(button('Подготовить заказ на сутки', async () => {
    const integrations = (await api('/api/integrations')).filter(i => i.kind === 'telethon');
    modal('Предложение Node Host', 'Польша, Ubuntu 24.04, 1 CPU / 3 ГБ / 25 ГБ. Сейчас будет открыт только предварительный расчёт, без оплаты. Не работайте параллельно с меню хостера.');
    const select = el('select');
    for (const i of integrations) {const o = el('option', i.name); o.value = i.id; select.append(o);}
    $('dialogBody').append(select);
    saveButton(async () => {
      const q = await write('/api/nodehost/quote', {integration_id:select.value});
      modal('Подтвердить покупку VPS', 'Сутки: ' + q.price_rub + ' ₽ (' + q.price_usd + ' $ по данным бота). Это платная покупка одного VPS. Установка и изменение DNS автоматически не запускаются.');
      const operationId = crypto.randomUUID();
      saveButton(async () => {
        const r = await write('/api/nodehost/order', {quote_id:q.quote_id, operation_id:operationId, approved:true});
        closeModal(); toast(r.status === 'ALLOCATED' ? 'VPS приобретён; доступы зашифрованы' : 'Исход заказа требует сверки. Повторную покупку не запускайте.');
        await render();
      }, 'Подтверждаю покупку на сутки');
    }, 'Рассчитать без оплаты');
  }));
  root.append(button('Найти VPS в истории Telegram', async () => {
    const integrations = (await api('/api/integrations')).filter(i => i.kind === 'telethon');
    modal('Импорт польских VPS', 'Укажите IP уже купленных серверов. Команда читает историю nodehost_bot и сохраняет найденные доступы зашифрованно. Покупок и установки нет.');
    const wrap = el('div', '', 'field'), select = el('select');
    for (const i of integrations) {const option = el('option', i.name); option.value = i.id; select.append(option);}
    wrap.append(el('label', 'Telegram-аккаунт'), select);
    const addresses = field('IPv4 через пробел');
    $('dialogBody').append(wrap, addresses.wrap);
    saveButton(async () => {
      const result = await write('/api/nodehost/discover', {integration_id: select.value, addresses: addresses.input.value.trim().split(/\s+/)});
      if (result.missing.length) toast('Не найдены в истории: ' + result.missing.join(', '));
      closeModal(); await render();
    });
  }));
  if (!data.resources.length) root.append(el('p', 'Пока нет импортированных VPS.'));
  for (const item of data.resources) {
    const card = el('div', '', 'card');
    card.append(el('h3', item.ipv4), el('p', 'Статус: ' + (item.status === 'discovered' ? 'Найден в истории; не принят под автоматическое управление' : title(item.status))));
    card.append(button('Проверить SSH из РФ и трёх стран', async () => {
      const r = await write('/api/nodehost/resources/' + item.source_message_id + '/preflight', {});
      const labels = {BOOT_WAIT:'Ожидается загрузка сервера', REJECT_HISTORY:'IP в истории блокировок', REJECT_RU_FILTER:'Повторные проверки: SSH недоступен из РФ', RECHECK:'Данных недостаточно — повторите проверку', SSH_READY:'SSH доступен. MTProto ещё не проверен'};
      toast(labels[r.status] || r.status);
    }));
    card.append(button('Проверить ОС и Telemt', async () => {
      const r = await write('/api/nodehost/resources/' + item.source_message_id + '/inspect', {});
      toast(r.os + ' ' + r.version + ' · Telemt: ' + (r.active ? 'работает' : r.installed ? 'установлен' : 'не установлен'));
    }));
    root.append(card);
  }
}
