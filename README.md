# AutoIP — Commander + Multi-Agent

A central control plane for multiple Linux servers running Telemt (MTProto proxy), with a Russian-language web panel and outbound-polling agents.

**Status: runnable early MVP (v0.1), monitoring-only. NOT production-ready.** No automatic Floating IP purchases, DNS changes, block decisions, Telegram sponsorship or automatic recovery. Code intentionally cannot trigger billable IP operations.

## Implemented

- Commander: FastAPI, PostgreSQL (Docker Compose), Basic-auth protected web panel and dashboard.
- One-time enrollment tokens (15 minutes), unique machine identity, hashed agent credentials, outbound HTTPS authentication, heartbeat and detected Telemt information.
- Agent polling and allowlisted jobs: status; optional disabled-by-default local ad-tag write helper.
- Read-only Check-Host TCP measurements, recording raw results with an UNKNOWN state rather than automated block judgement.
- Recent jobs and checks for each agent; pause and manual check API.

## Repository layout

- commander/ — API, database, monitoring, panel.
- agent/ — lightweight outbound agent and restricted Telemt config helper.
- docs/ — setup, architecture, security and remaining work.
- tests/ — regression tests.

## Start Commander

1. Install Docker Engine and the Compose plugin.
2. Clone to Commander VPS.
3. Copy .env.example to .env.
4. Set unique strong AUTOIP_ADMIN_PASSWORD and POSTGRES_PASSWORD. No real credentials in Git.
5. Run: docker compose up -d --build
6. Local port 127.0.0.1:8080 is loopback-only. Put HTTPS reverse proxy in front with rate limiting.
7. Open HTTPS panel and sign in. Monitoring defaults to disabled until manually enabled.

HTTP Basic is an MVP mechanism, not final account management.

## Add agent

1. Select Добавить агента, enter name, create one-time key.
2. On a Telemt VPS clone this repository to /opt/AutoIP and follow docs/agent-installation.md.
3. Configure HTTPS Commander URL; run enrollment as agent service user.
4. Start systemd agent service; it connects outward every 20 seconds.

Do not use replaceable Floating IP for management.

## Safety

- Do not install on production before evaluating access, networking and Telemt file permissions.
- Automatic IP operations are not implemented. There is no live Cherry Servers or Dynadot workflow yet.
- Telemt helper only supports apply-ad-tag and is never automatically granted sudo privileges.
- No secrets in Git. This repository currently may be public.
- Check-Host TCP alone cannot confirm MTProto functionality or censorship.
- Backend create_all is an MVP shortcut. Database migrations needed before upgrades.
- See docs/roadmap.md.

## Tests

Install Python requirements and pytest, then run pytest -q. Set AUTOIP_ADMIN_PASSWORD to a test password with at least 12 characters.

## License

No license is granted until repository owner explicitly chooses one.
