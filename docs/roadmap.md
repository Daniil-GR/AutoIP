# Roadmap — not yet implemented

This repository is an early MVP, NOT the completed AutoIP platform.

1. Harden commander authentication: reverse proxy TLS, rate limits, audited logins, 2FA, roles, CSRF-safe sessions.
2. Harden agents: approval, revocation, key rotation, durable command deduplication, typed events, strict privileges.
3. Monitoring: parse Check-Host results into tri-state, connect second independent provider, actual RU MTProto probes.
4. Incidents: manual approve/deny, delayed rechecks at 15/20/25 min and Telegram inline callbacks.
5. Cherry integration: inventory, IP acquisition, assignment, source-bound limits, budget, reconciliation; never delete unmanaged IP.
6. Agent network helper: allowlisted address operations with route safety and timed rollback.
7. DNS provider: authoritative NS validation, non-destructive per-record updates and TTL verification.
8. Sponsorship: separate Telethon session to @MTProxybot, ordered per-account dialogs, tag application/verification.
9. Fully repeatable recovery integration tests and dry-run simulation across agents.
10. Database migrations, backup/restore, metrics, CI, docs and staging before production enablement.

Never enable live purchases as part of this MVP.
