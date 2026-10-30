# Instructions for Codex working on AutoIP

Read README.md and docs/TECHNICAL_SPEC_RU.md before changing code.

Treat this as a live-infrastructure safety-critical management application. Existing AutoIP v0.1 is an early monitoring MVP. Do not claim paid IP recovery, DNS switching, or sponsorship are implemented until truly tested.

## Process

1. Inspect repo and current CI results.
2. Choose the smallest end-to-end vertical milestone from the technical spec.
3. Preserve existing API and user data; add Alembic migration for schema changes.
4. Write tests with mocked Cherry, DNS and Telegram APIs; run pytest and Python compilation.
5. Keep all paid/destructive actions gated behind explicit opt-in and budget/safety checks.
6. Document what remains and do not enable production by default.
7. Never commit secrets or sessions. Do not ask for them in GitHub issues or README.
8. Never change real servers, active IPs, public DNS, or Telemt config without explicit permission from the owner.
9. Coordinate safe agent updates so management SSH and primary IP always survive.
10. UI labels and end-user notices should default to Russian.

## Priority

Finish secure onboarding and persistent per-agent configuration first, then monitoring/incident state machine. Only then begin isolated, audited provider mutation adapters and sponsorship bot behavior.

## Owner's DNS boundary

AutoIP may manage only subdomains of `vetka.rest`. The first node uses
`lt.vetka.rest`. Never use or change other domains in the Dynadot account;
do not enumerate account-wide domains. The apex record of `vetka.rest` is
outside mutation scope. Preserve all records except the explicitly selected
node's A record. Enforce `commander/dns_scope.py` at every future DNS mutation
boundary; settings in the web panel must not expand this scope. DNS writes
still require the owner's separate approval and a verified safe adapter.

## Sponsorship feature frozen by owner

As of 2026-10-30, development and activation of automatic MTProxybot registration
and ad_tag replacement are frozen. IP recovery must preserve the current node's
ad_tag and must not require a Telegram registration step. Do not change the live
tag, registration, or Telethon session. Agent tag-write permissions remain closed.
Retain existing adapter code for reference; resume this feature only at the owner's
explicit request. The owner chose stable hostname/port plus tag reuse as the
operating approach; cross-IP sponsorship behavior still needs a real approved test.

## Recovery policy agreed on 2026-10-30

Read docs/recovery-policy.md when implementing recovery. The owner rejected
AutoIP's proposed fixed replacement-count and monthly-budget caps. Do not
reintroduce them as requirements. Preserve cost accounting, provider quotas,
serialized/idempotent purchases and explicit approval for the real pilot.
Hold rejected managed IPs during candidate search; delete old/rejected managed
Floating IPs only after a verified safe cutover. Never delete the primary IP.
The owner accepts about 30 minutes of outage; target 10 minutes after confirmed
blocking, report a delay at 30 minutes. This is not permission to enable live
paid or DNS operations now. Provider-quota exhaustion cleanup is still open.
