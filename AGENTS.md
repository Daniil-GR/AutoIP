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
