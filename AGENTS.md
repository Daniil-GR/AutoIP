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
paid or DNS operations now. On provider-quota exhaustion, free rejected managed
candidate IPs after stopping search; keep their blocked-address history across
release/restart. Exclude the management IP and any address still used by live
DNS/configuration from candidate cleanup. Respect the project-wide rolling
order quota; a new day does not imply fresh, previously unseen IPv4 addresses.

## Node Host VPS replacement, agreed on 2026-10-31

The owner additionally selected `pl.vetka.rest` for a separate whole-VPS
replacement strategy through `nodehost_bot`: Poland, Ubuntu 24.04, 1 vCPU,
3 GB RAM, 25 GB disk, one-day rental. Do not apply Cherry Floating IP actions
to those servers. The two strategies must stay isolated. Preserve the owner's
hello secret and ad_tag through encrypted profiles; no MTProxybot registration.
Read docs/nodehost-v2.md for verified scope and unfinished integration.
Live Node Host purchases, deletion and DNS cutover require a concrete approved
pilot; browsing the configuration menu is authorized. Report deletion/refund
refusal and retain resource accounting. Never try to bypass hoster restrictions.

## Node Host country update, 2026-10-31

The owner now selected Germany, 1 vCPU / 2 GB RAM / 25 GB disk, Ubuntu 24.04,
one day. Germany is offered under the 1 Gbps menu. Keep the existing logical
proxy hostname/profile. When searching Poland in future, three confirmed
Polish REJECT_RU_FILTER receipts trigger Germany for that search. Unknown
checks do not count. The owner reported manually deleting Polish servers;
keep this report distinct from a verified provider deletion/refund.

Finland was subsequently selected by the owner because German purchases were
temporarily disabled. Current candidate configuration remains 1 vCPU / 2 GB /
25 GB, Ubuntu 24.04, one day, 1 Gbps. Preserve the existing hostname/profile.

The owner then explicitly authorized deleting the rejected Finnish pilot VPS
and buying Netherlands with 1 vCPU / 2 GB / 25 GB, Ubuntu 24.04, one day.
Netherlands is offered under the 10 Gbps menu. Keep the existing hostname,
secrets and the separate Polish source VPS. Record actual deletion/refund
outcomes; a financial or destructive callback must never be blindly repeated.

## Proxy protocol selection, 2026-10-31

The owner requested a second protocol mode for new proxies: MTProto-only
FakeTLS on port 443, separate from the existing Web + MTProto 9443 mode.
Preserve existing nodes and their protocol. The selected new TelemtProxy
MTProto installer uses SNI www.booking.com. Store the chosen mode per agent
and encrypted profile; retain domain/hello/ad_tag across VPS replacements.
The next subdomain, hello and ad_tag will be supplied later through secure
settings. This request does not authorize installing on an existing node,
changing DNS, buying a server, or enabling a new paid automation mode.

The Lithuanian node's WEB proxy was subsequently switched to Gcore CDN in
an approved pilot. The owner confirmed actual proxy traffic and selected
Check-Host plus RIPE Atlas for CDN monitoring, excluding MTProto Checker
from decisions for this node. Preserve its client CNAME and keep direct
Floating IP/DNS automation disabled. HTTPS/TLS endpoint success is distinct
from owner-confirmed WEB proxy data transfer. Other nodes retain their own
monitoring modes. Atlas remains bounded to the existing hourly credit limit.
