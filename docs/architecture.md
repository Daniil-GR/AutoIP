# Architecture

Commander is the independent control plane: FastAPI, database, monitoring scheduler, management UI, future provider integrations. The agent resides next to Telemt and connects outward over TLS; it has no public management endpoint.

Commander never uses the changeable Floating IP for management. Every agent is identified separately from its address and has its own hashed API token.

## Registration

Commander issues one-time enrollment token for 15 minutes. An agent enrolls with its persistent machine identity, receives a long-lived opaque token and saves it with restrictive permissions.

Admin panel currently requires HTTP Basic authentication behind TLS; session management and 2FA are needed before production.

## Current database

Agents, enrollments, jobs and raw checks. Jobs are leased with retry cap; agent command types are allowlisted. Default mode has no endpoints to buy/delete IPs.

## Trust boundary

The optional root helper can update exactly one TOML field and never takes arbitrary commands or paths. It is not installed or authorized by default. Writing the file does not prove that Telemt loaded its new tag.

## Production TODO

Formal DB migrations, credential rotation, admin auth strengthening, independent RU probes, verified MTProto tests, incident state machine, Telegram confirmations, Cherry + budgets, safe DNS changes, network rollback, Telethon, backup/reconcile operations.
