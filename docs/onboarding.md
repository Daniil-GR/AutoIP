# Multi-agent onboarding

Commander dashboard includes Add agent and settings editor.

1. Generate a short-lived enrollment token. Token is displayed only once.
2. Install agent on another VPS and connect it to the Commander HTTPS URL.
3. Agent reports hostname, OS and Telemt facts if readable.
4. Open the agent detail panel and choose Настройки агента.
5. Save provider, Cherry project/server IDs, region, sponsoring channel and maximum candidates.
6. Values are stored as JSON in Commander PostgreSQL. These are **nonsecret metadata**.
7. Do not enter Cherry API tokens, Telegram session keys, passwords, or MTProto secrets into notes or ID fields.
8. Provider credential storage and an encrypted secret integration form are planned but not implemented.

The agent cannot yet automatically ask for all credentials. This milestone is a durable onboarding/settings MVP, not the full intelligent wizard.
