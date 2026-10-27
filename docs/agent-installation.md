# Agent installation: manual first deployment

1. On the proxy server install Python 3.12+, venv, Git and sudo. Keep main SSH and network settings untouched.
2. Clone the repository into /opt/AutoIP and review agent code and installer.
3. Run: sudo bash /opt/AutoIP/agent/install.sh
4. Edit /etc/autoip-agent/agent.env with HTTPS Commander URL.
5. Create a 15-minute enrollment token in Commander panel.
6. From /opt/AutoIP run the following, replacing both placeholders:
   sudo -u autoip-agent env AUTOIP_COMMANDER_URL=https://COMMANDER-DOMAIN AUTOIP_ENROLL_TOKEN=PASTE_TOKEN AUTOIP_STATE_PATH=/var/lib/autoip-agent/identity.json /opt/AutoIP/.venv/bin/python -m agent.main enroll
7. Run: sudo systemctl enable --now autoip-agent
8. Inspect: sudo journalctl -u autoip-agent -n 60 --no-pager
9. Confirm agent appears online in Commander panel.

Agent service user needs read access to /etc/telemt/telemt.toml to discover public_host. Never chmod the config world-readable; it contains secrets. If access is restricted, agent heartbeats but without public_host until a secure restricted config reader is implemented.

The installer intentionally does NOT authorize root helper or apply ad tags by default. Do not enable writes on production before code audit, privilege setup, hot reload and rollback testing.

Agent identity stored under /var/lib/autoip-agent/identity.json (0600). Never commit or share its contents.

Alternatively set AUTOIP_PUBLIC_HOST and AUTOIP_PROXY_PORT in /etc/autoip-agent/agent.env without allowing the service user to read secrets in the Telemt config.
