#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) != 0 ]]; then echo 'Run as root' >&2; exit 1; fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$ROOT_DIR" != "/opt/AutoIP" ]]; then echo 'Clone project to /opt/AutoIP before installing' >&2; exit 1; fi
id -u autoip-agent >/dev/null 2>&1 || useradd --system --home /var/lib/autoip-agent --shell /usr/sbin/nologin autoip-agent
install -d -o autoip-agent -g autoip-agent -m 0700 /var/lib/autoip-agent
install -d -m 0750 /etc/autoip-agent
if [[ ! -e /etc/autoip-agent/agent.env ]]; then
  cp "$ROOT_DIR/agent/agent.env.example" /etc/autoip-agent/agent.env
  chmod 0640 /etc/autoip-agent/agent.env
  chown root:autoip-agent /etc/autoip-agent/agent.env
fi
if [[ ! -e "$ROOT_DIR/.venv" ]]; then python3 -m venv "$ROOT_DIR/.venv"; fi
"$ROOT_DIR/.venv/bin/pip" install -r "$ROOT_DIR/agent/requirements.txt"
install -m 0644 "$ROOT_DIR/agent/autoip-agent.service" /etc/systemd/system/autoip-agent.service
# No sudo privileges are installed automatically.
systemctl daemon-reload
echo "Installed. Edit /etc/autoip-agent/agent.env, enroll as autoip-agent, then systemctl enable --now autoip-agent."
