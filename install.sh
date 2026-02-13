#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/monitorVPN"
SERVICE_SRC="./systemd/monitorVPN.service"
SERVICE_DST="/etc/systemd/system/monitorVPN.service"

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
  fi
}

detect_pkg_manager() {
  if command -v apt >/dev/null 2>&1; then echo "apt"; return; fi
  if command -v dnf >/dev/null 2>&1; then echo "dnf"; return; fi
  if command -v yum >/dev/null 2>&1; then echo "yum"; return; fi
  if command -v pacman >/dev/null 2>&1; then echo "pacman"; return; fi
  echo "unknown"
}

install_packages() {
  local pm
  pm="$(detect_pkg_manager)"
  case "$pm" in
    apt)
      apt update
      apt install -y python3 python3-venv python3-pip curl ca-certificates git unzip
      ;;
    dnf)
      dnf install -y python3 python3-pip curl ca-certificates git unzip
      ;;
    yum)
      yum install -y python3 python3-pip curl ca-certificates git unzip
      ;;
    pacman)
      pacman -Sy --noconfirm python python-pip curl ca-certificates git unzip
      ;;
    *)
      echo "Unsupported distro. Install manually: python3 python3-venv python3-pip curl git"
      exit 1
      ;;
  esac
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    echo "[OK] xray already installed."
    return
  fi
  echo "[INFO] Installing Xray (auto-detect arch/OS)…"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  command -v xray >/dev/null 2>&1 && echo "[OK] xray installed." || echo "[WARN] xray not found in PATH."
}

deploy_files() {
  mkdir -p "$APP_DIR"
  cp -f ./monitorVPN.py "$APP_DIR/monitorVPN.py"
  cp -f ./requirements.txt "$APP_DIR/requirements.txt"
}

setup_venv() {
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install -U pip
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
}

prompt_telegram_config_if_missing() {
  local tg="$APP_DIR/telegram.json"
  if [[ -f "$tg" ]]; then
    return
  fi

  echo
  echo "=== Telegram setup ==="
  read -r -p "Enable Telegram? [Y/n]: " ans </dev/tty || true
  ans="${ans:-Y}"
  if [[ "$ans" =~ ^[Nn]$ ]]; then
    cat > "$tg" <<'JSON'
{
  "enabled": false
}
JSON
    chmod 600 "$tg"
    echo "[INFO] Telegram disabled (telegram.json created)."
    return
  fi

  local token chatid mode
  read -r -p "Bot token (from @BotFather): " token </dev/tty
  read -r -p "Chat ID (numeric): " chatid </dev/tty
  read -r -p "Telegram mode [direct/proxy/tunnel] (default=direct): " mode </dev/tty || true
  mode="${mode:-direct}"

  cat > "$tg" <<JSON
{
  "enabled": true,
  "bot_token": "${token}",
  "chat_id": "${chatid}",
  "dashboard_message_id": null,
  "alerts_enabled": true,
  "recovery_alerts": true,
  "alert_cooldown_sec": 300,
  "telegram_mode": "${mode}",
  "telegram_proxy": "",
  "tunnel_keepalive_sec": 60,
  "tunnel_pick": "best_ping",
  "show_uptime": false,
  "auto_enabled": true,
  "auto_minutes": 1,
  "max_workers": 6
}
JSON
  chmod 600 "$tg"
  echo "[OK] Created $tg"
}

prompt_configs_if_missing() {
  local cfg="$APP_DIR/configs.json"
  if [[ -f "$cfg" ]]; then
    return
  fi

  echo
  echo "=== Servers list ==="
  read -r -p "Do you want to add server links now? [y/N]: " ans </dev/tty || true
  ans="${ans:-N}"
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "[]" > "$cfg"
    chmod 600 "$cfg"
    echo "[INFO] Created empty $cfg (you can add later via Telegram /add)."
    return
  fi

  echo "Paste links one by one. Press ENTER on empty line to finish."
  local tmp
  tmp="$(mktemp)"

  # Read from /dev/tty so it ALWAYS waits for user input (fixes EOF/0-items issue)
  while true; do
    local line
    IFS= read -r line </dev/tty || break
    line="$(echo "$line" | tr -d '\r')"
    [[ -z "$line" ]] && break
    echo "$line" >> "$tmp"
  done

  python3 - <<'PY' "$tmp" > "$cfg"
import sys, json, uuid
path = sys.argv[1]
items=[]
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for raw in f:
        link = raw.strip()
        if not link:
            continue
        items.append({
            "id": str(uuid.uuid4()),
            "name": "",
            "link": link,
            "enabled": True,
            "frozen_until": 0
        })
json.dump(items, sys.stdout, ensure_ascii=False, indent=2)
PY

  rm -f "$tmp"
  chmod 600 "$cfg"

  local count
  count="$(python3 - <<'PY'
import json
p="/opt/monitorVPN/configs.json"
try:
    print(len(json.load(open(p,"r",encoding="utf-8"))))
except Exception:
    print(0)
PY
)"
  echo "[OK] Created $cfg with ${count} item(s)."
}

install_systemd() {
  # Copy service file
  cp -f "$SERVICE_SRC" "$SERVICE_DST"

  # Ensure timezone for service = Asia/Tehran (fix program time display)
  if ! grep -q '^Environment=TZ=Asia/Tehran' "$SERVICE_DST"; then
    # insert after User=... if present, else after [Service]
    if grep -q '^User=' "$SERVICE_DST"; then
      sed -i '/^User=/a Environment=TZ=Asia/Tehran' "$SERVICE_DST"
    else
      sed -i '/^\[Service\]/a Environment=TZ=Asia/Tehran' "$SERVICE_DST"
    fi
  fi

  systemctl daemon-reload
  systemctl enable --now monitorVPN
  echo "[OK] Service installed and started: monitorVPN"
  echo "Logs: journalctl -u monitorVPN -f"
}

need_root
install_packages
install_xray
deploy_files
setup_venv
prompt_telegram_config_if_missing
prompt_configs_if_missing
install_systemd

echo
echo "Done."
echo "Edit: $APP_DIR/telegram.json and $APP_DIR/configs.json anytime."
