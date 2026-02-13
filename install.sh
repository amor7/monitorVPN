#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/monitorVPN"

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

  if [[ ! -f "$APP_DIR/telegram.json" ]]; then
    cp ./samples/telegram.sample.json "$APP_DIR/telegram.json"
    echo "[INFO] Created $APP_DIR/telegram.json from sample. Please edit it."
  fi
  if [[ ! -f "$APP_DIR/configs.json" ]]; then
    cp ./samples/configs.sample.json "$APP_DIR/configs.json"
    echo "[INFO] Created $APP_DIR/configs.json from sample."
  fi
}

setup_venv() {
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install -U pip
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
}

install_systemd() {
  cp -f ./systemd/monitorVPN.service /etc/systemd/system/monitorVPN.service
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
install_systemd

echo
echo "Done."
echo "1) Edit: $APP_DIR/telegram.json"
echo "2) Add servers: $APP_DIR/configs.json (or via Telegram /add)"
echo "3) Telegram: /status  /test"
