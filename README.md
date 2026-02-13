# monitorVPN (Telegram Dashboard + Xray Delay Test)

A lightweight server-side monitor for VLESS/VMess/Trojan/SS links:
- Real delay test using **Xray**
- Concurrent testing
- Telegram live dashboard (single message updated)
- Alerts on DOWN / RECOVERY with cooldown
- Remote commands via Telegram: `/status`, `/refresh`, `/test`, `/add`, `/rename`, `/freeze`, `/unfreeze`, etc.
- Runs as a daemon with **systemd** (auto-start after reboot)

## Quick Install

```bash
git clone https://github.com/amor7/monitorVPN.git
cd monitorVPN
sudo bash install.sh
```

After install:
- Edit: `/opt/monitorVPN/telegram.json`
- Add servers: `/opt/monitorVPN/configs.json` (or via Telegram `/add`)
- Logs: `journalctl -u monitorVPN -f`
