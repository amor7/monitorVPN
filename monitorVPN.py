#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
amor_monitor_server.py
Amor VPN Monitoring & Management (Server / Linux Edition)

Core features (compatible with your previous working script):
✅ Real Delay test (v2rayN-like): runs xray with a temporary config per link and measures an HTTP request through local SOCKS
✅ Concurrent testing
✅ Telegram Live Dashboard (ONE message edited; no spam)
✅ Telegram Alerts on state-change with cooldown
✅ Remote commands: /status, /refresh, /test, /freeze, /unfreeze, /del, /uptime on|off
✅ Freeze (manual / timed) + Uptime on dashboard
✅ Headless daemon (no GUI)

Fixes & improvements (patch):
- Default telegram_mode is now "direct" (you can switch later with /setmode tunnel|proxy|direct)
- More robust Telegram dashboard sending: HTML+keyboard → HTML → plain-text fallback
- Adds useful commands: /setmode, /setproxy, /resetdash, /ping, /debug
- Backward-compatible freeze fields (supports old keys: frozen/freeze_until)
- Wizard no longer nags every run: it shows only when needed (or FORCE_SETUP=1)

Requirements:
  python3 -m pip install requests pysocks
  Place xray binary next to this script (./xray) OR install xray in PATH.
  (Optional) set XRAY_PATH=/full/path/to/xray

Run:
  python3 amor_monitor_server.py
"""

from __future__ import annotations

import os
import sys
import json
import time
import threading
import subprocess
import urllib.parse
import tempfile
import base64
import socket
import signal
import uuid
import datetime
import html
import shutil
import logging
import traceback
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple, Dict, Any, List

# ---- Optional dependency (required for real delay + telegram) ----
try:
    import requests  # type: ignore
except Exception:
    requests = None

# -------------------- Logging --------------------
def _env_bool(name: str, default: bool = False) -> bool:
    v = str(os.environ.get(name, "") or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "y", "on")

DEBUG_ENABLED = _env_bool("AMOR_DEBUG", False) or _env_bool("DEBUG", False)

logging.basicConfig(
    level=(logging.DEBUG if DEBUG_ENABLED else logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("amor-monitor")

# -------------------- Paths --------------------
def app_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

APP_DIR = app_dir()
TELEGRAM_SETTINGS_FILE = os.path.join(APP_DIR, "telegram.json")
CONFIGS_FILE = os.path.join(APP_DIR, "configs.json")

# -------------------- Settings --------------------
TEST_URLS = [
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
    "https://www.wikipedia.org",
    "https://www.bing.com",
]

REQUEST_TIMEOUT_SEC = 8
SOCKS_READY_TIMEOUT_SEC = 1.2
MAX_WORKERS_DEFAULT = 5

DASHBOARD_WARN_MS = 700
DASHBOARD_UPDATE_MIN_INTERVAL_SEC = 3.0
DEFAULT_ALERT_COOLDOWN_SEC = 5 * 60  # 5 minutes


# -------------------- JSON helpers --------------------
def _atomic_write_json(path: str, data: Any, *, indent: int = 2):
    tmp = f"{path}.tmp.{os.getpid()}.{int(time.time()*1000)}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=indent)
    os.replace(tmp, path)

def _safe_read_json(path: str, default: Any):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

# -------------------- Xray path --------------------
def resolve_xray_path() -> str:
    env = str(os.environ.get("XRAY_PATH", "") or "").strip()
    if env:
        return env
    # Prefer local folder binary first
    for cand in (
        os.path.join(APP_DIR, "xray"),
        os.path.join(APP_DIR, "xray.exe"),
        "xray",
    ):
        if os.path.exists(cand):
            return cand
        if cand == "xray" and shutil.which("xray"):
            return "xray"
    return "xray"


XRAY_PATH = resolve_xray_path()


def _xray_available() -> bool:
    if os.path.exists(XRAY_PATH):
        return True
    return shutil.which(XRAY_PATH) is not None


def _ensure_exec_bit(path: str):
    if os.name == "nt":
        return
    try:
        if os.path.exists(path):
            st = os.stat(path)
            if not (st.st_mode & 0o111):
                os.chmod(path, st.st_mode | 0o111)
    except Exception:
        pass


_ensure_exec_bit(XRAY_PATH)

# -------------------- Core helpers --------------------
def get_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def b64decode_any(s: str) -> bytes:
    s = (s or "").strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def safe_unquote(s: str) -> str:
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return s

def extract_name_from_link(link: str) -> str:
    """Extract a human-friendly name from a config link.
    Preference:
      1) Fragment after # (URL-decoded) e.g. vless://...#🇮🇷 name
      2) Fallback: host:port
      3) Fallback: scheme
    """
    link = (link or "").strip()
    if not link:
        return ""
    # Fragment after '#'
    if "#" in link:
        frag = link.split("#", 1)[1]
        frag = safe_unquote(frag).strip()
        frag = frag.replace("\n", " ").replace("\r", " ")
        frag = re.sub(r"\s+", " ", frag).strip()
        if frag:
            return frag[:80]
    # Parse host:port
    try:
        if link.startswith("vmess://"):
            return "vmess"
        u = urllib.parse.urlparse(link)
        host = normalize_host(u.hostname or "")
        port = str(u.port or "").strip()
        if host and port:
            return f"{host}:{port}"[:80]
        if host:
            return host[:80]
        if u.scheme:
            return u.scheme[:80]
    except Exception:
        pass
    return link[:80]


def parse_query(qs: str) -> dict:
    try:
        d = urllib.parse.parse_qs(qs, keep_blank_values=True)
        return {k: (v[0] if isinstance(v, list) and v else "") for k, v in d.items()}
    except Exception:
        return {}


def normalize_host(host: str) -> str:
    return (host or "").strip().strip("[]")


def wait_port_open(host: str, port: int, timeout_sec: float) -> bool:
    end = time.time() + float(timeout_sec)
    while time.time() < end:
        try:
            s = socket.create_connection((host, int(port)), timeout=0.2)
            s.close()
            return True
        except Exception:
            time.sleep(0.05)
    return False


def _parse_ping_ms(ping_str: Any):
    if ping_str is None:
        return None
    s = str(ping_str).strip()
    if s == "-1":
        return -1
    try:
        s2 = s.lower().replace("ms", "").strip()
        return int(s2)
    except Exception:
        return None


def _strip_html_tags(s: str) -> str:
    # Minimal conversion for Telegram plain-text fallback
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"</p\s*>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s)

# -------------------- Link -> Xray outbound builders --------------------
def outbound_vless(u: urllib.parse.ParseResult) -> dict:
    uuid_ = u.username or ""
    host = normalize_host(u.hostname or "")
    port = int(u.port or 443)

    q = parse_query(u.query)
    transport_type = (q.get("type") or q.get("transport") or "").lower()
    security = (q.get("security") or q.get("tls") or "").lower()
    flow = q.get("flow") or ""

    ob = {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": host,
            "port": port,
            "users": [{"id": uuid_, "encryption": "none"}]
        }]},
        "streamSettings": {},
        "tag": "proxy",
    }

    if flow:
        ob["settings"]["vnext"][0]["users"][0]["flow"] = flow

    stream = ob["streamSettings"]

    if transport_type in ("ws", "websocket"):
        stream["network"] = "ws"
        path = q.get("path") or "/"
        ws_host = q.get("host") or q.get("Host") or ""
        headers = {}
        if ws_host:
            headers["Host"] = ws_host
        stream["wsSettings"] = {"path": path, "headers": headers}

    elif transport_type == "grpc":
        stream["network"] = "grpc"
        service_name = q.get("serviceName") or q.get("service") or ""
        mode = (q.get("mode") or "").lower()
        grpc_settings = {}
        if service_name:
            grpc_settings["serviceName"] = service_name
        if mode:
            grpc_settings["multiMode"] = (mode == "multi")
        authority = q.get("authority") or ""
        if authority:
            grpc_settings["authority"] = authority
        stream["grpcSettings"] = grpc_settings
    else:
        stream["network"] = "tcp"
        header_type = (q.get("headerType") or q.get("header") or "").lower()
        if header_type == "http":
            stream["tcpSettings"] = {"header": {"type": "http"}}

    sni = q.get("sni") or q.get("serverName") or q.get("host") or ""
    alpn = q.get("alpn") or ""
    fp = q.get("fp") or ""
    allow_insecure = (q.get("allowInsecure") or "0") in ("1", "true", "True")

    if security == "tls":
        stream["security"] = "tls"
        tls = {"allowInsecure": allow_insecure}
        if sni:
            tls["serverName"] = sni
        if alpn:
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["tlsSettings"] = tls

    elif security == "reality":
        stream["security"] = "reality"
        pbk = q.get("pbk") or q.get("publicKey") or ""
        sid = q.get("sid") or q.get("shortId") or ""
        spx = q.get("spx") or q.get("spiderX") or ""
        reality = {"show": False}
        if sni:
            reality["serverName"] = sni
        if alpn:
            reality["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        if fp:
            reality["fingerprint"] = fp
        if pbk:
            reality["publicKey"] = pbk
        if sid:
            reality["shortId"] = sid
        if spx:
            reality["spiderX"] = spx
        stream["realitySettings"] = reality
    else:
        stream["security"] = "none"

    return ob


def outbound_trojan(u: urllib.parse.ParseResult) -> dict:
    password = u.username or ""
    host = normalize_host(u.hostname or "")
    port = int(u.port or 443)

    q = parse_query(u.query)
    transport_type = (q.get("type") or "").lower()
    security = (q.get("security") or "tls").lower()

    ob = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": {},
        "tag": "proxy",
    }

    stream = ob["streamSettings"]

    if transport_type in ("ws", "websocket"):
        stream["network"] = "ws"
        path = q.get("path") or "/"
        ws_host = q.get("host") or q.get("Host") or ""
        headers = {}
        if ws_host:
            headers["Host"] = ws_host
        stream["wsSettings"] = {"path": path, "headers": headers}
    elif transport_type == "grpc":
        stream["network"] = "grpc"
        service_name = q.get("serviceName") or q.get("service") or ""
        grpc_settings = {}
        if service_name:
            grpc_settings["serviceName"] = service_name
        stream["grpcSettings"] = grpc_settings
    else:
        stream["network"] = "tcp"

    sni = q.get("sni") or q.get("serverName") or q.get("host") or ""
    alpn = q.get("alpn") or ""
    allow_insecure = (q.get("allowInsecure") or "0") in ("1", "true", "True")

    if security == "tls":
        stream["security"] = "tls"
        tls = {"allowInsecure": allow_insecure}
        if sni:
            tls["serverName"] = sni
        if alpn:
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    return ob


def outbound_vmess(link: str) -> dict:
    b64 = link.strip()[len("vmess://"):]
    raw = b64decode_any(b64)
    try:
        j = json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        j = json.loads(safe_unquote(raw.decode("utf-8", errors="ignore")))

    host = j.get("add") or j.get("address") or ""
    port = int(j.get("port") or 443)
    uid = j.get("id") or ""
    aid = int(j.get("aid") or 0)
    scy = j.get("scy") or "auto"
    net = (j.get("net") or "tcp").lower()
    tls_flag = (j.get("tls") or "").lower()
    sni = j.get("sni") or j.get("host") or ""
    alpn = j.get("alpn") or ""
    path = j.get("path") or "/"
    ws_host = j.get("host") or ""

    ob = {
        "protocol": "vmess",
        "settings": {"vnext": [{
            "address": host,
            "port": port,
            "users": [{"id": uid, "alterId": aid, "security": scy}]
        }]},
        "streamSettings": {},
        "tag": "proxy",
    }

    stream = ob["streamSettings"]

    if net == "ws":
        stream["network"] = "ws"
        headers = {}
        if ws_host:
            headers["Host"] = ws_host
        stream["wsSettings"] = {"path": path, "headers": headers}
    elif net == "grpc":
        stream["network"] = "grpc"
        service_name = j.get("path") or j.get("serviceName") or ""
        grpc_settings = {}
        if service_name:
            grpc_settings["serviceName"] = service_name
        stream["grpcSettings"] = grpc_settings
    else:
        stream["network"] = "tcp"

    if tls_flag == "tls":
        stream["security"] = "tls"
        tls = {"allowInsecure": False}
        if sni:
            tls["serverName"] = sni
        if alpn:
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    return ob


def outbound_ss(u: urllib.parse.ParseResult, raw_link: str) -> dict:
    host = normalize_host(u.hostname or "")
    port = int(u.port or 8388)

    username = u.username or ""
    password = u.password or ""

    method = ""
    passwd = ""

    if username and password:
        method = safe_unquote(username)
        passwd = safe_unquote(password)
    else:
        s = raw_link.strip()[len("ss://"):]
        if "@" in s:
            cred_b64 = s.split("@", 1)[0]
            cred = b64decode_any(cred_b64).decode("utf-8", errors="ignore")
            if ":" in cred:
                method, passwd = cred.split(":", 1)

    if not method or not passwd:
        raise ValueError("Invalid ss link")

    return {
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": host,
            "port": port,
            "method": method,
            "password": passwd
        }]},
        "tag": "proxy",
        "streamSettings": {"network": "tcp", "security": "none"}
    }


def build_xray_config_from_link(link: str, local_socks_port: int) -> dict:
    link = link.strip()

    if link.startswith("vmess://"):
        outbound = outbound_vmess(link)
    else:
        u = urllib.parse.urlparse(link)
        scheme = (u.scheme or "").lower()
        if scheme == "vless":
            outbound = outbound_vless(u)
        elif scheme == "trojan":
            outbound = outbound_trojan(u)
        elif scheme == "ss":
            outbound = outbound_ss(u, link)
        else:
            raise ValueError(f"Unsupported scheme: {scheme}")

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(local_socks_port),
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            "tag": "in-socks"
        }],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": ["in-socks"],
                "outboundTag": "proxy"
            }]
        }
    }


def _spawn_xray_with_socks(link: str):
    if requests is None or (not _xray_available()):
        return None, None, None

    socks_port = get_free_port()
    cfg_path = None
    proc = None

    try:
        cfg = build_xray_config_from_link(link, socks_port)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            cfg_path = f.name

        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # allow killing the whole group
        )

        if not wait_port_open("127.0.0.1", socks_port, SOCKS_READY_TIMEOUT_SEC):
            raise RuntimeError("socks not ready")

        return proc, cfg_path, socks_port
    except Exception as e:
        if DEBUG_ENABLED:
            log.debug("xray spawn failed: %s", e)
        try:
            if proc:
                proc.kill()
        except Exception:
            pass
        try:
            if cfg_path:
                os.remove(cfg_path)
        except Exception:
            pass
        return None, None, None


def _stop_xray(proc, cfg_path):
    if proc is not None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

        try:
            proc.wait(timeout=2.0)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    if cfg_path:
        try:
            os.remove(cfg_path)
        except Exception:
            pass


def run_xray_and_measure_delay(link: str, timeout_sec: int = REQUEST_TIMEOUT_SEC) -> str:
    # IMPORTANT: stable testing logic (same behavior)
    if requests is None:
        return "-1"
    if not _xray_available():
        return "-1"

    proc, cfg_path, socks_port = _spawn_xray_with_socks(link)
    if not proc:
        return "-1"

    try:
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }

        start = time.time()
        ok = False

        for url in TEST_URLS:
            try:
                r = requests.get(url, proxies=proxies, timeout=timeout_sec, stream=True)
                if r.status_code in (200, 204):
                    ok = True
                    try:
                        r.close()
                    except Exception:
                        pass
                    break
                try:
                    r.close()
                except Exception:
                    pass
            except Exception:
                continue

        delay_ms = int((time.time() - start) * 1000) if ok else -1
        return f"{delay_ms} ms" if delay_ms != -1 else "-1"
    finally:
        _stop_xray(proc, cfg_path)


# -------------------- Telegram settings --------------------
def _default_telegram_template():
    return {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",   # can be str or int in JSON; we normalize to str in memory
        "dashboard_message_id": None,

        "alerts_enabled": True,
        "recovery_alerts": True,
        "alert_cooldown_sec": DEFAULT_ALERT_COOLDOWN_SEC,

        # Telegram routing modes:
        # "direct"  -> try direct
        # "proxy"   -> use telegram_proxy for Telegram API only
        # "tunnel"  -> build a temporary tunnel using one healthy server config
        "telegram_mode": "direct",

        # Only if telegram_mode == "proxy"
        "telegram_proxy": "",

        # Only if telegram_mode == "tunnel"
        "tunnel_keepalive_sec": 60,
        "tunnel_pick": "best_ping",

        # Dashboard option
        "show_uptime": False,

        # Server-side scheduler defaults (can be overridden by env AUTO_MINUTES/MAX_WORKERS)
        "auto_enabled": True,
        "auto_minutes": 10,
        "max_workers": MAX_WORKERS_DEFAULT,

        # Debug flag (persisted)
        "debug": False,
    }


def ensure_telegram_file_exists():
    if os.path.exists(TELEGRAM_SETTINGS_FILE):
        return
    try:
        _atomic_write_json(TELEGRAM_SETTINGS_FILE, _default_telegram_template(), indent=2)
    except Exception:
        pass


def load_telegram_settings() -> dict:
    ensure_telegram_file_exists()
    base = _default_telegram_template()

    data = _safe_read_json(TELEGRAM_SETTINGS_FILE, {})
    if not isinstance(data, dict):
        data = {}

    merged = dict(base)
    merged.update(data)

    merged["enabled"] = bool(merged.get("enabled", False))
    merged["bot_token"] = str(merged.get("bot_token", "")).strip()

    # normalize chat_id to string (Telegram accepts both int and numeric str)
    cid = merged.get("chat_id", "")
    if cid is None:
        cid = ""
    merged["chat_id"] = str(cid).strip()

    merged["telegram_mode"] = str(merged.get("telegram_mode", "direct")).strip().lower()
    merged["telegram_proxy"] = str(merged.get("telegram_proxy", "") or "").strip()

    try:
        merged["alert_cooldown_sec"] = int(merged.get("alert_cooldown_sec", DEFAULT_ALERT_COOLDOWN_SEC))
    except Exception:
        merged["alert_cooldown_sec"] = DEFAULT_ALERT_COOLDOWN_SEC

    try:
        merged["tunnel_keepalive_sec"] = int(merged.get("tunnel_keepalive_sec", 60))
    except Exception:
        merged["tunnel_keepalive_sec"] = 60

    merged["tunnel_pick"] = str(merged.get("tunnel_pick", "best_ping")).strip().lower()
    if merged["tunnel_pick"] not in ("best_ping", "first_ok"):
        merged["tunnel_pick"] = "best_ping"

    merged["alerts_enabled"] = bool(merged.get("alerts_enabled", True))
    merged["recovery_alerts"] = bool(merged.get("recovery_alerts", True))
    merged["show_uptime"] = bool(merged.get("show_uptime", False))

    # debug persisted
    merged["debug"] = bool(merged.get("debug", False))

    return merged


def save_telegram_settings(cfg: dict):
    try:
        _atomic_write_json(TELEGRAM_SETTINGS_FILE, cfg, indent=2)
    except Exception:
        pass


# -------------------- Telegram Tunnel Manager --------------------
class TelegramTunnel:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.cfg_path = None
        self.socks_port = None
        self.expires_at = 0.0
        self.link_in_use = None

    def get_proxies(self, healthy_link: str, keepalive_sec: int):
        with self.lock:
            now_ts = time.time()
            if self.proc and self.socks_port and now_ts < self.expires_at and self.link_in_use == healthy_link:
                return {
                    "http": f"socks5h://127.0.0.1:{self.socks_port}",
                    "https": f"socks5h://127.0.0.1:{self.socks_port}",
                }

            self._stop_locked()

            proc, cfg_path, port = _spawn_xray_with_socks(healthy_link)
            if not proc:
                return None

            self.proc = proc
            self.cfg_path = cfg_path
            self.socks_port = port
            self.link_in_use = healthy_link
            self.expires_at = now_ts + max(10, int(keepalive_sec or 60))

            return {
                "http": f"socks5h://127.0.0.1:{self.socks_port}",
                "https": f"socks5h://127.0.0.1:{self.socks_port}",
            }

    def _stop_locked(self):
        if self.proc or self.cfg_path:
            _stop_xray(self.proc, self.cfg_path)
        self.proc = None
        self.cfg_path = None
        self.socks_port = None
        self.link_in_use = None
        self.expires_at = 0.0

    def stop(self):
        with self.lock:
            self._stop_locked()


# -------------------- Telegram API helpers --------------------
def tg_api_get_updates(tg_cfg: dict, offset: Optional[int] = None, timeout: int = 25, proxies=None):
    if requests is None:
        return None
    token = str(tg_cfg.get("bot_token", "")).strip()
    if not token:
        return None

    params: Dict[str, Any] = {"timeout": int(timeout)}
    if offset is not None:
        params["offset"] = int(offset)

    # Force types we care about (safe even if webhook allowed_updates is set)
    params["allowed_updates"] = json.dumps(["message", "edited_message", "callback_query"])

    try:
        url = f"https://api.telegram.org/bot{token}/getUpdates"
        r = requests.get(url, params=params, timeout=timeout + 10, proxies=proxies)
        return r.json()
    except Exception as e:
        return {"ok": False, "_error": str(e)}


def tg_api_post(method: str, payload: dict, tg_cfg: dict, proxies=None):
    if requests is None:
        return {"ok": False, "_error": "requests not installed"}
    token = str(tg_cfg.get("bot_token", "")).strip()
    if not token:
        return {"ok": False, "_error": "bot_token is empty"}
    base_url = str(tg_cfg.get("base_url", "https://api.telegram.org")).strip() or "https://api.telegram.org"
    url = f"{base_url}/bot{token}/{method}"
    try:
        r = requests.post(url, json=payload, timeout=20, proxies=proxies)
        try:
            return r.json()
        except Exception:
            return {"ok": False, "_error": f"Non-JSON response (HTTP {r.status_code}): {r.text[:400]}"}
    except Exception as e:
        return {"ok": False, "_error": str(e)}


def _tg_send_with_fallback(tg_cfg: dict, payload_html: dict, *, proxies=None) -> dict:
    """
    Try:
      1) HTML (as given)
      2) HTML without reply_markup
      3) Plain text without parse_mode
    """
    # 1) as-is
    resp = tg_api_post("sendMessage", payload_html, tg_cfg, proxies=proxies)
    if isinstance(resp, dict) and resp.get("ok"):
        return resp

    # 2) drop reply_markup
    payload2 = dict(payload_html)
    payload2.pop("reply_markup", None)
    resp2 = tg_api_post("sendMessage", payload2, tg_cfg, proxies=proxies)
    if isinstance(resp2, dict) and resp2.get("ok"):
        return resp2

    # 3) plain text
    payload3 = dict(payload2)
    try:
        payload3["text"] = _strip_html_tags(str(payload3.get("text", "")))
    except Exception:
        pass
    payload3.pop("parse_mode", None)
    resp3 = tg_api_post("sendMessage", payload3, tg_cfg, proxies=proxies)
    return resp3


def _tg_edit_with_fallback(tg_cfg: dict, payload_html: dict, *, proxies=None) -> dict:
    """
    Try:
      1) editMessageText HTML
      2) editMessageText HTML without reply_markup
      3) editMessageText plain text without parse_mode
    """
    resp = tg_api_post("editMessageText", payload_html, tg_cfg, proxies=proxies)
    if isinstance(resp, dict) and resp.get("ok"):
        return resp

    payload2 = dict(payload_html)
    payload2.pop("reply_markup", None)
    resp2 = tg_api_post("editMessageText", payload2, tg_cfg, proxies=proxies)
    if isinstance(resp2, dict) and resp2.get("ok"):
        return resp2

    payload3 = dict(payload2)
    try:
        payload3["text"] = _strip_html_tags(str(payload3.get("text", "")))
    except Exception:
        pass
    payload3.pop("parse_mode", None)
    resp3 = tg_api_post("editMessageText", payload3, tg_cfg, proxies=proxies)
    return resp3


def tg_send_text(tg_cfg: dict, text: str, proxies=None):
    if not tg_cfg.get("enabled"):
        return
    chat_id = str(tg_cfg.get("chat_id", "")).strip()
    token = str(tg_cfg.get("bot_token", "")).strip()
    if not chat_id or not token:
        return

    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    resp = _tg_send_with_fallback(tg_cfg, payload, proxies=proxies)
    if DEBUG_ENABLED or bool(tg_cfg.get("debug", False)):
        if not (isinstance(resp, dict) and resp.get("ok")):
            log.debug("tg_send_text failed: %s", resp)


# -------------------- Dashboard formatting --------------------
def _status_bucket(ms):
    if ms == -1:
        return 0
    if ms is None:
        return 1
    return 1 if ms > DASHBOARD_WARN_MS else 2


def build_dashboard_keyboard():
    return {
        "inline_keyboard": [
            [
                {"text": "✅ Test Now", "callback_data": "TEST_NOW"},
                {"text": "🔄 Refresh", "callback_data": "REFRESH"},
                {"text": "ℹ️ Help", "callback_data": "HELP"},
            ],
            [
                {"text": "🧯 Reset Dashboard", "callback_data": "RESET_DASH"},
            ],
        ]
    }


def build_dashboard_text(configs: list, last_test_ts: str, show_uptime: bool = False) -> str:
    def fmt_dur(sec: float) -> str:
        try:
            sec = int(max(0, sec))
        except Exception:
            return "0m"
        d, rem = divmod(sec, 86400)
        h, rem = divmod(rem, 3600)
        m, _ = divmod(rem, 60)
        if d > 0:
            return f"{d}d {h:02d}h"
        if h > 0:
            return f"{h}h {m:02d}m"
        return f"{m}m"

    now_ts = time.time()
    enriched = []

    for i, c in enumerate(configs, start=1):
        name = str(c.get("name", "Unknown"))
        ping = str(c.get("ping", "---")).strip()
        ms = _parse_ping_ms(ping)

        manual_frozen = bool(c.get("manual_frozen", False))
        try:
            fu = float(c.get("frozen_until", 0) or 0)
        except Exception:
            fu = 0.0
        frozen = manual_frozen or (fu and fu > now_ts)

        if frozen:
            icon = "🧊"
            bucket = 3
            sort_ms = 10**9
        else:
            bucket = _status_bucket(ms)
            sort_ms = ms if ms is not None else 10**9
            if ms == -1:
                icon = "🔴"
            elif ms is None:
                icon = "🟠"
            else:
                icon = "🟠" if ms > DASHBOARD_WARN_MS else "🟢"

        extras = []
        if frozen:
            if manual_frozen:
                extras.append("FROZEN")
            else:
                extras.append(f"FROZEN {fmt_dur(fu - now_ts)}")

        if show_uptime and not frozen:
            st = str(c.get("last_state", "UNKNOWN"))
            up_since = c.get("up_since")
            down_since = c.get("down_since")
            if st == "OK" and up_since:
                try:
                    extras.append("UP " + fmt_dur(now_ts - float(up_since)))
                except Exception:
                    pass
            elif st == "DOWN" and down_since:
                try:
                    extras.append("DOWN " + fmt_dur(now_ts - float(down_since)))
                except Exception:
                    pass

        safe_name = html.escape(name)
        shown = ping if ping not in ("---", "") else "—"
        safe_ping = html.escape(shown)

        extra_part = ""
        if extras:
            extra_part = " | " + " | ".join([f"<code>{html.escape(str(x))}</code>" for x in extras])

        line = f"{icon} <b>{i}. {safe_name}</b> — <code>{safe_ping}</code>{extra_part}"
        enriched.append((bucket, sort_ms, name.lower(), i, line))

    enriched.sort(key=lambda t: (t[0], t[1], t[2], t[3]))
    rows = [t[4] for t in enriched]

    header = [
        "📡 <b>Amor Monitor – Live Status</b>",
        f"Legend: 🟢 ≤{DASHBOARD_WARN_MS}ms | 🟠 &gt;{DASHBOARD_WARN_MS}ms | 🔴 DOWN (-1) | 🧊 Frozen",
        f"Last test: <code>{html.escape(last_test_ts)}</code>",
        "",
    ]

    text = "\n".join(header + rows) if rows else "\n".join(header + ["<i>No servers in configs.json</i>"])
    if len(text) > 3900:
        text = text[:3900] + "\n…"
    return text


# -------------------- Config store helpers (compatible + backward compatible) --------------------
def load_configs() -> list:
    data = _safe_read_json(CONFIGS_FILE, [])
    return data if isinstance(data, list) else []


def save_configs(configs: list):
    try:
        _atomic_write_json(CONFIGS_FILE, configs, indent=4)
    except Exception:
        pass


def _migrate_old_freeze_keys(c: dict) -> bool:
    """
    Support older keys:
      - frozen (bool) -> manual_frozen
      - freeze_until (ts) -> frozen_until
    """
    changed = False
    if "manual_frozen" not in c and "frozen" in c:
        c["manual_frozen"] = bool(c.get("frozen", False))
        changed = True
    if "frozen_until" not in c and "freeze_until" in c:
        try:
            c["frozen_until"] = float(c.get("freeze_until") or 0)
        except Exception:
            c["frozen_until"] = 0
        changed = True
    return changed


def ensure_ids_and_state(configs: list) -> bool:
    changed = False
    for c in configs:
        if not isinstance(c, dict):
            continue

        if _migrate_old_freeze_keys(c):
            changed = True

        if "id" not in c:
            c["id"] = str(uuid.uuid4()); changed = True
                # name: if missing or looks like a full link, infer from link fragment (#...)
        if "name" not in c:
            c["name"] = extract_name_from_link(str(c.get("link","") or "")) or c.get("link", "Config")
            changed = True
        else:
            cur_name = str(c.get("name","") or "")
            if (not cur_name.strip()) or (cur_name.strip().lower().startswith(("vless://","vmess://","trojan://","ss://"))):
                inferred = extract_name_from_link(str(c.get("link","") or ""))
                if inferred and inferred != cur_name:
                    c["name"] = inferred
                    changed = True
        if "link" not in c:
            c["link"] = ""; changed = True
        if "ping" not in c:
            c["ping"] = "---"; changed = True
        if "status" not in c:
            c["status"] = "Ready"; changed = True
        if "last_state" not in c:
            c["last_state"] = "UNKNOWN"; changed = True
        if "last_alert_ts" not in c:
            c["last_alert_ts"] = 0; changed = True

        # freeze + uptime fields (canonical)
        if "manual_frozen" not in c:
            c["manual_frozen"] = False; changed = True
        if "frozen_until" not in c:
            c["frozen_until"] = 0; changed = True
        if "up_since" not in c:
            c["up_since"] = None; changed = True
        if "down_since" not in c:
            c["down_since"] = None; changed = True

    return changed


def cleanup_expired_freezes(configs: list):
    now_ts = time.time()
    changed = False
    for c in configs:
        if not isinstance(c, dict):
            continue
        try:
            fu = float(c.get("frozen_until", 0) or 0)
        except Exception:
            fu = 0
        if fu and fu <= now_ts:
            c["frozen_until"] = 0
            changed = True
    if changed:
        save_configs(configs)


def is_frozen(c: dict, now_ts: Optional[float] = None):
    if now_ts is None:
        now_ts = time.time()
    if bool(c.get("manual_frozen", False)):
        return True, None, True
    try:
        fu = float(c.get("frozen_until", 0) or 0)
    except Exception:
        fu = 0
    if fu and fu > now_ts:
        return True, max(0.0, fu - now_ts), False
    return False, 0.0, False


def update_uptime_state(c: dict, prev_state: str, new_state: str, ts: float):
    if prev_state != "OK" and new_state == "OK":
        c["up_since"] = ts
        c["down_since"] = None
    elif prev_state == "OK" and new_state != "OK":
        c["down_since"] = ts
        c["up_since"] = None


# -------------------- Daemon --------------------
class AmorMonitorServer:
    def __init__(self):
        self.cfg_lock = threading.Lock()
        self.testing_lock = threading.Lock()
        self.is_testing_now = False

        self.tg_lock = threading.Lock()
        self.last_dashboard_push = 0.0
        self.tg_update_offset: Optional[int] = None

        self.stop_event = threading.Event()

        ensure_telegram_file_exists()
        self.tg_cfg = load_telegram_settings()
        self.tunnel = TelegramTunnel()

        self.configs = load_configs()
        if ensure_ids_and_state(self.configs):
            save_configs(self.configs)

        self.last_test_ts = "—"
        self.last_round_ok_links: List[Tuple[str, Optional[int]]] = []  # [(link, ping_ms)]

        # Defaults; can override via env:
        try:
            saved_auto_min = int(self.tg_cfg.get("auto_minutes", 10) or 10)
        except Exception:
            saved_auto_min = 10
        try:
            saved_workers = int(self.tg_cfg.get("max_workers", MAX_WORKERS_DEFAULT) or MAX_WORKERS_DEFAULT)
        except Exception:
            saved_workers = MAX_WORKERS_DEFAULT

        self.auto_enabled = bool(self.tg_cfg.get("auto_enabled", True))
        env_auto = str(os.environ.get("AUTO_MINUTES", "") or "").strip()
        env_workers = str(os.environ.get("MAX_WORKERS", "") or "").strip()

        self.auto_interval_sec = int(float(env_auto) * 60) if env_auto else int(saved_auto_min * 60)
        self.max_workers = int(env_workers) if env_workers else int(saved_workers)

    # ---------- First-run / interactive setup ----------
    def interactive_setup_if_needed(self):
        """
        Wizard runs only when needed:
          - missing bot_token/chat_id
          - configs.json empty
          - FORCE_SETUP=1
        """
        ensure_telegram_file_exists()
        if not os.path.exists(CONFIGS_FILE):
            save_configs([])

        if not sys.stdin.isatty():
            return

        force = _env_bool("FORCE_SETUP", False)
        self.tg_cfg = load_telegram_settings()
        self.configs = load_configs()
        ensure_ids_and_state(self.configs)

        needs = force
        if not str(self.tg_cfg.get("bot_token", "")).strip():
            needs = True
        if not str(self.tg_cfg.get("chat_id", "")).strip():
            needs = True
        if not self.configs:
            needs = True

        if not needs:
            return

        print("\n=== Amor Monitor Setup ===")
        print("You can press ENTER to skip any question.\n")

        # Telegram
        if not str(self.tg_cfg.get("bot_token", "")).strip():
            tok = input("Telegram bot token (from @BotFather): ").strip()
            if tok:
                self.tg_cfg["bot_token"] = tok
        if not str(self.tg_cfg.get("chat_id", "")).strip():
            cid = input("Telegram chat_id (numeric). If you don't know, send any msg to your bot then run /myid: ").strip()
            if cid:
                self.tg_cfg["chat_id"] = cid

        if str(self.tg_cfg.get("bot_token", "")).strip() and str(self.tg_cfg.get("chat_id", "")).strip():
            en = input("Enable Telegram? [Y/n]: ").strip().lower()
            if en in ("n", "no", "0", "off"):
                self.tg_cfg["enabled"] = False
            else:
                self.tg_cfg["enabled"] = True

        # Auto test settings
        try:
            cur_min = int(self.tg_cfg.get("auto_minutes", 10) or 10)
        except Exception:
            cur_min = 10
        s = input(f"Auto-test interval minutes (current={cur_min}): ").strip()
        if s:
            try:
                cur_min = max(1, int(float(s)))
            except Exception:
                pass
        self.tg_cfg["auto_minutes"] = cur_min

        ae = input(f"Auto-test enabled? [Y/n] (current={'ON' if self.tg_cfg.get('auto_enabled', True) else 'OFF'}): ").strip().lower()
        if ae in ("n", "no", "0", "off"):
            self.tg_cfg["auto_enabled"] = False
        elif ae in ("y", "yes", "1", "on", ""):
            self.tg_cfg["auto_enabled"] = True

        try:
            cur_workers = int(self.tg_cfg.get("max_workers", MAX_WORKERS_DEFAULT) or MAX_WORKERS_DEFAULT)
        except Exception:
            cur_workers = MAX_WORKERS_DEFAULT
        s = input(f"Concurrent tests (workers) (current={cur_workers}): ").strip()
        if s:
            try:
                cur_workers = max(1, min(32, int(float(s))))
            except Exception:
                pass
        self.tg_cfg["max_workers"] = cur_workers

        save_telegram_settings(self.tg_cfg)

        # Apply in runtime too
        self.auto_enabled = bool(self.tg_cfg.get("auto_enabled", True))
        self.auto_interval_sec = int(max(1, int(self.tg_cfg.get("auto_minutes", 10) or 10)) * 60)
        self.max_workers = int(max(1, int(self.tg_cfg.get("max_workers", MAX_WORKERS_DEFAULT) or MAX_WORKERS_DEFAULT)))

        # Configs input if empty
        if not self.configs:
            print("\nNo servers found in configs.json.")
            print("Paste your links (one per line). Finish with an empty line.\n")
            links = []
            while True:
                line = input().strip()
                if not line:
                    break
                if "://" in line:
                    links.append(line)
            if links:
                for l in links:
                    self._add_config(l, name=None, save_now=False)
                save_configs(self.configs)
                print(f"Saved {len(links)} server(s) into configs.json.\n")

        print("Setup done.\n")

    def _add_config(self, link: str, name: Optional[str] = None, save_now: bool = True) -> bool:
        link = (link or "").strip()
        if not link or "://" not in link:
            return False
        # Auto-infer name from link fragment (#...) when NAME is not provided.
        inferred = (name or "").strip() if name else ""
        if not inferred:
            inferred = extract_name_from_link(link)
        c = {
            "id": str(uuid.uuid4()),
            "name": inferred[:80] if inferred else link[:80],
            "link": link,
            "ping": "---",
            "status": "Ready",
            "last_state": "UNKNOWN",
            "last_alert_ts": 0,
            "manual_frozen": False,
            "frozen_until": 0,
            "up_since": None,
            "down_since": None,
            "added_at": int(time.time()),
        }
        self.configs.append(c)
        if save_now:
            save_configs(self.configs)
        return True

    def _parse_index(self, s: str) -> Optional[int]:
        try:
            i = int(s)
            if i < 1:
                return None
            return i - 1
        except Exception:
            return None

    def _set_scheduler_settings(self, *, auto_enabled=None, auto_minutes=None, max_workers=None):
        cfg = load_telegram_settings()
        if auto_enabled is not None:
            cfg["auto_enabled"] = bool(auto_enabled)
            self.auto_enabled = bool(auto_enabled)
        if auto_minutes is not None:
            try:
                m = max(1, int(float(auto_minutes)))
            except Exception:
                m = int(cfg.get("auto_minutes", 10) or 10)
            cfg["auto_minutes"] = m
            self.auto_interval_sec = int(m * 60)
        if max_workers is not None:
            try:
                w = max(1, min(32, int(float(max_workers))))
            except Exception:
                w = int(cfg.get("max_workers", MAX_WORKERS_DEFAULT) or MAX_WORKERS_DEFAULT)
            cfg["max_workers"] = w
            self.max_workers = int(w)
        save_telegram_settings(cfg)
        self.tg_cfg = cfg

    # ---------- Telegram routing ----------
    def _pick_tunnel_link(self) -> Optional[str]:
        if not self.last_round_ok_links:
            return None
        pick = str(self.tg_cfg.get("tunnel_pick", "best_ping")).lower()
        if pick == "first_ok":
            return self.last_round_ok_links[0][0]
        best = min(self.last_round_ok_links, key=lambda t: t[1] if t[1] is not None else 10**9)
        return best[0]

    def _get_telegram_proxies(self):
        if not self.tg_cfg.get("enabled"):
            return None
        mode = str(self.tg_cfg.get("telegram_mode", "direct")).lower().strip()
        if mode == "proxy":
            tp = str(self.tg_cfg.get("telegram_proxy", "") or "").strip()
            if not tp:
                return None
            return {"http": tp, "https": tp}
        if mode == "tunnel":
            link = self._pick_tunnel_link()
            if not link:
                return None
            keepalive = int(self.tg_cfg.get("tunnel_keepalive_sec", 60) or 60)
            return self.tunnel.get_proxies(link, keepalive)
        return None  # direct

    # ---------- Dashboard ----------
    def push_dashboard(self, force: bool = False):
        self.tg_cfg = load_telegram_settings()
        if not self.tg_cfg.get("enabled"):
            return
        now_ts = time.time()
        if (not force) and (now_ts - self.last_dashboard_push) < DASHBOARD_UPDATE_MIN_INTERVAL_SEC:
            return
        self.last_dashboard_push = now_ts
        threading.Thread(target=self._push_dashboard_worker, daemon=True).start()

    def _push_dashboard_worker(self):
        with self.tg_lock:
            self.tg_cfg = load_telegram_settings()
            chat_id = str(self.tg_cfg.get("chat_id", "")).strip()
            token = str(self.tg_cfg.get("bot_token", "")).strip()
            if not chat_id or not token:
                return

            proxies = self._get_telegram_proxies()
            with self.cfg_lock:
                text = build_dashboard_text(list(self.configs), self.last_test_ts, show_uptime=bool(self.tg_cfg.get("show_uptime", False)))
            mid = self.tg_cfg.get("dashboard_message_id", None)

            def _send_new(with_keyboard: bool) -> bool:
                payload = {
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
                if with_keyboard:
                    payload["reply_markup"] = build_dashboard_keyboard()
                resp = _tg_send_with_fallback(self.tg_cfg, payload, proxies=proxies)
                if isinstance(resp, dict) and resp.get("ok") and resp.get("result", {}).get("message_id"):
                    self.tg_cfg["dashboard_message_id"] = resp["result"]["message_id"]
                    save_telegram_settings(self.tg_cfg)
                    return True
                if DEBUG_ENABLED or bool(self.tg_cfg.get("debug", False)):
                    log.debug("Dashboard send failed: %s", resp)
                return False

            def _edit_existing(with_keyboard: bool) -> bool:
                payload = {
                    "chat_id": chat_id,
                    "message_id": mid,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
                if with_keyboard:
                    payload["reply_markup"] = build_dashboard_keyboard()
                resp = _tg_edit_with_fallback(self.tg_cfg, payload, proxies=proxies)
                ok = isinstance(resp, dict) and resp.get("ok")
                if (not ok) and (DEBUG_ENABLED or bool(self.tg_cfg.get("debug", False))):
                    log.debug("Dashboard edit failed: %s", resp)
                return ok

            if not mid:
                if _send_new(True):
                    return
                _send_new(False)
                return

            if _edit_existing(True):
                return
            if _edit_existing(False):
                return

            # If editing failed, reset and send a fresh message
            self.tg_cfg["dashboard_message_id"] = None
            save_telegram_settings(self.tg_cfg)
            if _send_new(True):
                return
            _send_new(False)

    # ---------- Alerts ----------
    def _maybe_collect_alert(self, c: dict, new_ping: str, new_state: str, now_ts: float, alerts_out: list):
        if not self.tg_cfg.get("enabled") or not self.tg_cfg.get("alerts_enabled", True):
            c["last_state"] = new_state
            return

        cooldown = int(self.tg_cfg.get("alert_cooldown_sec", DEFAULT_ALERT_COOLDOWN_SEC) or DEFAULT_ALERT_COOLDOWN_SEC)

        prev_state = str(c.get("last_state", "UNKNOWN"))
        last_alert_ts = float(c.get("last_alert_ts", 0) or 0)

        name = html.escape(str(c.get("name", "Unknown")))
        ping_show = html.escape(str(new_ping))

        if prev_state != "DOWN" and new_state == "DOWN":
            if (now_ts - last_alert_ts) >= cooldown:
                alerts_out.append(f"🔴 <b>ALERT</b>: <b>{name}</b> is <b>DOWN</b> (ping = <code>-1</code>)")
                c["last_alert_ts"] = now_ts

        if prev_state == "DOWN" and new_state == "OK" and self.tg_cfg.get("recovery_alerts", True):
            alerts_out.append(f"🟢 <b>RECOVERED</b>: <b>{name}</b> is back online — <code>{ping_show}</code>")

        c["last_state"] = new_state

    def _send_alerts_async(self, alerts: list):
        if not alerts:
            return

        def worker(msgs):
            cfg = load_telegram_settings()
            proxies = self._get_telegram_proxies()
            for m in msgs:
                tg_send_text(cfg, m, proxies=proxies)
                time.sleep(0.2)

        threading.Thread(target=worker, args=(alerts,), daemon=True).start()

    # ---------- Testing ----------
    def _run_one_round(self):
        cleanup_expired_freezes(self.configs)
        snapshot = list(self.configs)
        round_ts = time.time()

        def test_one(idx, link):
            r1 = run_xray_and_measure_delay(link)
            if r1 == "-1":
                r2 = run_xray_and_measure_delay(link)
                return idx, (r2 if r2 != "-1" else "-1")
            return idx, r1

        test_items = []
        for i, c in enumerate(snapshot):
            frozen, _, _ = is_frozen(c, round_ts)
            if frozen:
                continue
            link = c.get("link")
            if "://" not in str(link or ""):
                continue
            test_items.append((i, link))

        mw = max(1, min(64, int(self.max_workers or MAX_WORKERS_DEFAULT)))
        if not test_items:
            self.last_test_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_configs(self.configs)
            self.push_dashboard(force=True)
            return

        workers = min(mw, len(test_items))
        if workers <= 0:
            return

        self.tg_cfg = load_telegram_settings()
        alerts = []
        ok_links = []

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(test_one, i, link) for i, link in test_items]
            for fu in as_completed(futures):
                try:
                    idx, res = fu.result()
                except Exception:
                    continue

                if idx < len(self.configs):
                    c = self.configs[idx]
                    prev_state = str(c.get("last_state", "UNKNOWN"))

                    c["ping"] = res
                    is_ok = (res != "-1")
                    c["status"] = "✅ Connected" if is_ok else "🔴 Down"

                    if is_ok:
                        ms = _parse_ping_ms(res)
                        ok_links.append((c.get("link"), ms if ms is not None else 10**9))

                    new_state = "OK" if is_ok else "DOWN"
                    update_uptime_state(c, prev_state, new_state, time.time())
                    self._maybe_collect_alert(c, res, new_state, round_ts, alerts)

        ok_links.sort(key=lambda t: t[1])
        self.last_round_ok_links = ok_links

        save_configs(self.configs)
        self.last_test_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.push_dashboard()
        self._send_alerts_async(alerts)

    def trigger_test_async(self):
        with self.testing_lock:
            if self.is_testing_now:
                self.push_dashboard(force=True)
                return
            self.is_testing_now = True

        def worker():
            try:
                with self.cfg_lock:
                    self._run_one_round()
            finally:
                with self.testing_lock:
                    self.is_testing_now = False

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Bot commands ----------
    def _send_help(self, tg_cfg: dict, proxies):
        chat_id = str(tg_cfg.get("chat_id", "")).strip()
        if not chat_id:
            return
        help_text = (
            "🧭 <b>Commands</b>\n"
            "/status یا /refresh — بروزرسانی داشبورد\n"
            "/test — تست فوری\n"
            "/menu — منوی سریع\n"
            "/list — لیست شماره‌دار\n"
            "/add LINK [NAME] — اضافه کردن سرور\n"
            "/rename N NAME — تغییر اسم\n"
            "/del N — حذف سرور\n"
            "/freeze N [min] | /freeze all [min] — فریز\n"
            "/unfreeze N | /unfreeze all — آنفریز\n"
            "/uptime on|off — نمایش Uptime روی داشبورد\n"
            "/setinterval MIN — تنظیم زمان تست دوره‌ای\n"
            "/autotest on|off — روشن/خاموش تست دوره‌ای\n"
            "/workers N — تعداد تست همزمان\n"
            "/setchat CHAT_ID — بروزرسانی chat_id\n"
            "/settoken BOT_TOKEN — بروزرسانی توکن\n"
            "/setmode direct|proxy|tunnel — تغییر حالت تلگرام\n"
            "/setproxy socks5h://IP:PORT — تنظیم پروکسی تلگرام (برای mode=proxy)\n"
            "/resetdash — ریست داشبورد و ساخت پیام جدید\n"
            "/ping — تست پاسخ‌دهی\n"
            "/debug on|off — لاگ بیشتر\n"
            "/myid — نمایش chat_id فعلی\n"
        )
        tg_api_post("sendMessage", {
            "chat_id": chat_id,
            "text": help_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }, tg_cfg, proxies=proxies)

    def _send_menu(self, tg_cfg: dict, proxies):
        chat_id = str(tg_cfg.get("chat_id", "")).strip()
        if not chat_id:
            return
        kb = {
            "keyboard": [
                [{"text": "/status"}, {"text": "/test"}],
                [{"text": "/freeze all 10"}, {"text": "/unfreeze all"}],
                [{"text": "/setinterval 10"}, {"text": "/autotest off"}],
                [{"text": "/list"}, {"text": "/help"}],
            ],
            "resize_keyboard": True,
            "one_time_keyboard": False,
        }
        tg_api_post("sendMessage", {
            "chat_id": chat_id,
            "text": "🎛 <b>Menu</b>\nبا دکمه‌ها می‌تونی سریع دستور بزنی.",
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": kb,
        }, tg_cfg, proxies=proxies)

    def _set_telegram_mode(self, mode: str) -> str:
        mode = (mode or "").strip().lower()
        if mode not in ("direct", "proxy", "tunnel"):
            return "Usage: /setmode direct|proxy|tunnel"
        cfg = load_telegram_settings()
        cfg["telegram_mode"] = mode
        cfg["enabled"] = True
        save_telegram_settings(cfg)
        self.tg_cfg = cfg
        self.push_dashboard(force=True)
        return f"✅ telegram_mode set to {mode}"

    def _set_telegram_proxy(self, proxy: str) -> str:
        proxy = (proxy or "").strip()
        if not proxy:
            return "Usage: /setproxy socks5h://IP:PORT"
        cfg = load_telegram_settings()
        cfg["telegram_proxy"] = proxy
        cfg["telegram_mode"] = "proxy"
        cfg["enabled"] = True
        save_telegram_settings(cfg)
        self.tg_cfg = cfg
        self.push_dashboard(force=True)
        return "✅ telegram_proxy set and mode switched to proxy."

    def _reset_dashboard(self) -> str:
        cfg = load_telegram_settings()
        cfg["dashboard_message_id"] = None
        save_telegram_settings(cfg)
        self.tg_cfg = cfg
        self.push_dashboard(force=True)
        return "✅ Dashboard reset. Sending a new dashboard message…"

    def _set_debug(self, on: bool) -> str:
        cfg = load_telegram_settings()
        cfg["debug"] = bool(on)
        save_telegram_settings(cfg)
        self.tg_cfg = cfg
        return "✅ Debug is ON." if on else "✅ Debug is OFF."

    def _handle_command(self, txt: str, tg_cfg: dict, proxies):
        parts = (txt or "").strip().split()
        if not parts:
            return None
        cmd = parts[0].lower()

        if cmd in ("/status", "/refresh"):
            self.push_dashboard(force=True)
            return None

        if cmd == "/test":
            self.trigger_test_async()
            return "⏳ Test started."

        if cmd in ("/start", "/help"):
            self._send_help(tg_cfg, proxies)
            return None

        if cmd == "/menu":
            self._send_menu(tg_cfg, proxies)
            return None

        if cmd == "/ping":
            return "🏓 pong"

        if cmd == "/debug":
            if len(parts) < 2:
                return "Usage: /debug on | /debug off"
            arg = parts[1].lower()
            if arg not in ("on", "off"):
                return "Usage: /debug on | /debug off"
            return self._set_debug(arg == "on")

        if cmd == "/resetdash":
            return self._reset_dashboard()

        if cmd == "/setmode":
            if len(parts) < 2:
                return "Usage: /setmode direct|proxy|tunnel"
            return self._set_telegram_mode(parts[1])

        if cmd == "/setproxy":
            if len(parts) < 2:
                return "Usage: /setproxy socks5h://IP:PORT"
            return self._set_telegram_proxy(parts[1])

        if cmd == "/myid":
            return f"🆔 chat_id: <code>{html.escape(str(tg_cfg.get('chat_id','')))}</code>"

        if cmd == "/setchat":
            if len(parts) < 2:
                return "Usage: /setchat CHAT_ID"
            cfg = load_telegram_settings()
            cfg["chat_id"] = parts[1].strip()
            cfg["enabled"] = True
            save_telegram_settings(cfg)
            self.tg_cfg = cfg
            self.push_dashboard(force=True)
            return "✅ chat_id updated."

        if cmd == "/settoken":
            if len(parts) < 2:
                return "Usage: /settoken BOT_TOKEN"
            cfg = load_telegram_settings()
            cfg["bot_token"] = parts[1].strip()
            cfg["enabled"] = True
            cfg["dashboard_message_id"] = None
            save_telegram_settings(cfg)
            self.tg_cfg = cfg
            self.push_dashboard(force=True)
            return "✅ bot_token updated."

        if cmd == "/setinterval":
            if len(parts) < 2:
                return "Usage: /setinterval MINUTES"
            try:
                m = max(1, int(float(parts[1])))
            except Exception:
                return "Minutes must be a number. Example: /setinterval 10"
            self._set_scheduler_settings(auto_minutes=m, auto_enabled=True)
            return f"✅ Auto-test interval set to {m} min (enabled)."

        if cmd == "/autotest":
            if len(parts) < 2:
                return "Usage: /autotest on | /autotest off"
            arg = parts[1].lower()
            if arg not in ("on", "off"):
                return "Usage: /autotest on | /autotest off"
            self._set_scheduler_settings(auto_enabled=(arg == "on"))
            return "✅ Auto-test is ON." if arg == "on" else "✅ Auto-test is OFF."

        if cmd == "/workers":
            if len(parts) < 2:
                return "Usage: /workers N"
            try:
                w = max(1, min(32, int(float(parts[1]))))
            except Exception:
                return "Workers must be a number. Example: /workers 5"
            self._set_scheduler_settings(max_workers=w)
            return f"✅ Concurrent workers set to {w}."

        if cmd == "/add":
            if len(parts) < 2:
                return "Usage: /add LINK [NAME]"
            link = parts[1].strip()
            name = " ".join(parts[2:]).strip() if len(parts) > 2 else None
            ok = self._add_config(link, name=name, save_now=True)
            if not ok:
                return "❌ Invalid link."
            self.push_dashboard(force=True)
            return "✅ Added."

        if cmd == "/rename":
            if len(parts) < 3:
                return "Usage: /rename N NEW_NAME"
            idx = self._parse_index(parts[1])
            if idx is None:
                return "Invalid N. Example: /rename 1 MyServer"
            with self.cfg_lock:
                if idx >= len(self.configs):
                    return "Out of range."
                self.configs[idx]["name"] = " ".join(parts[2:]).strip()[:80]
                save_configs(self.configs)
            self.push_dashboard(force=True)
            return "✅ Renamed."

        if cmd == "/list":
            with self.cfg_lock:
                if not self.configs:
                    return "No servers."
                now_ts = time.time()
                lines = []
                for i, c in enumerate(self.configs, start=1):
                    nm = html.escape(str(c.get("name","")))
                    ping = html.escape(str(c.get("ping","—")))
                    frozen, _, _ = is_frozen(c, now_ts)
                    frz = " ❄️" if frozen else ""
                    lines.append(f"{i}) <b>{nm}</b> — <code>{ping}</code>{frz}")
                msg = "\n".join(lines)
            return msg[:3900]

        if cmd == "/uptime":
            if len(parts) < 2:
                return "Usage: /uptime on | /uptime off"
            arg = parts[1].lower()
            if arg not in ("on", "off"):
                return "Usage: /uptime on | /uptime off"
            cfg = load_telegram_settings()
            cfg["show_uptime"] = (arg == "on")
            save_telegram_settings(cfg)
            self.tg_cfg = cfg
            self.push_dashboard(force=True)
            return "✅ Uptime is ON on dashboard." if arg == "on" else "✅ Uptime is OFF on dashboard."

        if cmd == "/freeze":
            if len(parts) < 2:
                return "Usage: /freeze N [min] | /freeze all [min]"
            target = parts[1].lower()
            minutes = None
            if len(parts) >= 3:
                try:
                    minutes = int(float(parts[2]))
                except Exception:
                    return "Minutes must be a number. Example: /freeze 1 30"
                if minutes <= 0:
                    minutes = None

            with self.testing_lock:
                if self.is_testing_now:
                    return "⛔ Busy testing right now. Try again after it finishes."

            now_ts = time.time()

            with self.cfg_lock:
                if target == "all":
                    for c in self.configs:
                        if minutes is None:
                            c["manual_frozen"] = True
                            c["frozen_until"] = 0
                        else:
                            c["manual_frozen"] = False
                            c["frozen_until"] = now_ts + minutes * 60
                    save_configs(self.configs)
                else:
                    try:
                        n = int(target)
                    except Exception:
                        return "Usage: /freeze N [min] | /freeze all [min]"
                    idx = n - 1
                    if idx < 0 or idx >= len(self.configs):
                        return f"Server number out of range. Valid: 1..{len(self.configs)}"
                    c = self.configs[idx]
                    if minutes is None:
                        c["manual_frozen"] = True
                        c["frozen_until"] = 0
                    else:
                        c["manual_frozen"] = False
                        c["frozen_until"] = now_ts + minutes * 60
                    save_configs(self.configs)

            self.push_dashboard(force=True)
            if target == "all":
                return "🧊 Frozen ALL servers." if minutes is None else f"🧊 Frozen ALL servers for {minutes} minutes."
            else:
                return f"🧊 Frozen server {target}." if minutes is None else f"🧊 Frozen server {target} for {minutes} minutes."

        if cmd == "/unfreeze":
            if len(parts) < 2:
                return "Usage: /unfreeze N | /unfreeze all"
            target = parts[1].lower()

            with self.testing_lock:
                if self.is_testing_now:
                    return "⛔ Busy testing right now. Try again after it finishes."

            with self.cfg_lock:
                if target == "all":
                    for c in self.configs:
                        c["manual_frozen"] = False
                        c["frozen_until"] = 0
                    save_configs(self.configs)
                else:
                    try:
                        n = int(target)
                    except Exception:
                        return "Usage: /unfreeze N | /unfreeze all"
                    idx = n - 1
                    if idx < 0 or idx >= len(self.configs):
                        return f"Server number out of range. Valid: 1..{len(self.configs)}"
                    c = self.configs[idx]
                    c["manual_frozen"] = False
                    c["frozen_until"] = 0
                    save_configs(self.configs)

            self.push_dashboard(force=True)
            return "✅ Unfrozen ALL servers." if target == "all" else f"✅ Unfrozen server {target}."

        if cmd == "/del":
            if len(parts) < 2:
                return "Usage: /del N"

            with self.testing_lock:
                if self.is_testing_now:
                    return "⛔ Busy testing right now. Try again after it finishes."

            try:
                n = int(parts[1])
            except Exception:
                return "Usage: /del N"

            with self.cfg_lock:
                idx = n - 1
                if idx < 0 or idx >= len(self.configs):
                    return f"Server number out of range. Valid: 1..{len(self.configs)}"
                removed = self.configs.pop(idx)
                save_configs(self.configs)

            self.push_dashboard(force=True)
            name = str(removed.get("name", "server"))
            return f"🗑 Deleted server {n}: {html.escape(name)}"

        return "Unknown command. Use /help"

    # ---------- Bot listener ----------
    def _maybe_bind_chat(self, cid: str, proxies):
        cid = str(cid or "").strip()
        if not cid:
            return None
        cfg2 = load_telegram_settings()
        if str(cfg2.get("chat_id", "")).strip():
            return str(cfg2.get("chat_id", "")).strip()
        cfg2["chat_id"] = cid
        cfg2["enabled"] = True
        save_telegram_settings(cfg2)
        self.tg_cfg = cfg2
        try:
            tg_send_text(cfg2, "✅ chat_id ذخیره شد. حالا /help رو بزن.", proxies=proxies)
        except Exception:
            pass
        return cid

    def bot_listener_loop(self):
        while not self.stop_event.is_set():
            try:
                tg_cfg = load_telegram_settings()
                if not tg_cfg.get("enabled"):
                    self.stop_event.wait(2.0)
                    continue

                chat_id_allowed = str(tg_cfg.get("chat_id", "")).strip()
                token = str(tg_cfg.get("bot_token", "")).strip()
                if not token:
                    self.stop_event.wait(2.0)
                    continue

                self.tg_cfg = tg_cfg
                proxies = self._get_telegram_proxies()
                resp = tg_api_get_updates(tg_cfg, offset=self.tg_update_offset, timeout=25, proxies=proxies)
                if not resp or not isinstance(resp, dict) or not resp.get("ok"):
                    if DEBUG_ENABLED or bool(tg_cfg.get("debug", False)):
                        log.debug("getUpdates failed: %s", resp)
                    self.stop_event.wait(2.0)
                    continue

                updates = resp.get("result", []) or []
                for upd in updates:
                    try:
                        uid = upd.get("update_id")
                        if uid is not None:
                            self.tg_update_offset = int(uid) + 1
                    except Exception:
                        pass

                    # Callback query (inline buttons)
                    if "callback_query" in upd:
                        cq = upd.get("callback_query", {}) or {}
                        data = str(cq.get("data", "") or "")
                        msg = cq.get("message", {}) or {}
                        chat = msg.get("chat", {}) or {}
                        cid = str(chat.get("id", "")).strip()

                        if chat_id_allowed and cid != chat_id_allowed:
                            continue
                        if (not chat_id_allowed) and cid:
                            chat_id_allowed = self._maybe_bind_chat(cid, proxies) or chat_id_allowed

                        try:
                            tg_api_post("answerCallbackQuery", {"callback_query_id": cq.get("id")}, tg_cfg, proxies=proxies)
                        except Exception:
                            pass

                        if data == "TEST_NOW":
                            self.trigger_test_async()
                        elif data == "REFRESH":
                            self.push_dashboard(force=True)
                        elif data == "HELP":
                            self._send_help(tg_cfg, proxies)
                        elif data == "RESET_DASH":
                            self._reset_dashboard()
                        continue

                    # Normal messages
                    msg = upd.get("message") or upd.get("edited_message")
                    if not msg:
                        continue

                    chat = msg.get("chat", {}) or {}
                    cid = str(chat.get("id", "")).strip()

                    # Access control / first-time bind
                    if chat_id_allowed:
                        if cid != chat_id_allowed:
                            continue
                    else:
                        if cid:
                            chat_id_allowed = self._maybe_bind_chat(cid, proxies) or chat_id_allowed

                    txt = str(msg.get("text", "") or "").strip()
                    if not txt:
                        continue

                    reply = self._handle_command(txt, tg_cfg, proxies)
                    if reply:
                        tg_send_text(tg_cfg, reply, proxies=proxies)

            except Exception as e:
                if DEBUG_ENABLED:
                    log.debug("bot listener exception: %s\n%s", e, traceback.format_exc())
                self.stop_event.wait(2.0)

    # ---------- Main loop ----------
    def run(self):
        # Quick prechecks (non-fatal; allow running for Telegram-only commands)
        if requests is None:
            log.warning("Missing dependency: pip install requests pysocks")
        if not _xray_available():
            log.warning("xray not found. Put ./xray next to this script or install xray in PATH (or set XRAY_PATH).")

        # Start bot listener thread
        threading.Thread(target=self.bot_listener_loop, daemon=True).start()

        # Push dashboard on start (so you immediately get the list)
        self.push_dashboard(force=True)

        # Initial test (so tunnel mode can work if user switches later)
        self.trigger_test_async()

        next_run = time.time() + max(30, int(self.auto_interval_sec))
        while not self.stop_event.is_set():
            if self.auto_enabled and time.time() >= next_run:
                self.trigger_test_async()
                next_run = time.time() + max(30, int(self.auto_interval_sec))
            self.stop_event.wait(1.0)

        # cleanup
        try:
            self.tunnel.stop()
        except Exception:
            pass


def main():
    server = AmorMonitorServer()
    server.interactive_setup_if_needed()

    def _handle_stop(signum, frame):
        server.stop_event.set()

    try:
        signal.signal(signal.SIGTERM, _handle_stop)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGINT, _handle_stop)
    except Exception:
        pass

    server.run()


if __name__ == "__main__":
    main()
