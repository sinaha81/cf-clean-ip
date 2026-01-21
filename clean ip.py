import os
import json
import time
import queue
import base64
import shutil
import signal
import socket
import threading
import subprocess
import random
import math
import atexit
import sys
import tempfile  # Added for Performance Tuning
from pathlib import Path
from urllib.parse import urlparse, unquote
from datetime import datetime
import ipaddress

import requests
import customtkinter as ctk  # UI Library
from tkinter import messagebox

# =========================
# SYSTEM CONFIGURATION
# =========================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# =========================
# User settings / files
# =========================
PROJECT_ROOT = Path(".").resolve()
INPUT_FILE = PROJECT_ROOT / "input.txt"
IP_FILE = PROJECT_ROOT / "ip4.txt"
CONFIG_DIR = PROJECT_ROOT / "configs" # Kept for fallback, but main logic uses temp
REPORT_FILE = PROJECT_ROOT / "report.log"

# Base name for clean IP outputs
CLEAN_IP_BASENAME = "clean_ip"
CLEAN_IP_EXT = ".txt"

# Default Constraints
HTTP_TIMEOUT = 10.0
SOCKS_READY_TIMEOUT = 6.0
XRAY_BOOT_GRACE = 0.3
BASE_LOCAL_PORT = 30000
PRETTY_JSON = True

# Advanced Logic Defaults
TCP_PREFILTER = True
TCP_PREFILTER_TIMEOUT = 0.8
TCP_PREFILTER_RETRIES = 2

TEST_ENDPOINTS = [
    "https://speed.cloudflare.com/__down?bytes={n}",
    "https://cf.loxal.net/__down?bytes={n}",
    "https://detectportal.firefox.com/success.txt",
    "https://example.com/",
]

UPLOAD_ENDPOINTS = [
    "https://httpbin.org/post",
    "https://postman-echo.com/post",
]

XRAY_CANDIDATES = [
    PROJECT_ROOT / "xray.exe",
    PROJECT_ROOT / "vendor" / "xray.exe",
    PROJECT_ROOT / "core_engine" / "xray.exe",
    PROJECT_ROOT / "xray",
    PROJECT_ROOT / "vendor" / "xray",
    PROJECT_ROOT / "core_engine" / "xray",
]

# ---------- Shared State ----------
overall_good_ips = set()
good_ips_lock = threading.Lock()
shutdown_flag = threading.Event()

# UI Communication Queues
log_queue = queue.Queue()
result_queue = queue.Queue()
progress_queue = queue.Queue()

# =========================
# CORE LOGIC (UNCHANGED & ROBUST)
# =========================

def _ip_sort_key(ipstr: str):
    return tuple(int(p) for p in ipstr.split("."))

def select_clean_ip_file(basename: str = CLEAN_IP_BASENAME, ext: str = CLEAN_IP_EXT, root: Path = PROJECT_ROOT) -> Path:
    candidate = root / f"{basename}{ext}"
    if not candidate.exists():
        return candidate
    i = 1
    while True:
        cand = root / f"{basename}_{i}{ext}"
        if not cand.exists():
            return cand
        i += 1

CLEAN_IP_FILE = select_clean_ip_file()

def write_clean_ips_atomic(ips_set: set[str]):
    if not ips_set:
        return
    CLEAN_IP_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CLEAN_IP_FILE.with_suffix(CLEAN_IP_FILE.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fc:
        for ip in sorted(ips_set, key=_ip_sort_key):
            fc.write(ip + "\n")
    try:
        tmp.replace(CLEAN_IP_FILE)
    except Exception:
        pass

def persist_now():
    with good_ips_lock:
        write_clean_ips_atomic(overall_good_ips)

def handle_signal(signum, frame):
    log_queue.put(f"[SYSTEM] Signal {signum} received. Saving...")
    shutdown_flag.set()
    persist_now()

signal.signal(signal.SIGINT, handle_signal)
try:
    signal.signal(signal.SIGTERM, handle_signal)
except:
    pass

@atexit.register
def _on_exit():
    persist_now()
    try:
        cleanup_configs()
    except:
        pass

# ---------- Report Logic ----------
def read_completed_ranges_from_report() -> set[str]:
    done = set()
    if not REPORT_FILE.exists():
        return done
    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("✅"):
                    parts = s.split(" ", 1)
                    if len(parts) == 2:
                        done.add(parts[1].strip())
    except:
        pass
    return done

def append_done_to_report(label_raw: str):
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        already = False
        if REPORT_FILE.exists():
            with open(REPORT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() == f"✅ {label_raw}":
                        already = True
                        break
        if not already:
            with open(REPORT_FILE, "a", encoding="utf-8") as f:
                f.write(f"✅ {label_raw}\n")
    except:
        pass

# ---------- Helpers ----------
def find_xray_binary() -> Path:
    for p in XRAY_CANDIDATES:
        if p.exists(): return p
    x = shutil.which("xray.exe") or shutil.which("xray")
    if x: return Path(x)
    raise FileNotFoundError("xray binary not found!")

def parse_qs_flat(u):
    raw = u.query if hasattr(u, "query") else str(u)
    result = {}
    if not raw: return result
    for pair in raw.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k] = unquote(v)
        else:
            result[pair] = ""
    return result

def ensure_leading_slash(p: str | None) -> str:
    if not p: return "/"
    p = unquote(p)
    return p if p.startswith("/") else ("/" + p)

def b64_decode(data: str) -> str:
    data = data.strip().replace("-", "+").replace("_", "/")
    pad = len(data) % 4
    if pad: data += "=" * (4 - pad)
    return base64.b64decode(data).decode("utf-8", errors="ignore")

def wait_until_listening(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                s.close()
                return True
        finally:
            s.close()
        time.sleep(0.1)
    return False

def quick_tcp_check(ip: str, port: int, timeout: float, retries: int = 1) -> bool:
    for _ in range(max(1, retries)):
        if shutdown_flag.is_set(): return False
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except:
            continue
    return False

# ---------- GEOIP Logic (Added) ----------
def get_ip_info(ip: str) -> dict:
    """Fetches Country and ISP info for the IP."""
    try:
        # Using ip-api.com (free, no key needed for low usage)
        # In a high-throughput enterprise scenario, use geoip2 local DB.
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("countryCode", "UNK"),
                    "isp": data.get("isp", "Unknown ISP")
                }
    except:
        pass
    return {"country": "--", "isp": "--"}

# ---------- Protocol Parsers (FULL LOGIC) ----------
def parse_vless(uri: str) -> dict:
    u = urlparse(uri)
    q = parse_qs_flat(u)
    return {
        "proto": "vless", "uuid": u.username or "", "host": u.hostname, "port": int(u.port or 443),
        "security": (q.get("security", "none") or "none").lower(), "sni": q.get("sni"),
        "alpn": [p.strip() for p in (q.get("alpn", "") or "").split(",") if p.strip()] or None,
        "transport": (q.get("type") or "").lower() or None, "host_header": q.get("host"),
        "path": ensure_leading_slash(q.get("path")), "tag": unquote(u.fragment) if u.fragment else None,
        "encryption": q.get("encryption", "none"),
    }

def parse_vmess(uri: str) -> dict:
    payload = uri[len("vmess://") :]
    d = json.loads(b64_decode(payload))
    alpn_raw = d.get("alpn")
    if isinstance(alpn_raw, list): alpn = [str(x).strip() for x in alpn_raw if str(x).strip()]
    elif isinstance(alpn_raw, str) and alpn_raw.strip(): alpn = [p.strip() for p in alpn_raw.split(",") if p.strip()]
    else: alpn = None
    return {
        "proto": "vmess", "uuid": d.get("id"), "aid": int(d.get("aid", 0) if str(d.get("aid", "0")).isdigit() else 0),
        "cipher": d.get("scy") or "auto", "host": d.get("add"), "port": int(d.get("port", 443)),
        "security": "tls" if str(d.get("tls", "")).lower() in ("tls", "reality") else "none",
        "sni": d.get("sni"), "alpn": alpn, "transport": (d.get("net") or "").lower() or None,
        "host_header": d.get("host") or d.get("sni"), "path": ensure_leading_slash(d.get("path")), "tag": d.get("ps"),
    }

def parse_trojan(uri: str) -> dict:
    u = urlparse(uri)
    q = parse_qs_flat(u)
    return {
        "proto": "trojan", "password": u.username or "", "host": u.hostname, "port": int(u.port or 443),
        "security": (q.get("security", "tls") or "tls").lower(), "sni": q.get("sni"),
        "alpn": [p.strip() for p in (q.get("alpn", "") or "").split(",") if p.strip()] or None,
        "transport": (q.get("type") or "").lower() or None, "host_header": q.get("host"),
        "path": ensure_leading_slash(q.get("path")), "tag": unquote(u.fragment) if u.fragment else None,
    }

def parse_ss(uri: str) -> dict:
    u = urlparse(uri)
    host, port = u.hostname, u.port or 8388
    method, password = None, None
    if u.username and u.password:
        method, password = unquote(u.username), unquote(u.password)
    else:
        body = uri[len("ss://") :].split("#", 1)[0]
        try:
            decoded = b64_decode(body)
            if "@" in decoded and ":" in decoded:
                c, _ = decoded.split("@", 1); method, password = c.split(":", 1)
            elif ":" in decoded: method, password = decoded.split(":", 1)
        except: pass
    if not (method and password and host and port): raise ValueError("Invalid SS URI")
    return {"proto": "ss", "method": method, "password": password, "host": host, "port": int(port), "tag": unquote(u.fragment) if u.fragment else None}

def parse_hysteria2(uri: str) -> dict:
    u = urlparse(uri)
    q = parse_qs_flat(u)
    return {
        "proto": "hysteria2", "auth": u.username or "", "host": u.hostname, "port": int(u.port or 443),
        "sni": q.get("sni"), "alpn": [p.strip() for p in (q.get("alpn", "") or "").split(",") if p.strip()] or None,
        "insecure": str(q.get("insecure", "0")).strip().lower() in ("1", "true"), "tag": unquote(u.fragment) if u.fragment else None,
    }

def parse_uri_generic(uri: str) -> dict:
    low = uri.lower()
    if low.startswith("vless://"): return parse_vless(uri)
    if low.startswith("vmess://"): return parse_vmess(uri)
    if low.startswith("trojan://"): return parse_trojan(uri)
    if low.startswith("ss://"): return parse_ss(uri)
    if low.startswith("hysteria2://") or low.startswith("hy2://"): return parse_hysteria2(uri)
    raise ValueError("Unsupported scheme")

# ---------- Config Builders ----------
def inbound_socks(port: int) -> dict:
    return {
        "tag": "socks-in", "port": port, "listen": "127.0.0.1", "protocol": "socks",
        "settings": {"udp": True, "auth": "noauth"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }

def build_stream_settings(parsed: dict, force_tls: bool = False) -> dict:
    stream = {}
    is_tls = force_tls or parsed.get("security", "none") in ("tls", "reality")
    if is_tls:
        stream["security"] = "tls"
        tls = {}
        sni = parsed.get("sni") or parsed.get("host_header") or parsed.get("host")
        if sni: tls["serverName"] = sni
        tls["nextProto"] = parsed.get("alpn") or ["h2", "http/1.1"]
        tls["fingerprint"] = "chrome"
        if tls: stream["tlsSettings"] = tls
    net = parsed.get("transport")
    if net in ("ws", "httpupgrade", "xhttp"):
        stream["network"] = net
        if net == "ws":
            ws = {"path": parsed.get("path", "/")}
            if parsed.get("host_header"): ws["headers"] = {"Host": parsed["host_header"]}
            stream["wsSettings"] = ws
        elif net == "httpupgrade":
            hu = {}
            if parsed.get("path"): hu["path"] = parsed["path"]
            if parsed.get("host_header"): hu["host"] = parsed["host_header"]
            stream["httpupgradeSettings"] = hu
        elif net == "xhttp":
            xh = {}
            if parsed.get("path"): xh["path"] = parsed["path"]
            if parsed.get("host_header"): xh["host"] = parsed["host_header"]
            stream["xhttpSettings"] = xh
    return stream

def build_outbound(parsed: dict) -> dict:
    p = parsed["proto"]
    stream = build_stream_settings(parsed, force_tls=(p == "trojan"))
    if p == "vless":
        out = {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": parsed["host"], "port": parsed["port"], "users": [{"id": parsed["uuid"], "encryption": parsed.get("encryption", "none")}]}]}}
        if stream: out["streamSettings"] = stream
        return out
    if p == "vmess":
        out = {"tag": "proxy", "protocol": "vmess", "settings": {"vnext": [{"address": parsed["host"], "port": parsed["port"], "users": [{"id": parsed["uuid"], "alterId": parsed.get("aid", 0), "security": parsed.get("cipher", "auto")}]}]}}
        if stream: out["streamSettings"] = stream
        return out
    if p == "trojan":
        out = {"tag": "proxy", "protocol": "trojan", "settings": {"servers": [{"address": parsed["host"], "port": parsed["port"], "password": parsed["password"]}]}}
        if stream: out["streamSettings"] = stream
        return out
    if p == "ss":
        return {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [{"address": parsed["host"], "port": parsed["port"], "method": parsed["method"], "password": parsed["password"]}]}}
    if p == "hysteria2":
        out = {"tag": "proxy", "protocol": "hysteria2", "settings": {"server": parsed["host"], "serverPort": parsed["port"], "password": parsed["auth"]}}
        tls_set = {"serverName": parsed.get("sni") or parsed.get("host_header") or parsed.get("host"), "nextProto": parsed.get("alpn") or ["h2", "http/1.1"]}
        out["streamSettings"] = {"network": "quic", "security": "tls", "tlsSettings": tls_set}
        return out
    raise ValueError(f"Unknown proto: {p}")

def build_one_config(parsed: dict, local_socks_port: int) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": [{"address": "https+local://1.1.1.1/dns-query"}, {"address": "https+local://8.8.8.8/dns-query"}, "localhost"], "queryStrategy": "UseIP"},
        "inbounds": [inbound_socks(local_socks_port)],
        "outbounds": [build_outbound(parsed), {"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}],
        "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]},
    }

def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2 if PRETTY_JSON else None)

def run_xray(xray_path: Path, json_path: Path) -> subprocess.Popen:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.Popen([str(xray_path), "-c", str(json_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)

# ---------- Network Testers (Performance & Ping) ----------
def try_download_with_ping(port: int, bytes_to_dl: int, timeout_override: float = None, deadline_ts: float = None) -> tuple[bool, int]:
    """Returns (Success, Ping_ms)"""
    if bytes_to_dl < 1: return False, -1
    proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    for url_tpl in TEST_ENDPOINTS:
        if deadline_ts and (deadline_ts - time.time()) <= 0: return False, -1
        url = url_tpl.format(n=bytes_to_dl) if "{n}" in url_tpl else url_tpl
        try:
            to = min(HTTP_TIMEOUT, timeout_override or HTTP_TIMEOUT)
            if deadline_ts: to = min(to, deadline_ts - time.time())
            if to <= 0: return False, -1
            
            # PING Measurement Start
            start_t = time.time()
            r = requests.get(url, proxies=proxies, timeout=to, stream=True)
            # Time to headers is our "Ping"
            latency = int((time.time() - start_t) * 1000)
            
            if r.status_code != 200:
                r.close(); continue
            read_total = 0
            for chunk in r.iter_content(chunk_size=min(8192, bytes_to_dl)):
                if not chunk: break
                read_total += len(chunk)
                if read_total >= bytes_to_dl or (deadline_ts and time.time() >= deadline_ts): break
            r.close()
            if read_total >= bytes_to_dl: return True, latency
        except: pass
    return False, -1

def try_upload(port: int, bytes_to_ul: int, timeout_override: float = None, deadline_ts: float = None) -> bool:
    if bytes_to_ul < 1: return False
    proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    payload = b"x" * bytes_to_ul
    headers = {"Content-Type": "application/octet-stream"}
    for url in UPLOAD_ENDPOINTS:
        if deadline_ts and (deadline_ts - time.time()) <= 0: return False
        try:
            to = min(HTTP_TIMEOUT, timeout_override or HTTP_TIMEOUT)
            if deadline_ts: to = min(to, deadline_ts - time.time())
            if to <= 0: return False
            r = requests.post(url, data=payload, headers=headers, proxies=proxies, timeout=to)
            status = r.status_code; r.close()
            if status in (200, 201, 202): return True
        except: pass
    return False

# ---------- Worker Thread (Optimized) ----------
def worker(task_queue, xray_path, dl_bytes, ul_bytes, retries, time_budget, require_both):
    # PERFORMANCE TUNING: Use Temp Directory for Configs
    # This reduces disk I/O significantly
    temp_dir = tempfile.mkdtemp(prefix="xray_scan_")
    
    try:
        while not shutdown_flag.is_set():
            try:
                idx, uri, ip = task_queue.get_nowait()
            except queue.Empty:
                break

            ok = False
            proc = None
            ping_ms = -1
            geo_info = {"country": "", "isp": ""}
            local_port = BASE_LOCAL_PORT + (idx % 40000)

            try:
                parsed = parse_uri_generic(uri)
                parsed["host"] = ip
                
                # TCP Prefilter
                if TCP_PREFILTER and parsed.get("port"):
                    if not quick_tcp_check(ip, int(parsed["port"]), TCP_PREFILTER_TIMEOUT, TCP_PREFILTER_RETRIES):
                        raise RuntimeError("TCP_FAIL")

                conf = build_one_config(parsed, local_port)
                # Use temp path
                json_path = Path(temp_dir) / f"cfg_{idx}_{ip}.json"
                write_json(json_path, conf)

                proc = run_xray(xray_path, json_path)
                time.sleep(XRAY_BOOT_GRACE)
                if not wait_until_listening(local_port, SOCKS_READY_TIMEOUT):
                    raise RuntimeError("SOCKS_FAIL")

                dl_deadline = (time.time() + time_budget) if time_budget > 0 else None
                ul_deadline = (time.time() + time_budget) if time_budget > 0 else None
                dl_ok = False
                ul_ok = False

                for attempt in range(1, max(1, retries) + 1):
                    if shutdown_flag.is_set(): break
                    
                    if dl_bytes > 0 and not dl_ok:
                        dl_ok, p_ms = try_download_with_ping(local_port, dl_bytes, deadline_ts=dl_deadline)
                        if dl_ok: ping_ms = p_ms
                    
                    if ul_bytes > 0 and not ul_ok:
                        ul_ok = try_upload(local_port, ul_bytes, deadline_ts=ul_deadline)

                    success_cond = (dl_ok and ul_ok) if require_both else (dl_ok or ul_ok)
                    if dl_bytes == 0: success_cond = ul_ok
                    if ul_bytes == 0: success_cond = dl_ok
                    
                    if success_cond: break
                    time.sleep(0.6 * attempt)

                ok = success_cond

            except Exception:
                ok = False
            finally:
                if proc:
                    try:
                        if os.name == "nt": proc.send_signal(signal.SIGTERM)
                        else: proc.terminate()
                        proc.wait(timeout=2)
                    except:
                        try: proc.kill()
                        except: pass
                
                # Cleanup temp file for this task
                try:
                    if 'json_path' in locals() and json_path.exists():
                        json_path.unlink()
                except: pass
                
                if ok:
                    # Fetch GEO IP info on success
                    geo_info = get_ip_info(ip)
                    
                    with good_ips_lock:
                        overall_good_ips.add(ip)
                        write_clean_ips_atomic(overall_good_ips)
                    
                    # Put structured result: IP, Ping, Geo
                    result_queue.put({
                        "ip": ip,
                        "ping": ping_ms,
                        "geo": geo_info
                    })
                
                progress_queue.put(1)
                task_queue.task_done()
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

# ---------- IP Expansion ----------
def expand_ip_line(line: str):
    line = line.strip()
    if not line: return []
    if "/" in line:
        try: return [str(ip) for ip in ipaddress.ip_network(line, strict=False).hosts()]
        except: return []
    if "-" in line:
        try:
            s, e = line.split("-", 1)
            start, end = int(ipaddress.ip_address(s.strip())), int(ipaddress.ip_address(e.strip()))
            if end < start or (end - start) > 65536: raise ValueError
            return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
        except: return []
    try: ipaddress.ip_address(line); return [line]
    except: return []

def cleanup_configs():
    if CONFIG_DIR.exists():
        for f in CONFIG_DIR.iterdir():
            try: f.unlink()
            except: pass

# =========================
# MODERN UI (CustomTkinter)
# =========================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Config
        self.title("ULTIMATE PROXY TESTER - PRO EDITION")
        self.geometry("1100x800")
        self.minsize(900, 700)

        # Variables
        self.concurrency_var = ctk.StringVar(value="8")
        self.dl_bytes_var = ctk.StringVar(value="1")
        self.ul_bytes_var = ctk.StringVar(value="0")
        self.retries_var = ctk.StringVar(value="2")
        self.timeout_var = ctk.StringVar(value="8")
        self.percent_var = ctk.StringVar(value="100")
        self.shuffle_var = ctk.BooleanVar(value=False)
        
        self.is_scanning = False
        self.total_tasks = 0
        self.completed_tasks = 0
        self.clean_ips_count = 0

        # Layout Config
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # 1. Sidebar (Navigation)
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="PROXY\nSCANNER\nPRO", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=lambda: self.select_frame("dashboard"), fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.btn_config = ctk.CTkButton(self.sidebar_frame, text="Configuration", command=lambda: self.select_frame("config"), fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.btn_config.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_editor = ctk.CTkButton(self.sidebar_frame, text="File Editor", command=lambda: self.select_frame("editor"), fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.btn_editor.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        # Status Footer in Sidebar
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: IDLE", text_color="gray")
        self.status_label.grid(row=5, column=0, padx=20, pady=10)

        # 2. Main Frames
        self.dashboard_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.config_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.editor_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        self.setup_dashboard()
        self.setup_config()
        self.setup_editor()

        # Select default
        self.select_frame("dashboard")

        # Background Loop
        self.after(100, self.update_ui_loop)

        # File Init
        self.check_files()

    def select_frame(self, name):
        # Hide all
        self.dashboard_frame.grid_forget()
        self.config_frame.grid_forget()
        self.editor_frame.grid_forget()

        # Reset button colors
        self.btn_dashboard.configure(fg_color="transparent")
        self.btn_config.configure(fg_color="transparent")
        self.btn_editor.configure(fg_color="transparent")

        if name == "dashboard":
            self.dashboard_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            self.btn_dashboard.configure(fg_color=("gray75", "gray25"))
        elif name == "config":
            self.config_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            self.btn_config.configure(fg_color=("gray75", "gray25"))
        elif name == "editor":
            self.editor_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            self.btn_editor.configure(fg_color=("gray75", "gray25"))

    def setup_dashboard(self):
        # Top Stats
        self.dashboard_frame.grid_columnconfigure(0, weight=1)
        self.dashboard_frame.grid_columnconfigure(1, weight=1)
        self.dashboard_frame.grid_rowconfigure(3, weight=1)

        # Progress Section
        self.prog_frame = ctk.CTkFrame(self.dashboard_frame)
        self.prog_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        
        self.lbl_progress = ctk.CTkLabel(self.prog_frame, text="Progress: 0%", font=("Arial", 16, "bold"))
        self.lbl_progress.pack(pady=(10, 5))
        
        self.progressbar = ctk.CTkProgressBar(self.prog_frame, height=20, corner_radius=10)
        self.progressbar.pack(fill="x", padx=20, pady=(0, 20))
        self.progressbar.set(0)

        # Control Buttons
        self.btn_start = ctk.CTkButton(self.dashboard_frame, text="START SCAN", command=self.start_scan, height=50, fg_color="#00A300", hover_color="#008000", font=("Arial", 14, "bold"))
        self.btn_start.grid(row=1, column=0, padx=10, sticky="ew")

        self.btn_stop = ctk.CTkButton(self.dashboard_frame, text="STOP SCAN", command=self.stop_scan, height=50, fg_color="#D32F2F", hover_color="#B71C1C", font=("Arial", 14, "bold"), state="disabled")
        self.btn_stop.grid(row=1, column=1, padx=10, sticky="ew")

        # Results & Logs Split
        self.log_box = ctk.CTkTextbox(self.dashboard_frame, font=("Consolas", 12), text_color="#00FF00")
        self.log_box.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)
        self.log_box.insert("0.0", "--- SYSTEM READY ---\n")
        self.log_box.configure(state="disabled")

        self.res_box = ctk.CTkTextbox(self.dashboard_frame, font=("Consolas", 14), text_color="#FFD700")
        self.res_box.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=10)
        self.res_box.insert("0.0", f"{'IP Address':<20} | {'Ping':<8} | {'Country':<8} | ISP\n" + "-"*60 + "\n")
        self.res_box.configure(state="disabled")

        # Labels
        ctk.CTkLabel(self.dashboard_frame, text="System Logs", text_color="gray").grid(row=2, column=0, sticky="nw", padx=5, pady=10)
        ctk.CTkLabel(self.dashboard_frame, text="Found IPs (Live Updates)", text_color="gray").grid(row=3, column=0, sticky="nw", padx=5, pady=10)

    def setup_config(self):
        # Form
        self.config_frame.grid_columnconfigure(1, weight=1)

        def add_entry(row, label, var):
            ctk.CTkLabel(self.config_frame, text=label).grid(row=row, column=0, sticky="w", pady=10, padx=10)
            ctk.CTkEntry(self.config_frame, textvariable=var).grid(row=row, column=1, sticky="ew", pady=10, padx=10)

        add_entry(0, "Concurrency (Threads):", self.concurrency_var)
        add_entry(1, "Retries:", self.retries_var)
        add_entry(2, "Timeout (sec):", self.timeout_var)
        add_entry(3, "Download Bytes:", self.dl_bytes_var)
        add_entry(4, "Upload Bytes:", self.ul_bytes_var)
        add_entry(5, "Sample Percent (0-100):", self.percent_var)

        ctk.CTkCheckBox(self.config_frame, text="Shuffle Tasks (Random Order)", variable=self.shuffle_var).grid(row=6, column=0, columnspan=2, pady=20)

    def setup_editor(self):
        self.editor_tabview = ctk.CTkTabview(self.editor_frame)
        self.editor_tabview.pack(fill="both", expand=True)

        t_input = self.editor_tabview.add("input.txt")
        t_ip = self.editor_tabview.add("ip4.txt")

        self.txt_input = ctk.CTkTextbox(t_input, font=("Consolas", 12))
        self.txt_input.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.txt_ip = ctk.CTkTextbox(t_ip, font=("Consolas", 12))
        self.txt_ip.pack(fill="both", expand=True, padx=5, pady=5)

        btn_save = ctk.CTkButton(self.editor_frame, text="SAVE FILES", command=self.save_files, fg_color="#E65100", hover_color="#BF360C")
        btn_save.pack(fill="x", pady=10)

    def check_files(self):
        if not INPUT_FILE.exists(): INPUT_FILE.touch()
        if not IP_FILE.exists(): IP_FILE.touch()
        
        try:
            self.txt_input.insert("0.0", INPUT_FILE.read_text(encoding="utf-8"))
            self.txt_ip.insert("0.0", IP_FILE.read_text(encoding="utf-8"))
        except: pass

    def save_files(self):
        try:
            INPUT_FILE.write_text(self.txt_input.get("0.0", "end"), encoding="utf-8")
            IP_FILE.write_text(self.txt_ip.get("0.0", "end"), encoding="utf-8")
            messagebox.showinfo("Saved", "Files updated successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def add_result(self, data):
        # Handle dict input (IP, Ping, Geo)
        if isinstance(data, dict):
            ip = data["ip"]
            ping = f"{data['ping']}ms" if data['ping'] != -1 else "N/A"
            country = data['geo'].get('country', '--')
            isp = data['geo'].get('isp', '--')
            display_str = f"{ip:<20} | {ping:<8} | {country:<8} | {isp}"
        else:
            display_str = str(data) # Fallback

        self.res_box.configure(state="normal")
        self.res_box.insert("end", f"{display_str}\n")
        self.res_box.see("end")
        self.res_box.configure(state="disabled")
        self.clean_ips_count += 1

    def update_ui_loop(self):
        # Process Logs
        while not log_queue.empty():
            self.log(log_queue.get())
        
        # Process Results
        while not result_queue.empty():
            self.add_result(result_queue.get())
        
        # Process Progress
        while not progress_queue.empty():
            progress_queue.get()
            self.completed_tasks += 1
            if self.total_tasks > 0:
                val = self.completed_tasks / self.total_tasks
                self.progressbar.set(val)
                self.lbl_progress.configure(text=f"Progress: {int(val*100)}% ({self.completed_tasks}/{self.total_tasks}) - Clean: {self.clean_ips_count}")

        if self.is_scanning and shutdown_flag.is_set() and threading.active_count() <= 2:
            self.is_scanning = False
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            self.status_label.configure(text="Status: FINISHED/STOPPED", text_color="orange")
            self.log("Scan process ended.")

        self.after(200, self.update_ui_loop)

    def start_scan(self):
        if self.is_scanning: return
        self.save_files()
        
        try:
            xray_path = find_xray_binary()
        except FileNotFoundError:
            messagebox.showerror("Error", "xray.exe not found!")
            return

        self.is_scanning = True
        self.completed_tasks = 0
        self.clean_ips_count = 0
        self.progressbar.set(0)
        self.lbl_progress.configure(text="Progress: 0%")
        
        # Clear logs/results
        self.log_box.configure(state="normal"); self.log_box.delete("0.0", "end"); self.log_box.configure(state="disabled")
        self.res_box.configure(state="normal"); self.res_box.delete("0.0", "end"); self.res_box.configure(state="disabled")
        # Re-insert header
        self.res_box.configure(state="normal")
        self.res_box.insert("0.0", f"{'IP Address':<20} | {'Ping':<8} | {'Country':<8} | ISP\n" + "-"*60 + "\n")
        self.res_box.configure(state="disabled")


        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status_label.configure(text="Status: RUNNING", text_color="#00FF00")
        
        shutdown_flag.clear()
        
        threading.Thread(target=self.run_logic_thread, args=(xray_path,), daemon=True).start()

    def stop_scan(self):
        if not self.is_scanning: return
        shutdown_flag.set()
        self.log("Stopping... Waiting for threads...")
        self.status_label.configure(text="Status: STOPPING...", text_color="red")

    def run_logic_thread(self, xray_path):
        try:
            # Load Data
            uris = [l.strip() for l in INPUT_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
            ip_lines = [l.strip() for l in IP_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
            
            if not uris or not ip_lines:
                log_queue.put("No URIs or IPs found!")
                shutdown_flag.set()
                return

            completed = read_completed_ranges_from_report()
            groups_todo = []
            
            for raw in ip_lines:
                if raw in completed: continue
                ips = expand_ip_line(raw)
                if ips: groups_todo.append({"label": raw, "ips": ips})

            log_queue.put(f"Groups to scan: {len(groups_todo)}")
            
            # Params
            conc = int(self.concurrency_var.get())
            dl = int(self.dl_bytes_var.get())
            ul = int(self.ul_bytes_var.get())
            retries = int(self.retries_var.get())
            tout = int(self.timeout_var.get())
            pct = int(self.percent_var.get())
            shuffle = self.shuffle_var.get()

            # Calc total
            total_est = 0
            for g in groups_todo:
                k = len(g["ips"])
                if pct < 100: k = max(1, math.ceil(k * (pct/100.0)))
                total_est += k * len(uris)
            
            self.total_tasks = total_est
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)

            for g in groups_todo:
                if shutdown_flag.is_set(): break
                label = g["label"]
                ips = g["ips"]
                
                # Sample
                if pct < 100:
                    k = max(1, math.ceil(len(ips) * (pct/100.0)))
                    sampled = random.sample(ips, k) if k < len(ips) else ips
                else:
                    sampled = ips
                
                tasks = [(u, ip) for u in uris for ip in sampled]
                if shuffle: random.shuffle(tasks)
                
                log_queue.put(f"Range: {label} ({len(tasks)} items)")
                
                q = queue.Queue()
                for i, t in enumerate(tasks): q.put((i, t[0], t[1]))
                
                threads = []
                for _ in range(min(conc, len(tasks))):
                    # Passing Queue, XrayPath, DL, UL, Retries, Timeout, RequireBoth
                    t = threading.Thread(target=worker, args=(q, xray_path, dl, ul, retries, tout, True), daemon=True)
                    t.start()
                    threads.append(t)
                
                for t in threads: t.join()
                
                if not shutdown_flag.is_set():
                    append_done_to_report(label)
                    log_queue.put(f"Completed Range: {label}")

            log_queue.put("ALL DONE.")
        
        except Exception as e:
            log_queue.put(f"CRITICAL ERROR: {e}")
        finally:
            cleanup_configs()
            shutdown_flag.set()

if __name__ == "__main__":
    app = App()
    app.mainloop()
