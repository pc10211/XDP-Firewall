import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import struct
import threading
import time
import uuid
import ctypes
import platform
from collections import deque
from pathlib import Path
from typing import AsyncIterator, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, field_validator, model_validator

logging.getLogger("uvicorn.access").handlers = []
logging.getLogger("uvicorn.access").propagate = False

BASE_DIR       = Path(__file__).parent
RULES_FILE     = BASE_DIR / "rules.json"
XDP_SRC        = BASE_DIR / "xdp_firewall.c"
IFACE          = os.environ.get("XDP_IFACE", "eth0")
API_KEY_FILE   = BASE_DIR / "api_key.txt"
CERT_FILE      = BASE_DIR / "cert.pem"
KEY_FILE       = BASE_DIR / "cert.key"
SESSION_SECRET_FILE = BASE_DIR / "session_secret.bin"
INTERFACES_FILE = BASE_DIR / "interfaces.txt"

HTTP_PORT      = int(os.environ.get("FW_HTTP_PORT", "8000"))
HTTPS_PORT     = int(os.environ.get("FW_HTTPS_PORT", "8443"))
USE_TLS        = os.environ.get("FW_USE_TLS", "1") not in ("0", "false", "False", "")

SESSION_TTL        = 86400
LOCKOUT_WINDOW     = 300
LOCKOUT_DURATION   = 900
MAX_LOGIN_FAILURES = 5

_sessions: dict = {}
_sessions_lock = threading.Lock()
_auth_fails: dict = {}
_auth_fails_lock = threading.Lock()

_file_lock = threading.RLock()


def _load_or_create_api_key() -> str:
    env_key = os.environ.get("FW_API_KEY")
    if env_key:
        return env_key
    if API_KEY_FILE.exists():
        return API_KEY_FILE.read_text().strip()
    key = secrets.token_hex(32)
    API_KEY_FILE.write_text(key)
    os.chmod(API_KEY_FILE, 0o600)
    print(f"[AUTH] API-Key generiert: {key}")
    print(f"[AUTH] Gespeichert in: {API_KEY_FILE}")
    return key


def _load_or_create_session_secret() -> bytes:
    if SESSION_SECRET_FILE.exists():
        return SESSION_SECRET_FILE.read_bytes()
    s = secrets.token_bytes(32)
    SESSION_SECRET_FILE.write_bytes(s)
    os.chmod(SESSION_SECRET_FILE, 0o600)
    return s


def _ensure_tls_cert() -> bool:
    if CERT_FILE.exists() and KEY_FILE.exists():
        return True
    try:
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        try:
            r = subprocess.run(
                ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                 "-days", "3650", "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
                 "-subj", "/CN=xdp-firewall", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                capture_output=True, timeout=30
            )
            if r.returncode == 0:
                os.chmod(KEY_FILE, 0o600)
                os.chmod(CERT_FILE, 0o644)
                print(f"[TLS] Zertifikat via openssl erstellt: {CERT_FILE}")
                return True
        except Exception as e:
            print(f"[TLS] openssl fehlgeschlagen: {e}")
        return False

    try:
        from datetime import datetime, timedelta, timezone
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "xdp-firewall")])
        san = x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        KEY_FILE.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(KEY_FILE, 0o600)
        os.chmod(CERT_FILE, 0o644)
        print(f"[TLS] Zertifikat via cryptography erstellt: {CERT_FILE}")
        return True
    except Exception as e:
        print(f"[TLS] cryptography fehlgeschlagen: {e}")
        return False


API_KEY = _load_or_create_api_key()
SESSION_SECRET = _load_or_create_session_secret()

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

IPRoute = None
PYROUTE2_AVAILABLE = False


def _bpf_pin(fd: int, path: str) -> None:
    BPF_OBJ_PIN = 6
    _NR = {"x86_64": 321, "aarch64": 280, "armv7l": 386}.get(platform.machine())
    if _NR is None:
        raise OSError(f"Unbekannte Architektur: {platform.machine()}")

    class _Attr(ctypes.Structure):
        _fields_ = [("pathname", ctypes.c_uint64),
                    ("bpf_fd",   ctypes.c_uint32),
                    ("file_flags", ctypes.c_uint32)]

    buf  = ctypes.create_string_buffer(path.encode() + b'\x00')
    attr = _Attr()
    attr.pathname   = ctypes.cast(buf, ctypes.c_void_p).value
    attr.bpf_fd     = fd
    attr.file_flags = 0
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(_NR, BPF_OBJ_PIN, ctypes.byref(attr), ctypes.sizeof(attr)) < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


PROTO_MAP   = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
VALID_TYPES = frozenset(("filter", "established", "forward", "ratelimit", "dns", "ip_ratelimit", "conn_timeout"))
IP_RE       = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
IFACE_RE    = re.compile(r'^[a-zA-Z0-9_-]{1,15}$')
MASQ_COMMENT = "xdp-firewall-masq"

_rules_cache: Optional[list] = None
_rules_mtime: float = 0


def _normalize_iface_string(value: Optional[str], fallback: str = IFACE) -> str:
    raw = value or fallback or "eth0"
    parts = []
    seen = set()
    for part in raw.split(','):
        item = part.strip()
        if not item or not IFACE_RE.match(item) or item in seen:
            continue
        seen.add(item)
        parts.append(item)
    if not parts and fallback and fallback != raw:
        return _normalize_iface_string(fallback, "eth0")
    if not parts:
        parts = ["eth0"]
    return ",".join(parts)


def _load_iface_config() -> str:
    try:
        if INTERFACES_FILE.exists():
            return _normalize_iface_string(INTERFACES_FILE.read_text().strip(), IFACE)
    except Exception:
        pass
    return _normalize_iface_string(IFACE, "eth0")


def _save_iface_config(iface: str) -> None:
    val = _normalize_iface_string(iface, IFACE)
    tmp = INTERFACES_FILE.with_name(f".interfaces.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp")
    try:
        tmp.write_text(val)
        os.chmod(tmp, 0o600)
        tmp.replace(INTERFACES_FILE)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass


def ip_to_be(ip: str) -> int:
    net = ipaddress.ip_network(ip, strict=False)
    return struct.unpack('<I', net.network_address.packed)[0]


def _normalize_rules(raw):
    out = []
    seen = set()
    counters = {}
    for idx, item in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(item, dict):
            continue
        r = dict(item)
        rid = str(r.get("id") or "").strip()
        if not rid or len(rid) > 64 or not re.match(r"^[a-zA-Z0-9_-]+$", rid):
            rid = f"rule{idx + 1:04d}"[:8]
        if rid in seen:
            base = re.sub(r"[^a-zA-Z0-9_-]", "", rid)[:6] or "rule"
            n = counters.get(base, 1) + 1
            while True:
                cand = f"{base}{n:02d}"[:8]
                if cand not in seen:
                    counters[base] = n
                    rid = cand
                    break
                n += 1
        else:
            base = re.sub(r"[^a-zA-Z0-9_-]", "", rid)[:6] or "rule"
            counters[base] = max(counters.get(base, 0), 1)
        r["id"] = rid
        seen.add(rid)
        out.append(r)
    return out

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _auth_throttle_check(ip: str) -> Optional[int]:
    now = time.time()
    with _auth_fails_lock:
        entry = _auth_fails.get(ip)
        if not entry:
            return None
        count, first_ts, locked_until = entry
        if locked_until and now < locked_until:
            return int(locked_until - now)
        if locked_until and now >= locked_until:
            _auth_fails.pop(ip, None)
            return None
        if now - first_ts > LOCKOUT_WINDOW:
            _auth_fails.pop(ip, None)
            return None
    return None


def _auth_record_failure(ip: str) -> None:
    now = time.time()
    with _auth_fails_lock:
        entry = _auth_fails.get(ip)
        if not entry or (now - entry[1]) > LOCKOUT_WINDOW:
            _auth_fails[ip] = (1, now, 0.0)
            return
        count = entry[0] + 1
        if count >= MAX_LOGIN_FAILURES:
            _auth_fails[ip] = (count, entry[1], now + LOCKOUT_DURATION)
            print(f"[AUTH] IP {ip} nach {count} Fehlversuchen gesperrt für {LOCKOUT_DURATION}s")
        else:
            _auth_fails[ip] = (count, entry[1], 0.0)


def _auth_reset_failure(ip: str) -> None:
    with _auth_fails_lock:
        _auth_fails.pop(ip, None)


def _create_session(origin_ip: str) -> str:
    sid = secrets.token_urlsafe(32)
    now = time.time()
    with _sessions_lock:
        _sessions[sid] = {"created": now, "expires": now + SESSION_TTL, "ip": origin_ip}
        if len(_sessions) > 1000:
            expired = [k for k, v in _sessions.items() if v["expires"] < now]
            for k in expired:
                _sessions.pop(k, None)
    return sid


def _validate_session(sid: str) -> bool:
    if not sid:
        return False
    now = time.time()
    with _sessions_lock:
        s = _sessions.get(sid)
        if not s:
            return False
        if s["expires"] < now:
            _sessions.pop(sid, None)
            return False
    return True


def _destroy_session(sid: str) -> None:
    if not sid:
        return
    with _sessions_lock:
        _sessions.pop(sid, None)


def _check_auth(request: Request) -> bool:
    sid = request.cookies.get("sid", "")
    if _validate_session(sid):
        return True
    header_key = request.headers.get("x-api-key", "")
    if header_key and hmac.compare_digest(header_key, API_KEY):
        return True
    return False


class FirewallRule(BaseModel):
    id:           Optional[str] = None
    type:         str           = "filter"
    action:       str           = "allow"
    direction:    str           = "inbound"
    src:          str           = "any"
    src_port:     str           = "any"
    protocol:     str           = "any"
    dst_port:     str           = "any"
    icmp_type:    str           = "any"
    icmp_code:    str           = "any"
    rate_limit:   Optional[int] = None
    per_ip_limit: Optional[int] = None
    comment:      str           = ""
    value:        Optional[str] = None
    forward_ip:   Optional[str] = None
    forward_port: Optional[str] = None
    enabled:      bool          = True
    priority:     int           = 100

    @field_validator("type")
    @classmethod
    def _type(cls, v):
        if v not in VALID_TYPES:
            raise ValueError(f"Ungültiger Typ: {v}")
        return v

    @field_validator("action")
    @classmethod
    def _action(cls, v):
        if v not in ("allow", "block"):
            raise ValueError("action muss 'allow' oder 'block' sein")
        return v

    @field_validator("direction")
    @classmethod
    def _direction(cls, v):
        if v not in ("inbound", "outbound", "both"):
            raise ValueError("direction muss 'inbound', 'outbound' oder 'both' sein")
        return v

    @field_validator("protocol")
    @classmethod
    def _proto(cls, v):
        if v not in ("any", "tcp", "udp", "icmp"):
            raise ValueError("protocol: any | tcp | udp | icmp")
        return v

    @field_validator("src")
    @classmethod
    def _src(cls, v):
        if v in ("any", ""):
            return "any"
        if not IP_RE.match(v):
            raise ValueError("src muss 'any' oder IP/CIDR sein")
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError("Ungültige IP/CIDR")
        return v

    @field_validator("src_port")
    @classmethod
    def _src_port(cls, v):
        if v in ("any", ""):
            return "any"
        try:
            p = int(v)
            if not 1 <= p <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError("src_port: 'any' oder 1-65535")
        return str(p)

    @field_validator("dst_port")
    @classmethod
    def _dst_port(cls, v):
        if v in ("any", ""):
            return "any"
        try:
            p = int(v)
            if not 1 <= p <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError("dst_port: 'any' oder 1-65535")
        return str(p)

    @field_validator("icmp_type")
    @classmethod
    def _icmp_type(cls, v):
        if v in ("any", ""):
            return "any"
        try:
            t = int(v)
            if not 0 <= t <= 255:
                raise ValueError
        except ValueError:
            raise ValueError("icmp_type: 'any' oder 0-255")
        return str(t)

    @field_validator("icmp_code")
    @classmethod
    def _icmp_code(cls, v):
        if v in ("any", ""):
            return "any"
        try:
            c = int(v)
            if not 0 <= c <= 255:
                raise ValueError
        except ValueError:
            raise ValueError("icmp_code: 'any' oder 0-255")
        return str(c)

    @field_validator("rate_limit")
    @classmethod
    def _rate_limit(cls, v):
        if v is not None and not 1 <= v <= 100_000_000:
            raise ValueError("rate_limit: 1-100000000")
        return v

    @field_validator("per_ip_limit")
    @classmethod
    def _per_ip_limit(cls, v):
        if v is not None and not 1 <= v <= 100_000_000:
            raise ValueError("per_ip_limit: 1-100000000")
        return v

    @field_validator("priority")
    @classmethod
    def _priority(cls, v):
        if not 0 <= v <= 9999:
            raise ValueError("priority: 0-9999")
        return v

    @field_validator("comment")
    @classmethod
    def _comment(cls, v):
        if len(v) > 200:
            raise ValueError("comment: max 200 Zeichen")
        return v

    @model_validator(mode="after")
    def _cross(self):
        t = self.type
        if t == "ratelimit":
            if not self.value:
                raise ValueError("ratelimit benötigt value (PPS)")
            try:
                pps = int(self.value)
                if not 1 <= pps <= 100_000_000:
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError("value muss Zahl (PPS) sein")
        elif t == "ip_ratelimit":
            if self.src == "any":
                raise ValueError("ip_ratelimit benötigt src IP/CIDR")
            if not self.value:
                raise ValueError("ip_ratelimit benötigt value (PPS)")
            try:
                pps = int(self.value)
                if not 1 <= pps <= 100_000_000:
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError("value muss Zahl (PPS) sein")
        elif t == "dns":
            if self.value not in ("query", "response", "both", None):
                raise ValueError("dns value: query | response | both")
            if not self.value:
                self.value = "both"
        elif t == "forward":
            if not self.dst_port or self.dst_port == "any":
                raise ValueError("forward benötigt dst_port")
            if not self.forward_ip:
                raise ValueError("forward benötigt forward_ip")
            try:
                ipaddress.ip_address(self.forward_ip)
            except ValueError:
                raise ValueError("Ungültige forward_ip")
            if not self.forward_port:
                self.forward_port = self.dst_port
            else:
                try:
                    fp = int(self.forward_port)
                    if not 1 <= fp <= 65535:
                        raise ValueError
                except (ValueError, TypeError):
                    raise ValueError("forward_port: 1-65535")
        elif t == "conn_timeout":
            if not self.value:
                raise ValueError("conn_timeout benötigt value (Sekunden)")
            try:
                secs = int(self.value)
                if not 1 <= secs <= 86400:
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError("value muss Zahl (1-86400 Sekunden) sein")
        return self


class ApplyRequest(BaseModel):
    iface: Optional[str] = None

    @field_validator("iface")
    @classmethod
    def _iface(cls, v):
        if not v:
            return v
        parts = [p.strip() for p in v.split(',') if p.strip()]
        if not parts:
            raise ValueError("Kein Interface angegeben")
        for p in parts:
            if not IFACE_RE.match(p):
                raise ValueError(f"Ungültiger Interface-Name: {p}")
        return ",".join(parts)


class ReorderRequest(BaseModel):
    order: list[str]

    @field_validator("order")
    @classmethod
    def _order(cls, v):
        if len(v) > 500:
            raise ValueError("Max 500 IDs")
        for rid in v:
            if not isinstance(rid, str) or len(rid) > 64:
                raise ValueError("Ungültige Regel-ID")
        return v


class LoginRequest(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def _pw(cls, v):
        if not isinstance(v, str) or len(v) > 512:
            raise ValueError("Ungültiges Passwort")
        return v


class IPv6PolicyRequest(BaseModel):
    allow: bool


class StatsRing:
    __slots__ = ('_ring', '_lock')

    def __init__(self):
        self._ring: deque = deque(maxlen=600)
        self._lock = threading.Lock()

    def push(self, ts, passed, dropped, pass_bytes=0, drop_bytes=0):
        with self._lock:
            self._ring.append((ts, passed, dropped, pass_bytes, drop_bytes))

    def pps(self):
        with self._lock:
            if len(self._ring) < 2:
                return 0.0, 0.0
            e0 = self._ring[-2]
            e1 = self._ring[-1]
        dt = e1[0] - e0[0]
        return ((e1[1] - e0[1]) / dt, (e1[2] - e0[2]) / dt) if dt > 0 else (0.0, 0.0)

    def bps(self):
        with self._lock:
            if len(self._ring) < 2:
                return 0.0, 0.0
            e0 = self._ring[-2]
            e1 = self._ring[-1]
        dt = e1[0] - e0[0]
        if dt <= 0 or len(e1) < 5:
            return 0.0, 0.0
        return ((e1[3] - e0[3]) / dt, (e1[4] - e0[4]) / dt)

    def history(self, n=60):
        with self._lock:
            ring = list(self._ring)
        out = []
        ln = len(ring)
        for i in range(1, min(n + 1, ln)):
            e_prev = ring[-i - 1] if i + 1 <= ln else ring[0]
            e_cur  = ring[-i]
            dt = e_cur[0] - e_prev[0]
            if dt > 0:
                out.append({
                    "ts":       e_cur[0],
                    "pass_pps": round((e_cur[1] - e_prev[1]) / dt, 1),
                    "drop_pps": round((e_cur[2] - e_prev[2]) / dt, 1),
                })
        out.reverse()
        return out


ring = StatsRing()


class XDPFirewall:
    __slots__ = ('bpf', 'loaded', 'ifaces', '_lock', '_poll', '_run', '_nat_rules',
                 'tc_attached', '_masq_applied', 'ipv6_allow', 'requested_ifaces',
                 '_rule_id_map', '_rule_meta', '_rule_num_by_string', '_next_rule_num', '_prev_pkt_bytes')

    def __init__(self):
        self.bpf = None
        self.loaded = False
        self.ifaces = []
        self._lock = threading.Lock()
        self._poll = None
        self._run = False
        self._nat_rules = []
        self.tc_attached = []
        self._masq_applied = False
        self.ipv6_allow = False
        self.requested_ifaces = []
        self._rule_id_map: dict = {}
        self._rule_meta: dict = {}
        self._rule_num_by_string: dict = {}
        self._next_rule_num = 1
        self._prev_pkt_bytes = (0, 0)

    def load_rules(self):
        global _rules_cache, _rules_mtime
        with _file_lock:
            if not RULES_FILE.exists():
                return []
            try:
                mt = RULES_FILE.stat().st_mtime
                if _rules_cache is not None and mt == _rules_mtime:
                    return list(_rules_cache)
                data = json.loads(RULES_FILE.read_text())
                if isinstance(data, list):
                    data = _normalize_rules(data)
                    _rules_cache = data
                    _rules_mtime = mt
                    return list(data)
            except (json.JSONDecodeError, IOError, OSError):
                pass
            return []

    def save_rules(self, rules):
        global _rules_cache, _rules_mtime
        with _file_lock:
            tmp_name = f".rules.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp"
            tmp = RULES_FILE.with_name(tmp_name)
            try:
                tmp.write_text(json.dumps(rules, indent=2))
                os.chmod(tmp, 0o600)
                tmp.replace(RULES_FILE)
                _rules_cache = list(rules)
                _rules_mtime = RULES_FILE.stat().st_mtime
            except Exception:
                try:
                    tmp.unlink()
                except OSError:
                    pass
                raise

    def _parse_ifaces(self, iface):
        ifaces = [i.strip() for i in iface.split(',') if i.strip() and IFACE_RE.match(i.strip())]
        if not ifaces:
            raise ValueError("Keine gültigen Interfaces")
        return ifaces

    def _cleanup_bpf(self, b):
        if not b:
            return
        for name in ("cleanup", "close"):
            fn = getattr(b, name, None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass
                break

    def compile_and_attach(self, rules, iface):
        if not BCC_AVAILABLE:
            return "BCC nicht verfügbar"
        ifaces = self._parse_ifaces(iface)
        with self._lock:
            old_bpf = self.bpf
            if self.bpf and self.loaded:
                try:
                    for old in self.ifaces:
                        try:
                            self.bpf.remove_xdp(old, flags=BPF.XDP_FLAGS_SKB_MODE)
                        except Exception:
                            pass
                except Exception:
                    pass
                self._detach_tc()
                self.loaded = False

            b = BPF(text=XDP_SRC.read_text())
            fn = b.load_func("xdp_firewall", BPF.XDP)
            attached = []
            errors = []
            for ifc in ifaces:
                try:
                    b.attach_xdp(ifc, fn, flags=BPF.XDP_FLAGS_SKB_MODE)
                    attached.append(ifc)
                except Exception as e:
                    errors.append(f"{ifc}: {e}")
            if not attached:
                self._cleanup_bpf(b)
                raise ValueError(f"Konnte auf keinem Interface laden: {'; '.join(errors)}")

            self._cleanup_bpf(old_bpf)
            self.bpf = b
            self.ifaces = attached
            self.requested_ifaces = ifaces
            _save_iface_config(",".join(ifaces))
            self.loaded = True
            self._populate_maps(rules, preserve_counters=False)
            self._apply_nat(rules)

            has_est = any(r.get("type") == "established" and r.get("enabled", True) for r in rules)
            tc_ok = False
            if has_est:
                tc_ok = self._attach_tc(b, attached)

            self._start_poll()

        tc_msg = ""
        if has_est:
            tc_msg = " + TC-Conntrack aktiv" if tc_ok else " + TC fehlgeschlagen (kein Conntrack)"

        return f"XDP neu geladen auf {len(attached)} Interfaces – {len(rules)} Regeln{tc_msg}"

    def apply_runtime(self, rules, iface):
        if not BCC_AVAILABLE:
            return "BCC nicht verfügbar"
        ifaces = self._parse_ifaces(iface)
        with self._lock:
            base_ifaces = self.requested_ifaces or self.ifaces
            same_ifaces = self.loaded and self.bpf and sorted(ifaces) == sorted(base_ifaces)
            if not same_ifaces:
                return None
            self.requested_ifaces = ifaces
            _save_iface_config(",".join(ifaces))
            self._populate_maps(rules, preserve_counters=True)
            self._apply_nat(rules)
            has_est = any(r.get("type") == "established" and r.get("enabled", True) for r in rules)
            tc_msg = ""
            if has_est and not self.tc_attached:
                tc_ok = self._attach_tc(self.bpf, self.ifaces)
                tc_msg = " + TC-Conntrack aktiv" if tc_ok else " + TC fehlgeschlagen"
            elif not has_est and self.tc_attached:
                self._detach_tc()
                tc_msg = " + TC getrennt"
            return f"Regeln ohne Neustart aktualisiert – {len(rules)} Regeln{tc_msg}"

    def _attach_tc(self, b, ifaces):
        try:
            fn_tc = b.load_func("tc_egress", BPF.SCHED_CLS)
        except Exception as e:
            print(f"[TC] load_func fehlgeschlagen: {e}")
            return False

        attached = []
        for ifc in ifaces:
            if self._tc_pyroute2(fn_tc, ifc):
                attached.append(ifc)
            elif self._tc_cli(fn_tc.fd, ifc):
                attached.append(ifc)
            else:
                print(f"[TC] Alle Methoden auf {ifc} fehlgeschlagen")

        self.tc_attached = attached
        return len(attached) > 0

    def _tc_pyroute2(self, fn_tc, ifc) -> bool:
        return False

    def _tc_cli(self, fd: int, ifc: str) -> bool:
        pin = f"/sys/fs/bpf/fw_egress_{ifc}"
        try:
            try:
                os.unlink(pin)
            except OSError:
                pass
            _bpf_pin(fd, pin)
            subprocess.run(["tc", "qdisc", "add", "dev", ifc, "clsact"], capture_output=True, timeout=5)
            r = subprocess.run(
                ["tc", "filter", "add", "dev", ifc, "egress", "bpf", "pinned", pin, "direct-action"],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                print(f"[TC] CLI-Pin OK auf {ifc}")
                return True
            print(f"[TC] tc filter fehlgeschlagen: {r.stderr.decode().strip()}")
            return False
        except Exception as e:
            print(f"[TC] CLI-Fallback fehlgeschlagen auf {ifc}: {e}")
            return False

    def _detach_tc(self):
        for ifc in list(dict.fromkeys(self.tc_attached)):
            try:
                subprocess.run(["tc", "qdisc", "del", "dev", ifc, "clsact"], capture_output=True, timeout=5)
            except Exception:
                pass
            try:
                os.unlink(f"/sys/fs/bpf/fw_egress_{ifc}")
            except OSError:
                pass
        self.tc_attached = []

    def configured_iface(self):
        return ",".join(self.requested_ifaces or self.ifaces)

    def _clear_table(self, name):
        try:
            m = self.bpf[name]
            keys = list(m.keys())
            for k in keys:
                try:
                    m.__delitem__(k)
                except Exception:
                    pass
        except Exception:
            pass

    def _prepare_rule_ids(self, rules):
        self._rule_id_map = {}
        self._rule_meta = {}
        used = set()
        for r in rules:
            rid_str = r.get("id", "")
            if not rid_str:
                continue
            num = self._rule_num_by_string.get(rid_str)
            if not num or num >= 1024:
                while self._next_rule_num in used or self._next_rule_num in self._rule_id_map or self._next_rule_num >= 1024:
                    self._next_rule_num += 1
                if self._next_rule_num >= 1024:
                    continue
                num = self._next_rule_num
                self._rule_num_by_string[rid_str] = num
                self._next_rule_num += 1
            used.add(num)
            self._rule_id_map[num] = rid_str
            self._rule_meta[rid_str] = {
                "numeric_id": num,
                "comment": r.get("comment", ""),
                "type": r.get("type", "filter"),
            }

    def _populate_maps(self, rules, preserve_counters=False):
        b = self.bpf
        wl_subnet       = b["wl_subnet"]
        bl_subnet       = b["bl_subnet"]
        wl_port         = b["wl_port"]
        bl_port         = b["bl_port"]
        wl_icmp         = b["wl_icmp"]
        rl_global_cfg   = b["rl_global_cfg"]
        rl_global_rule  = b["rl_global_rule"]
        rl_proto_cfg    = b["rl_proto_cfg"]
        rl_proto_rule   = b["rl_proto_rule"]
        rl_ip_cfg       = b["rl_ip_cfg"]
        rl_port_cfg     = b["rl_port_cfg"]
        rl_port_rule    = b["rl_port_rule"]
        dns_rl_cfg      = b["dns_rl_cfg"]
        dns_rule        = b["dns_rule"]
        stateful_enabled= b["stateful_enabled"]
        conn_timeout_cfg= b["conn_timeout_cfg"]
        per_ip_port_cfg = b["per_ip_port_cfg"]
        per_ip_port_rule= b["per_ip_port_rule"]
        bl_out_port     = b["bl_out_port"]
        bl_out_subnet   = b["bl_out_subnet"]
        ipv6_policy     = b["ipv6_policy"]

        for mname in ("wl_subnet", "bl_subnet", "wl_port", "bl_port", "wl_icmp",
                      "rl_proto_cfg", "rl_proto_rule", "rl_ip_cfg", "rl_port_cfg",
                      "rl_port_rule", "dns_rl_cfg", "dns_rule", "per_ip_port_cfg",
                      "per_ip_port_rule", "bl_out_port", "bl_out_subnet", "dns_wl"):
            self._clear_table(mname)
        if not preserve_counters:
            for mname in ("stats", "rule_hits", "rule_pass_hits", "rule_drop_hits", "proto_pkts", "proto_bytes", "egress_pkts",
                          "egress_bytes", "egress_drop_pkts", "egress_drop_bytes"):
                try:
                    m = b[mname]
                    for i in range(len(m)):
                        m[i] = m.Leaf(0)
                except Exception:
                    pass
        for mname in ("rl_global_rule",):
            try:
                m = b[mname]
                for i in range(len(m)):
                    m[i] = m.Leaf(0)
            except Exception:
                pass
        self._prepare_rule_ids(rules)

        def _rid_of(r):
            meta = self._rule_meta.get(r.get("id", ""))
            return meta["numeric_id"] if meta else 0

        rl_global_cfg[0]    = rl_global_cfg.Leaf(0)
        rl_global_rule[0]   = rl_global_rule.Leaf(0)
        stateful_enabled[0] = stateful_enabled.Leaf(0)
        conn_timeout_cfg[0] = conn_timeout_cfg.Leaf(0)
        ipv6_policy[0]      = ipv6_policy.Leaf(1 if self.ipv6_allow else 0)

        for r in rules:
            if not r.get("enabled", True):
                continue
            t = r.get("type", "filter")
            proto = PROTO_MAP.get(r.get("protocol", "any"), 0)
            rl = r.get("rate_limit") or 0
            pip = r.get("per_ip_limit") or 0
            src_port = r.get("src_port", "any") or "any"
            rid = _rid_of(r)

            if t == "filter":
                action = r.get("action", "allow")
                src = r.get("src", "any") or "any"
                dst_port = r.get("dst_port", "any") or "any"
                icmp_tp = r.get("icmp_type", "any") or "any"
                icmp_cd = r.get("icmp_code", "any") or "any"

                if action == "allow":
                    if proto == 1 or r.get("protocol") == "icmp":
                        if icmp_tp == "any":
                            key16 = 0xFFFF
                        else:
                            it = int(icmp_tp)
                            ic = 0xFF if icmp_cd == "any" else int(icmp_cd)
                            key16 = (it << 8) | ic
                        wl_icmp[wl_icmp.Key(key16)] = wl_icmp.Leaf(proto=1, port=key16, action=1, rate_limit=rl, rule_id=rid)
                        icmp_pk = (1 << 16) | key16
                        if rl > 0:
                            rl_port_cfg[rl_port_cfg.Key(icmp_pk)] = rl_port_cfg.Leaf(rl)
                            rl_port_rule[rl_port_rule.Key(icmp_pk)] = rl_port_rule.Leaf(rid)
                        if pip > 0:
                            per_ip_port_cfg[per_ip_port_cfg.Key(icmp_pk)] = per_ip_port_cfg.Leaf(pip)
                            per_ip_port_rule[per_ip_port_rule.Key(icmp_pk)] = per_ip_port_rule.Leaf(rid)
                    elif src != "any":
                        try:
                            net = ipaddress.ip_network(src, strict=False)
                            addr = ip_to_be(src)
                        except ValueError:
                            continue
                        port = 0 if dst_port == "any" else int(dst_port)
                        wl_subnet[wl_subnet.Key(prefixlen=net.prefixlen, addr=addr)] = wl_subnet.Leaf(proto=proto, port=port, action=1, rate_limit=rl, rule_id=rid)
                    else:
                        if dst_port != "any":
                            port = int(dst_port)
                            if proto:
                                pk = (proto << 16) | port
                                wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=proto, port=port, action=1, rate_limit=rl, rule_id=rid)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                    rl_port_rule[rl_port_rule.Key(pk)] = rl_port_rule.Leaf(rid)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                                    per_ip_port_rule[per_ip_port_rule.Key(pk)] = per_ip_port_rule.Leaf(rid)
                            else:
                                for p in (6, 17):
                                    pk = (p << 16) | port
                                    wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=p, port=port, action=1, rate_limit=rl, rule_id=rid)
                                    if rl > 0:
                                        rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                        rl_port_rule[rl_port_rule.Key(pk)] = rl_port_rule.Leaf(rid)
                                    if pip > 0:
                                        per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                                        per_ip_port_rule[per_ip_port_rule.Key(pk)] = per_ip_port_rule.Leaf(rid)
                                wl_port[wl_port.Key(port)] = wl_port.Leaf(proto=0, port=port, action=1, rate_limit=rl, rule_id=rid)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(port)] = rl_port_cfg.Leaf(rl)
                                    rl_port_rule[rl_port_rule.Key(port)] = rl_port_rule.Leaf(rid)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(port)] = per_ip_port_cfg.Leaf(pip)
                                    per_ip_port_rule[per_ip_port_rule.Key(port)] = per_ip_port_rule.Leaf(rid)
                        if src_port != "any":
                            port = int(src_port)
                            if proto:
                                pk = (1 << 24) | (proto << 16) | port
                                wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=proto, port=port, action=1, rate_limit=rl, rule_id=rid)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                    rl_port_rule[rl_port_rule.Key(pk)] = rl_port_rule.Leaf(rid)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                                    per_ip_port_rule[per_ip_port_rule.Key(pk)] = per_ip_port_rule.Leaf(rid)
                            else:
                                for p in (6, 17):
                                    pk = (1 << 24) | (p << 16) | port
                                    wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=p, port=port, action=1, rate_limit=rl, rule_id=rid)
                                    if rl > 0:
                                        rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                        rl_port_rule[rl_port_rule.Key(pk)] = rl_port_rule.Leaf(rid)
                                    if pip > 0:
                                        per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                                        per_ip_port_rule[per_ip_port_rule.Key(pk)] = per_ip_port_rule.Leaf(rid)
                                pk_any = (1 << 24) | port
                                wl_port[wl_port.Key(pk_any)] = wl_port.Leaf(proto=0, port=port, action=1, rate_limit=rl, rule_id=rid)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(pk_any)] = rl_port_cfg.Leaf(rl)
                                    rl_port_rule[rl_port_rule.Key(pk_any)] = rl_port_rule.Leaf(rid)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(pk_any)] = per_ip_port_cfg.Leaf(pip)
                                    per_ip_port_rule[per_ip_port_rule.Key(pk_any)] = per_ip_port_rule.Leaf(rid)
                elif action == "block":
                    direction = r.get("direction", "inbound")
                    do_in = direction in ("inbound", "both")
                    do_out = direction in ("outbound", "both")
                    if src != "any":
                        try:
                            net = ipaddress.ip_network(src, strict=False)
                            addr = ip_to_be(src)
                        except ValueError:
                            continue
                        b_port = 0 if dst_port == "any" else int(dst_port)
                        b_proto = 0 if not proto else proto
                        if do_in:
                            bl_subnet[bl_subnet.Key(prefixlen=net.prefixlen, addr=addr)] = bl_subnet.Leaf(proto=b_proto, port=b_port, action=1, rate_limit=0, rule_id=rid)
                        if do_out:
                            bl_out_subnet[bl_out_subnet.Key(prefixlen=net.prefixlen, addr=addr)] = bl_out_subnet.Leaf(proto=b_proto, port=b_port, action=1, rate_limit=0, rule_id=rid)
                    else:
                        if dst_port != "any":
                            port = int(dst_port)
                            if proto:
                                pk = (proto << 16) | port
                                if do_in:
                                    bl_port[bl_port.Key(pk)] = bl_port.Leaf(proto=proto, port=port, action=1, rate_limit=0, rule_id=rid)
                                if do_out:
                                    bl_out_port[bl_out_port.Key(pk)] = bl_out_port.Leaf(proto=proto, port=port, action=1, rate_limit=0, rule_id=rid)
                            else:
                                for p in (6, 17):
                                    pk = (p << 16) | port
                                    if do_in:
                                        bl_port[bl_port.Key(pk)] = bl_port.Leaf(proto=p, port=port, action=1, rate_limit=0, rule_id=rid)
                                    if do_out:
                                        bl_out_port[bl_out_port.Key(pk)] = bl_out_port.Leaf(proto=p, port=port, action=1, rate_limit=0, rule_id=rid)
                                if do_in:
                                    bl_port[bl_port.Key(port)] = bl_port.Leaf(proto=0, port=port, action=1, rate_limit=0, rule_id=rid)
                                if do_out:
                                    bl_out_port[bl_out_port.Key(port)] = bl_out_port.Leaf(proto=0, port=port, action=1, rate_limit=0, rule_id=rid)
                        if src_port != "any":
                            port = int(src_port)
                            if proto:
                                pk = (1 << 24) | (proto << 16) | port
                                if do_in:
                                    bl_port[bl_port.Key(pk)] = bl_port.Leaf(proto=proto, port=port, action=1, rate_limit=0, rule_id=rid)
                                if do_out:
                                    bl_out_port[bl_out_port.Key(pk)] = bl_out_port.Leaf(proto=proto, port=port, action=1, rate_limit=0, rule_id=rid)
                            else:
                                for p in (6, 17):
                                    pk = (1 << 24) | (p << 16) | port
                                    if do_in:
                                        bl_port[bl_port.Key(pk)] = bl_port.Leaf(proto=p, port=port, action=1, rate_limit=0, rule_id=rid)
                                    if do_out:
                                        bl_out_port[bl_out_port.Key(pk)] = bl_out_port.Leaf(proto=p, port=port, action=1, rate_limit=0, rule_id=rid)
                                if do_in:
                                    pk_any = (1 << 24) | port
                                    bl_port[bl_port.Key(pk_any)] = bl_port.Leaf(proto=0, port=port, action=1, rate_limit=0, rule_id=rid)
                                if do_out:
                                    pk_any = (1 << 24) | port
                                    bl_out_port[bl_out_port.Key(pk_any)] = bl_out_port.Leaf(proto=0, port=port, action=1, rate_limit=0, rule_id=rid)

            elif t == "established":
                stateful_enabled[0] = stateful_enabled.Leaf(1)

            elif t == "ratelimit":
                try:
                    pps = int(r.get("value", "0"))
                except (ValueError, TypeError):
                    continue
                if proto == 0:
                    rl_global_cfg[0] = rl_global_cfg.Leaf(pps)
                    rl_global_rule[0] = rl_global_rule.Leaf(rid)
                else:
                    rl_proto_cfg[rl_proto_cfg.Key(proto)] = rl_proto_cfg.Leaf(pps)
                    rl_proto_rule[rl_proto_rule.Key(proto)] = rl_proto_rule.Leaf(rid)

            elif t == "ip_ratelimit":
                try:
                    pps = int(r.get("value", "0"))
                except (ValueError, TypeError):
                    continue
                src = r.get("src")
                if src:
                    try:
                        net = ipaddress.ip_network(src, strict=False)
                        addr = ip_to_be(src)
                        rl_ip_cfg[rl_ip_cfg.Key(prefixlen=net.prefixlen, addr=addr)] = rl_ip_cfg.Leaf(pps=pps, enabled=1, pad=[0,0,0], rule_id=rid)
                    except ValueError:
                        continue

            elif t == "dns":
                dns_wl = b["dns_wl"]
                val = r.get("value", "both")
                if val in ("query", "both"):
                    dns_wl[dns_wl.Key(0)] = dns_wl.Leaf(1)
                    dns_rule[dns_rule.Key(0)] = dns_rule.Leaf(rid)
                if val in ("response", "both"):
                    dns_wl[dns_wl.Key(1)] = dns_wl.Leaf(1)
                    dns_rule[dns_rule.Key(1)] = dns_rule.Leaf(rid)
                if val == "both":
                    dns_wl[dns_wl.Key(2)] = dns_wl.Leaf(1)
                    dns_rule[dns_rule.Key(2)] = dns_rule.Leaf(rid)

            elif t == "forward":
                port_str = r.get("dst_port") or r.get("value", "0")
                try:
                    port = int(port_str)
                except (ValueError, TypeError):
                    continue
                if proto:
                    pk = (proto << 16) | port
                    wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=proto, port=port, action=1, rate_limit=0, rule_id=rid)
                else:
                    for p in (6, 17):
                        pk = (p << 16) | port
                        wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=p, port=port, action=1, rate_limit=0, rule_id=rid)

            elif t == "conn_timeout":
                try:
                    secs = int(r.get("value", "0"))
                except (ValueError, TypeError):
                    continue
                if secs > 0:
                    conn_timeout_cfg[0] = conn_timeout_cfg.Leaf(secs * 1_000_000_000)

    def _masq_exists(self) -> bool:
        try:
            r = subprocess.run(
                ["iptables", "-t", "nat", "-C", "POSTROUTING", "-m", "comment",
                 "--comment", MASQ_COMMENT, "-j", "MASQUERADE"],
                capture_output=True, timeout=5
            )
            return r.returncode == 0
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _apply_nat(self, rules):
        self._flush_nat()
        any_fwd = False
        for r in rules:
            if r.get("type") != "forward" or not r.get("enabled", True):
                continue
            proto = r.get("protocol", "tcp")
            if proto not in ("tcp", "udp"):
                proto = "tcp"
            port = r.get("dst_port") or r.get("value", "")
            fwd_ip = r.get("forward_ip", "")
            fwd_prt = r.get("forward_port") or port
            if not port or not fwd_ip:
                continue
            try:
                ipaddress.ip_address(fwd_ip)
                p_int = int(port)
                fp_int = int(fwd_prt)
                if not (1 <= p_int <= 65535 and 1 <= fp_int <= 65535):
                    continue
            except (ValueError, TypeError):
                continue
            try:
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "PREROUTING",
                     "-p", proto, "--dport", str(p_int),
                     "-m", "comment", "--comment", MASQ_COMMENT,
                     "-j", "DNAT", "--to-destination", f"{fwd_ip}:{fp_int}"],
                    check=True, capture_output=True, timeout=5
                )
                any_fwd = True
                self._nat_rules.append(r)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                print(f"[NAT] iptables PREROUTING fehlgeschlagen: {e}")

        if any_fwd and not self._masq_exists():
            try:
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-m", "comment", "--comment", MASQ_COMMENT, "-j", "MASQUERADE"],
                    check=True, capture_output=True, timeout=5
                )
                self._masq_applied = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                pass
            try:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                               check=True, capture_output=True, timeout=5)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                pass

    def _flush_nat(self):
        for chain in ("PREROUTING", "POSTROUTING"):
            try:
                r = subprocess.run(
                    ["iptables", "-t", "nat", "-S", chain],
                    capture_output=True, timeout=5, text=True
                )
                if r.returncode != 0:
                    continue
                for line in r.stdout.splitlines():
                    if MASQ_COMMENT not in line:
                        continue
                    if not line.startswith("-A "):
                        continue
                    del_line = "-D " + line[3:]
                    try:
                        subprocess.run(
                            ["iptables", "-t", "nat"] + del_line.split(),
                            capture_output=True, timeout=5
                        )
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        pass
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                pass
        self._nat_rules = []
        self._masq_applied = False

    def read_raw_stats(self):
        zero = {"passed": 0, "dropped": 0, "xdp_dropped": 0, "rl_dropped": 0, "bl_dropped": 0,
                "icmp_dropped": 0, "ct_passed": 0, "ct_tracked": 0, "out_dropped": 0,
                "tc_out_blocked": 0, "ipv6_dropped": 0, "bad_dropped": 0,
                "proto": {"tcp":   {"pass_pkts": 0, "drop_pkts": 0, "pass_bytes": 0, "drop_bytes": 0},
                          "udp":   {"pass_pkts": 0, "drop_pkts": 0, "pass_bytes": 0, "drop_bytes": 0},
                          "icmp":  {"pass_pkts": 0, "drop_pkts": 0, "pass_bytes": 0, "drop_bytes": 0},
                          "other": {"pass_pkts": 0, "drop_pkts": 0, "pass_bytes": 0, "drop_bytes": 0}},
                "egress": {"tcp":   {"pkts": 0, "bytes": 0, "drop_pkts": 0, "drop_bytes": 0},
                           "udp":   {"pkts": 0, "bytes": 0, "drop_pkts": 0, "drop_bytes": 0},
                           "icmp":  {"pkts": 0, "bytes": 0, "drop_pkts": 0, "drop_bytes": 0},
                           "other": {"pkts": 0, "bytes": 0, "drop_pkts": 0, "drop_bytes": 0}},
                "bytes_total": {"pass": 0, "drop": 0}}
        if not BCC_AVAILABLE or not self.bpf or not self.loaded:
            return zero
        try:
            s = self.bpf["stats"]
            def sv(i: int) -> int:
                try:
                    return int(s[i].value)
                except Exception:
                    return 0
            xdp_dropped = sv(1)
            out_dropped = sv(7)
            out = {
                "passed":        sv(0),
                "dropped":       xdp_dropped + out_dropped,
                "xdp_dropped":   xdp_dropped,
                "rl_dropped":    sv(2),
                "bl_dropped":    sv(3),
                "icmp_dropped":  sv(4),
                "ct_passed":     sv(5),
                "ct_tracked":    sv(6),
                "out_dropped":   out_dropped,
                "tc_out_blocked":out_dropped,
                "ipv6_dropped":  sv(8),
                "bad_dropped":   sv(9),
            }
        except Exception:
            return zero

        proto_out = {k: {"pass_pkts": 0, "drop_pkts": 0, "pass_bytes": 0, "drop_bytes": 0}
                     for k in ("tcp", "udp", "icmp", "other")}
        bytes_pass_total = 0
        bytes_drop_total = 0
        try:
            pp = self.bpf["proto_pkts"]
            pb = self.bpf["proto_bytes"]
            names = ("tcp", "udp", "icmp", "other")
            for slot, name in enumerate(names):
                base = slot << 1
                pp_pass  = int(pp[base].value)
                pp_drop  = int(pp[base | 1].value)
                pb_pass  = int(pb[base].value)
                pb_drop  = int(pb[base | 1].value)
                proto_out[name] = {
                    "pass_pkts":  pp_pass,
                    "drop_pkts":  pp_drop,
                    "pass_bytes": pb_pass,
                    "drop_bytes": pb_drop,
                }
                bytes_pass_total += pb_pass
                bytes_drop_total += pb_drop
        except Exception:
            pass
        out["proto"] = proto_out
        out["bytes_total"] = {"pass": bytes_pass_total, "drop": bytes_drop_total}

        egress_out = {k: {"pkts": 0, "bytes": 0, "drop_pkts": 0, "drop_bytes": 0}
                      for k in ("tcp", "udp", "icmp", "other")}
        try:
            ep = self.bpf["egress_pkts"]
            eb = self.bpf["egress_bytes"]
            edp = None
            edb = None
            try:
                edp = self.bpf["egress_drop_pkts"]
                edb = self.bpf["egress_drop_bytes"]
            except Exception:
                pass
            names = ("tcp", "udp", "icmp", "other")
            for slot, name in enumerate(names):
                egress_out[name] = {
                    "pkts":       int(ep[slot].value),
                    "bytes":      int(eb[slot].value),
                    "drop_pkts":  int(edp[slot].value) if edp else 0,
                    "drop_bytes": int(edb[slot].value) if edb else 0,
                }
        except Exception:
            pass
        out["egress"] = egress_out

        return out

    def read_rule_hits(self):
        out = {}
        if not BCC_AVAILABLE or not self.bpf or not self.loaded:
            return out
        try:
            mt = self.bpf["rule_hits"]
        except Exception:
            return out
        mp = None
        md = None
        try:
            mp = self.bpf["rule_pass_hits"]
            md = self.bpf["rule_drop_hits"]
        except Exception:
            pass
        id_map = self._rule_id_map
        for numeric_id, string_id in id_map.items():
            try:
                total = int(mt[numeric_id].value)
            except Exception:
                total = 0
            try:
                passed = int(mp[numeric_id].value) if mp else 0
            except Exception:
                passed = 0
            try:
                dropped = int(md[numeric_id].value) if md else 0
            except Exception:
                dropped = 0
            out[string_id] = {"total": total, "pass": passed, "drop": dropped}
        return out

    def set_ipv6_policy(self, allow: bool):
        self.ipv6_allow = bool(allow)
        with self._lock:
            if self.bpf and self.loaded:
                try:
                    m = self.bpf["ipv6_policy"]
                    m[0] = m.Leaf(1 if self.ipv6_allow else 0)
                except Exception as e:
                    print(f"[IPV6] Map-Update fehlgeschlagen: {e}")

    def _gc_conntrack(self):
        if not self.bpf or not self.loaded:
            return
        try:
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        except (AttributeError, OSError):
            now = time.monotonic_ns()
        try:
            ct = self.bpf["conntrack"]
            max_age = 0
            try:
                cfg = self.bpf["conn_timeout_cfg"]
                v = cfg[0]
                max_age = v.value if v else 0
            except Exception:
                pass
            to_delete = []
            for k, v in ct.items():
                proto = k.proto
                state = v.state
                if proto == 6:
                    timeout = 300_000_000_000 if state == 2 else 30_000_000_000
                elif proto == 17:
                    timeout = 120_000_000_000
                else:
                    timeout = 30_000_000_000
                idle = now - v.last_seen > timeout
                aged = max_age > 0 and v.created > 0 and (now - v.created > max_age)
                if idle or aged:
                    to_delete.append(k)
            for k in to_delete:
                try:
                    ct.__delitem__(k)
                except Exception:
                    pass
        except Exception:
            pass

    def _gc_rl_state(self):
        if not self.bpf or not self.loaded:
            return
        try:
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        except (AttributeError, OSError):
            now = time.monotonic_ns()
        stale = 5_000_000_000
        for map_name in ("rl_ip_state", "dns_rl_state", "rl_port_state", "per_ip_port_state"):
            try:
                m = self.bpf[map_name]
                to_delete = []
                for k, v in m.items():
                    if now - v.window_start > stale:
                        to_delete.append(k)
                for k in to_delete:
                    try:
                        m.__delitem__(k)
                    except Exception:
                        pass
            except Exception:
                pass

    def _start_poll(self):
        prev = self._poll
        if prev and prev.is_alive():
            self._run = False
            prev.join(timeout=2)
        self._run = True

        def _loop():
            gc_tick = 0
            while self._run:
                time.sleep(1)
                try:
                    st = self.read_raw_stats()
                    bt = st.get("bytes_total") or {"pass": 0, "drop": 0}
                    ring.push(time.monotonic(), st["passed"], st["dropped"],
                              bt.get("pass", 0), bt.get("drop", 0))
                except Exception:
                    pass
                gc_tick += 1
                if gc_tick >= 10:
                    gc_tick = 0
                    self._gc_conntrack()
                    self._gc_rl_state()

        self._poll = threading.Thread(target=_loop, daemon=True, name="xdp-poll")
        self._poll.start()

    def detach(self):
        self._run = False
        poll = self._poll
        if poll and poll.is_alive():
            poll.join(timeout=2)
        self._flush_nat()
        self._detach_tc()
        with self._lock:
            if self.bpf and self.loaded:
                try:
                    if BCC_AVAILABLE:
                        for ifc in self.ifaces:
                            try:
                                self.bpf.remove_xdp(ifc, flags=BPF.XDP_FLAGS_SKB_MODE)
                            except Exception:
                                pass
                except Exception:
                    pass
                self.loaded = False
                self.ifaces = []
                self._cleanup_bpf(self.bpf)
                self.bpf = None


xdp = XDPFirewall()
app = FastAPI(title="XDP Firewall", version="5.1", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    if request.url.path in ("/", "/login"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


PUBLIC_PATHS = frozenset({"/login", "/api/login", "/healthz"})


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        return await call_next(request)
    if path == "/":
        sid = request.cookies.get("sid", "")
        if _validate_session(sid):
            return await call_next(request)
        return RedirectResponse(url="/login", status_code=302)
    if not _check_auth(request):
        if path.startswith("/api/"):
            return JSONResponse(status_code=401, content={"detail": "Nicht autorisiert"})
        return RedirectResponse(url="/login", status_code=302)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sid = request.cookies.get("sid", "")
        if _validate_session(sid):
            origin = request.headers.get("origin", "")
            host = request.headers.get("host", "")
            if origin:
                try:
                    from urllib.parse import urlparse
                    oh = urlparse(origin).netloc
                    if oh and oh != host:
                        return JSONResponse(status_code=403, content={"detail": "CSRF: Origin-Mismatch"})
                except Exception:
                    return JSONResponse(status_code=403, content={"detail": "CSRF: Origin ungültig"})
    return await call_next(request)


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    try:
        html = (BASE_DIR / "login.html").read_text()
    except FileNotFoundError:
        html = _FALLBACK_LOGIN_HTML
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store, max-age=0"})


@app.post("/api/login")
async def login(req: LoginRequest, request: Request, response: Response):
    ip = _client_ip(request)
    wait = _auth_throttle_check(ip)
    if wait is not None:
        return JSONResponse(status_code=429, content={"detail": f"Zu viele Fehlversuche. Warte {wait}s."})
    ok = hmac.compare_digest(req.password, API_KEY)
    if not ok:
        _auth_record_failure(ip)
        return JSONResponse(status_code=401, content={"detail": "Falsches Passwort"})
    _auth_reset_failure(ip)
    sid = _create_session(ip)
    secure = request.url.scheme == "https" or USE_TLS
    response = JSONResponse(content={"ok": True})
    response.set_cookie(
        key="sid", value=sid, max_age=SESSION_TTL,
        httponly=True, samesite="strict", secure=secure, path="/"
    )
    return response


@app.post("/api/logout")
async def logout(request: Request):
    sid = request.cookies.get("sid", "")
    _destroy_session(sid)
    response = JSONResponse(content={"ok": True})
    response.delete_cookie("sid", path="/")
    return response


@app.get("/api/auth/check")
async def auth_check():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
async def root():
    html = (BASE_DIR / "index.html").read_text()
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store, max-age=0"})


@app.get("/api/rules")
async def get_rules():
    rules = xdp.load_rules()
    hits = xdp.read_rule_hits()
    for r in rules:
        rid = r.get("id", "")
        c = hits.get(rid, {"total": 0, "pass": 0, "drop": 0})
        if isinstance(c, dict):
            r["hit_count"] = int(c.get("total", 0) or 0)
            r["hit_pass_count"] = int(c.get("pass", 0) or 0)
            r["hit_drop_count"] = int(c.get("drop", 0) or 0)
        else:
            r["hit_count"] = int(c or 0)
            r["hit_pass_count"] = 0
            r["hit_drop_count"] = 0
    return rules


@app.post("/api/rules")
async def add_rule(rule: FirewallRule):
    rules = xdp.load_rules()
    if len(rules) >= 500:
        raise HTTPException(400, "Max 500 Regeln")
    rule.id = uuid.uuid4().hex[:8]
    rules.append(rule.model_dump())
    xdp.save_rules(rules)
    return {"ok": True, "rule": rule}


@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: str, rule: FirewallRule):
    if len(rule_id) > 64 or not re.match(r'^[a-zA-Z0-9_-]+$', rule_id):
        raise HTTPException(400, "Ungültige ID")
    rules = xdp.load_rules()
    for i, r in enumerate(rules):
        if r.get("id") == rule_id:
            rule.id = rule_id
            rules[i] = rule.model_dump()
            xdp.save_rules(rules)
            return {"ok": True, "rule": rule}
    raise HTTPException(404, "Nicht gefunden")


@app.patch("/api/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str):
    if len(rule_id) > 64 or not re.match(r'^[a-zA-Z0-9_-]+$', rule_id):
        raise HTTPException(400, "Ungültige ID")
    rules = xdp.load_rules()
    for r in rules:
        if r.get("id") == rule_id:
            r["enabled"] = not r.get("enabled", True)
            xdp.save_rules(rules)
            return {"ok": True, "enabled": r["enabled"]}
    raise HTTPException(404, "Nicht gefunden")


@app.post("/api/rules/{rule_id}/duplicate")
async def duplicate_rule(rule_id: str):
    if len(rule_id) > 64 or not re.match(r'^[a-zA-Z0-9_-]+$', rule_id):
        raise HTTPException(400, "Ungültige ID")
    rules = xdp.load_rules()
    for r in rules:
        if r.get("id") == rule_id:
            try:
                validated = FirewallRule(**r)
            except Exception as e:
                raise HTTPException(400, f"Original-Regel ungültig: {e}")
            new_rule = validated.model_dump()
            new_rule["id"] = uuid.uuid4().hex[:8]
            new_rule["comment"] = (r.get("comment", "") + " (Kopie)").strip()[:200]
            rules.append(new_rule)
            xdp.save_rules(rules)
            return {"ok": True, "rule": new_rule}
    raise HTTPException(404, "Nicht gefunden")


@app.post("/api/rules/reorder")
async def reorder_rules(req: ReorderRequest):
    rules = xdp.load_rules()
    by_id = {r.get("id"): r for r in rules}
    ordered = []
    for rid in req.order:
        if rid in by_id:
            ordered.append(by_id.pop(rid))
    for leftover in by_id.values():
        ordered.append(leftover)
    xdp.save_rules(ordered)
    return {"ok": True}


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    if len(rule_id) > 64 or not re.match(r'^[a-zA-Z0-9_-]+$', rule_id):
        raise HTTPException(400, "Ungültige ID")
    rules = xdp.load_rules()
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        raise HTTPException(404, "Nicht gefunden")
    xdp.save_rules(new_rules)
    return {"ok": True}


@app.post("/api/apply")
async def apply_rules(req: ApplyRequest):
    rules = xdp.load_rules()
    iface = req.iface or IFACE
    try:
        msg = xdp.apply_runtime(rules, iface)
        if msg is None:
            msg = xdp.compile_and_attach(rules, iface)
        return {"ok": True, "message": msg, "reloaded": msg.startswith("XDP neu geladen"), "configured_iface": xdp.configured_iface(), "iface": ",".join(xdp.ifaces) if xdp.ifaces else ""}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/detach")
async def detach():
    xdp.detach()
    return {"ok": True, "message": "XDP getrennt."}


@app.get("/api/stats")
async def stats():
    raw = xdp.read_raw_stats()
    pp, dp = ring.pps()
    pb, db = ring.bps()
    return {**raw,
            "pass_pps": round(pp, 1), "drop_pps": round(dp, 1), "total_pps": round(pp + dp, 1),
            "pass_bps": round(pb, 1), "drop_bps": round(db, 1), "total_bps": round(pb + db, 1),
            "loaded": xdp.loaded,
            "iface": ",".join(xdp.ifaces) if xdp.ifaces else "",
            "rules": len(xdp.load_rules()),
            "history": ring.history(300),
            "configured_iface": xdp.configured_iface(),
            "tc_active": len(xdp.tc_attached) > 0,
            "ipv6_allow": xdp.ipv6_allow}



@app.get("/api/rule-hits")
async def rule_hits():
    return {"hits": xdp.read_rule_hits()}


@app.get("/api/status")
async def status():
    return {"loaded": xdp.loaded,
            "iface": ",".join(xdp.ifaces) if xdp.ifaces else "",
            "rules": len(xdp.load_rules()),
            "bcc": BCC_AVAILABLE, "pyroute2": PYROUTE2_AVAILABLE,
            "configured_iface": xdp.configured_iface(),
            "tc_active": len(xdp.tc_attached) > 0,
            "ipv6_allow": xdp.ipv6_allow}


@app.post("/api/ipv6")
async def set_ipv6(req: IPv6PolicyRequest):
    xdp.set_ipv6_policy(req.allow)
    return {"ok": True, "ipv6_allow": xdp.ipv6_allow}


@app.get("/api/stream")
async def stream(request: Request):
    async def gen() -> AsyncIterator[str]:
        while True:
            if await request.is_disconnected():
                break
            try:
                raw = xdp.read_raw_stats()
                pp, dp = ring.pps()
                pb, db = ring.bps()
                d = {**raw,
                     "pass_pps": round(pp, 1), "drop_pps": round(dp, 1), "total_pps": round(pp + dp, 1),
                     "pass_bps": round(pb, 1), "drop_bps": round(db, 1), "total_bps": round(pb + db, 1),
                     "loaded": xdp.loaded,
                     "iface": ",".join(xdp.ifaces) if xdp.ifaces else "",
                     "rules": len(xdp.load_rules()),
                     "configured_iface": xdp.configured_iface(),
                     "tc_active": len(xdp.tc_attached) > 0,
                     "ipv6_allow": xdp.ipv6_allow}
                yield f"data: {json.dumps(d)}\n\n"
            except Exception:
                yield f"data: {json.dumps({'error': 'stats_unavailable'})}\n\n"
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.on_event("startup")
async def on_start():
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.access").disabled = True
    rules = xdp.load_rules()
    if rules:
        try:
            xdp.compile_and_attach(rules, _load_iface_config())
        except Exception as e:
            print(f"[STARTUP] XDP konnte nicht geladen werden: {e}")


@app.on_event("shutdown")
async def on_shutdown():
    try:
        xdp.detach()
    except Exception:
        pass


_FALLBACK_LOGIN_HTML = """<!doctype html><html lang="de"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>XDP Firewall Login</title>
<style>body{font-family:system-ui,sans-serif;background:#0e1117;color:#dde4f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#1d2236;border:1px solid #2a3152;padding:30px;border-radius:10px;min-width:320px}
h1{font-size:16px;margin:0 0 18px;font-weight:500}
input{width:100%;padding:10px;background:#161b27;border:1px solid #344070;color:#dde4f5;border-radius:5px;font-size:14px;outline:none;box-sizing:border-box}
input:focus{border-color:#5b9bf8}
button{width:100%;padding:10px;margin-top:12px;background:#5b9bf8;color:#fff;border:0;border-radius:5px;font-weight:600;cursor:pointer;font-size:14px}
button:hover{background:#4a88e8}
.err{color:#f05252;font-size:12px;margin-top:10px;min-height:16px}</style></head>
<body><div class="box"><h1>XDP Firewall Login</h1>
<form id="f" onsubmit="login(event)"><input id="pw" type="password" placeholder="API-Key / Passwort" autofocus autocomplete="current-password">
<button type="submit">Anmelden</button><div class="err" id="e"></div></form>
<script>async function login(e){e.preventDefault();var pw=document.getElementById('pw').value;
var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({password:pw})});
if(r.ok){location.href='/'}else{var j=await r.json().catch(function(){return{detail:'Fehler'}});document.getElementById('e').textContent=j.detail||'Fehler'}}</script>
</div></body></html>"""


_LOG_CFG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"default": {"()": "uvicorn.logging.DefaultFormatter", "fmt": "%(levelprefix)s %(message)s"}},
    "handlers": {"default": {"class": "logging.StreamHandler", "formatter": "default", "stream": "ext://sys.stderr"}},
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO"},
        "uvicorn.access": {"handlers": [], "level": "WARNING", "propagate": False},
    },
}


if __name__ == "__main__":
    tls_ok = USE_TLS and _ensure_tls_cert()
    if tls_ok:
        print(f"[HTTPS] Starte auf Port {HTTPS_PORT} mit TLS")
        uvicorn.run(app, host="0.0.0.0", port=HTTPS_PORT,
                    ssl_keyfile=str(KEY_FILE), ssl_certfile=str(CERT_FILE),
                    loop="asyncio", log_config=_LOG_CFG)
    else:
        print(f"[HTTP] Starte auf Port {HTTP_PORT} OHNE TLS (NICHT für Produktion!)")
        uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT, loop="asyncio", log_config=_LOG_CFG)
