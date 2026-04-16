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
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel, field_validator, model_validator

logging.getLogger("uvicorn.access").handlers = []
logging.getLogger("uvicorn.access").propagate = False

BASE_DIR   = Path(__file__).parent
RULES_FILE = BASE_DIR / "rules.json"
XDP_SRC    = BASE_DIR / "xdp_firewall.c"
IFACE      = os.environ.get("XDP_IFACE", "eth0")
API_KEY_FILE = BASE_DIR / "api_key.txt"

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

API_KEY = _load_or_create_api_key()

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

try:
    from pyroute2 import IPRoute
    PYROUTE2_AVAILABLE = True
except ImportError:
    PYROUTE2_AVAILABLE = False


def _bpf_pin(fd: int, path: str) -> None:
    """Pinnt einen geladenen BPF-Prog-FD nach /sys/fs/bpf/ via Syscall."""
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
    attr.pathname  = ctypes.cast(buf, ctypes.c_void_p).value
    attr.bpf_fd    = fd
    attr.file_flags = 0
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(_NR, BPF_OBJ_PIN, ctypes.byref(attr), ctypes.sizeof(attr)) < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

PROTO_MAP   = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
VALID_TYPES = frozenset(("filter", "established", "forward", "ratelimit", "dns", "ip_ratelimit", "conn_timeout"))
IP_RE       = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
IFACE_RE    = re.compile(r'^[a-zA-Z0-9_-]{1,15}$')

_rules_cache: Optional[list] = None
_rules_mtime: float = 0


def ip_to_be(ip: str) -> int:
    net = ipaddress.ip_network(ip, strict=False)
    return struct.unpack('<I', net.network_address.packed)[0]


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
            if not IP_RE.match(self.forward_ip.split("/")[0]):
                raise ValueError("Ungültige forward_ip")
            if not self.forward_port:
                self.forward_port = self.dst_port
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
        if v and not IFACE_RE.match(v.split(',')[0].strip()):
            raise ValueError("Ungültiger Interface-Name")
        return v


class ReorderRequest(BaseModel):
    order: list[str]


class StatsRing:
    __slots__ = ('_ring', '_lock')

    def __init__(self):
        self._ring: deque = deque(maxlen=120)
        self._lock = threading.Lock()

    def push(self, ts, passed, dropped):
        with self._lock:
            self._ring.append((ts, passed, dropped))

    def pps(self):
        with self._lock:
            if len(self._ring) < 2:
                return 0.0, 0.0
            t0, p0, d0 = self._ring[-2]
            t1, p1, d1 = self._ring[-1]
        dt = t1 - t0
        return ((p1 - p0) / dt, (d1 - d0) / dt) if dt > 0 else (0.0, 0.0)

    def history(self, n=60):
        with self._lock:
            ring = list(self._ring)
        out = []
        ln = len(ring)
        for i in range(1, min(n + 1, ln)):
            t0, p0, d0 = ring[-i - 1] if i + 1 <= ln else ring[0]
            t1, p1, d1 = ring[-i]
            dt = t1 - t0
            if dt > 0:
                out.append({"ts": t1, "pass_pps": round((p1 - p0) / dt, 1), "drop_pps": round((d1 - d0) / dt, 1)})
        out.reverse()
        return out


ring = StatsRing()


class XDPFirewall:
    __slots__ = ('bpf', 'loaded', 'ifaces', '_lock', '_poll', '_run', '_nat_rules', 'tc_attached')

    def __init__(self):
        self.bpf = None
        self.loaded = False
        self.ifaces = []
        self._lock = threading.Lock()
        self._poll = None
        self._run = False
        self._nat_rules = []
        self.tc_attached = []

    def load_rules(self):
        global _rules_cache, _rules_mtime
        if not RULES_FILE.exists():
            return []
        try:
            mt = RULES_FILE.stat().st_mtime
            if _rules_cache is not None and mt == _rules_mtime:
                return _rules_cache
            data = json.loads(RULES_FILE.read_text())
            if isinstance(data, list):
                _rules_cache = data
                _rules_mtime = mt
                return data
        except (json.JSONDecodeError, IOError, OSError):
            pass
        return []

    def save_rules(self, rules):
        global _rules_cache, _rules_mtime
        tmp = RULES_FILE.with_suffix('.tmp')
        tmp.write_text(json.dumps(rules, indent=2))
        tmp.replace(RULES_FILE)
        _rules_cache = rules
        _rules_mtime = RULES_FILE.stat().st_mtime

    def compile_and_attach(self, rules, iface):
        if not BCC_AVAILABLE:
            return "BCC nicht verfügbar"
        ifaces = [i.strip() for i in iface.split(',') if i.strip() and IFACE_RE.match(i.strip())]
        if not ifaces:
            raise ValueError("Keine gültigen Interfaces")
        with self._lock:
            if self.bpf and self.loaded:
                try:
                    for old in self.ifaces:
                        self.bpf.remove_xdp(old, flags=BPF.XDP_FLAGS_SKB_MODE)
                except Exception:
                    pass
                self._detach_tc()
                self.loaded = False

            b = BPF(text=XDP_SRC.read_text())
            fn = b.load_func("xdp_firewall", BPF.XDP)
            attached = []
            for ifc in ifaces:
                try:
                    b.attach_xdp(ifc, fn, flags=BPF.XDP_FLAGS_SKB_MODE)
                    attached.append(ifc)
                except Exception:
                    pass
            if not attached:
                raise ValueError("Konnte auf keinem Interface laden")

            self.bpf = b
            self.ifaces = attached
            self.loaded = True
            self._populate_maps(rules)
            self._apply_nat(rules)

            has_est = any(r.get("type") == "established" and r.get("enabled", True) for r in rules)
            tc_ok = False
            if has_est:
                tc_ok = self._attach_tc(b, attached)

            self._start_poll()

        tc_msg = ""
        if has_est:
            tc_msg = " + TC-Conntrack aktiv" if tc_ok else " + TC fehlgeschlagen (kein Conntrack)"

        return f"XDP auf {len(attached)} Interfaces – {len(rules)} Regeln{tc_msg}"

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
                print(f"[TC] Alle Methoden auf {ifc} fehlgeschlagen – kein TC-Conntrack")

        self.tc_attached = attached
        return len(attached) > 0

    def _tc_pyroute2(self, fn_tc, ifc) -> bool:

        if not PYROUTE2_AVAILABLE:
            return False
        ipr = None
        try:
            ipr = IPRoute()
            idx = ipr.link_lookup(ifname=ifc)[0]
            try:
                ipr.tc("add", "clsact", idx)
            except Exception:
                pass  

          
            attempts = [
                dict(fd=fn_tc.fd, name=fn_tc.name, parent="ffff:fff3",
                     classid=1, direct_act=True),
                dict(fd=fn_tc.fd, name=fn_tc.name, parent="ffff:fff3",
                     direct_act=True),
                dict(fd=fn_tc.fd, name=fn_tc.name, parent="ffff:fff3",
                     classid=1, direct_act=True, protocol=3),  
            ]
            for kw in attempts:
                try:
                    ipr.tc("add-filter", "bpf", idx, ":1", **kw)
                    print(f"[TC] pyroute2 OK auf {ifc}")
                    return True
                except Exception as e:
                    print(f"[TC] pyroute2 Versuch fehlgeschlagen ({kw}): {e}")
            return False
        except Exception as e:
            print(f"[TC] pyroute2 generell fehlgeschlagen auf {ifc}: {e}")
            return False
        finally:
            if ipr:
                try:
                    ipr.close()
                except Exception:
                    pass

    def _tc_cli(self, fd: int, ifc: str) -> bool:

        pin = f"/sys/fs/bpf/fw_egress_{ifc}"
        try:
            try:
                os.unlink(pin)
            except OSError:
                pass

            _bpf_pin(fd, pin)  

            subprocess.run(["tc", "qdisc", "add", "dev", ifc, "clsact"],
                           capture_output=True, timeout=5)  

            r = subprocess.run(
                ["tc", "filter", "add", "dev", ifc, "egress",
                 "bpf", "pinned", pin, "direct-action"],
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
        for ifc in self.tc_attached:
            try:
              
                if PYROUTE2_AVAILABLE:
                    ipr = IPRoute()
                    idx = ipr.link_lookup(ifname=ifc)[0]
                    ipr.tc("del", "clsact", idx)
                    ipr.close()
                else:
                    subprocess.run(["tc", "qdisc", "del", "dev", ifc, "clsact"],
                                   capture_output=True, timeout=5)
            except Exception:
                pass

            try:
                os.unlink(f"/sys/fs/bpf/fw_egress_{ifc}")
            except OSError:
                pass
        self.tc_attached = []

    def _populate_maps(self, rules):
        b = self.bpf
        wl_subnet = b["wl_subnet"]
        bl_subnet = b["bl_subnet"]
        wl_port = b["wl_port"]
        bl_port = b["bl_port"]
        wl_icmp = b["wl_icmp"]
        rl_global_cfg = b["rl_global_cfg"]
        rl_proto_cfg = b["rl_proto_cfg"]
        rl_ip_cfg = b["rl_ip_cfg"]
        rl_port_cfg = b["rl_port_cfg"]
        dns_rl_cfg = b["dns_rl_cfg"]
        stateful_enabled = b["stateful_enabled"]
        conn_timeout_cfg = b["conn_timeout_cfg"]
        per_ip_port_cfg = b["per_ip_port_cfg"]
        bl_out_port = b["bl_out_port"]
        bl_out_subnet = b["bl_out_subnet"]
        ipv6_policy = b["ipv6_policy"]

        rl_global_cfg[0] = rl_global_cfg.Leaf(0)
        stateful_enabled[0] = stateful_enabled.Leaf(0)
        conn_timeout_cfg[0] = conn_timeout_cfg.Leaf(0)
        ipv6_policy[0] = ipv6_policy.Leaf(0)

        for r in rules:
            if not r.get("enabled", True):
                continue
            t = r.get("type", "filter")
            proto = PROTO_MAP.get(r.get("protocol", "any"), 0)
            rl = r.get("rate_limit") or 0
            pip = r.get("per_ip_limit") or 0
            src_port = r.get("src_port", "any") or "any"

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
                        wl_icmp[wl_icmp.Key(key16)] = wl_icmp.Leaf(1)
                        if rl > 0:
                            rl_proto_cfg[rl_proto_cfg.Key(1)] = rl_proto_cfg.Leaf(rl)
                        if pip > 0:
                            icmp_pk = (1 << 16) | 0xFFFF
                            per_ip_port_cfg[per_ip_port_cfg.Key(icmp_pk)] = per_ip_port_cfg.Leaf(pip)
                    elif src != "any":
                        try:
                            net = ipaddress.ip_network(src, strict=False)
                            addr = ip_to_be(src)
                        except ValueError:
                            continue
                        port = 0 if dst_port == "any" else int(dst_port)
                        wl_subnet[wl_subnet.Key(prefixlen=net.prefixlen, addr=addr)] = wl_subnet.Leaf(proto=proto, port=port, action=1, rate_limit=rl)
                    else:
                        if dst_port != "any":
                            port = int(dst_port)
                            if proto:
                                pk = (proto << 16) | port
                                wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=proto, port=port, action=1, rate_limit=rl)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                            else:
                                for p in (6, 17):
                                    pk = (p << 16) | port
                                    wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=p, port=port, action=1, rate_limit=rl)
                                    if rl > 0:
                                        rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                    if pip > 0:
                                        per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                                wl_port[wl_port.Key(port)] = wl_port.Leaf(proto=0, port=port, action=1, rate_limit=rl)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(port)] = rl_port_cfg.Leaf(rl)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(port)] = per_ip_port_cfg.Leaf(pip)
                        if src_port != "any":
                            port = int(src_port)
                            if proto:
                                pk = (proto << 16) | port
                                wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=proto, port=port, action=1, rate_limit=rl)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                            else:
                                for p in (6, 17):
                                    pk = (p << 16) | port
                                    wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=p, port=port, action=1, rate_limit=rl)
                                    if rl > 0:
                                        rl_port_cfg[rl_port_cfg.Key(pk)] = rl_port_cfg.Leaf(rl)
                                    if pip > 0:
                                        per_ip_port_cfg[per_ip_port_cfg.Key(pk)] = per_ip_port_cfg.Leaf(pip)
                                wl_port[wl_port.Key(port)] = wl_port.Leaf(proto=0, port=port, action=1, rate_limit=rl)
                                if rl > 0:
                                    rl_port_cfg[rl_port_cfg.Key(port)] = rl_port_cfg.Leaf(rl)
                                if pip > 0:
                                    per_ip_port_cfg[per_ip_port_cfg.Key(port)] = per_ip_port_cfg.Leaf(pip)
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
                        if do_in:
                            bl_subnet[bl_subnet.Key(prefixlen=net.prefixlen, addr=addr)] = bl_subnet.Leaf(1)
                        if do_out:
                            bl_out_subnet[bl_out_subnet.Key(prefixlen=net.prefixlen, addr=addr)] = bl_out_subnet.Leaf(1)
                    elif dst_port != "any":
                        port = int(dst_port)
                        if proto:
                            pk = (proto << 16) | port
                            if do_in:
                                bl_port[bl_port.Key(pk)] = bl_port.Leaf(1)
                            if do_out:
                                bl_out_port[bl_out_port.Key(pk)] = bl_out_port.Leaf(1)
                        else:
                            for p in (6, 17):
                                pk = (p << 16) | port
                                if do_in:
                                    bl_port[bl_port.Key(pk)] = bl_port.Leaf(1)
                                if do_out:
                                    bl_out_port[bl_out_port.Key(pk)] = bl_out_port.Leaf(1)
                            if do_in:
                                bl_port[bl_port.Key(port)] = bl_port.Leaf(1)
                            if do_out:
                                bl_out_port[bl_out_port.Key(port)] = bl_out_port.Leaf(1)

            elif t == "established":
                stateful_enabled[0] = stateful_enabled.Leaf(1)

            elif t == "ratelimit":
                try:
                    pps = int(r.get("value", "0"))
                except (ValueError, TypeError):
                    continue
                if proto == 0:
                    rl_global_cfg[0] = rl_global_cfg.Leaf(pps)
                else:
                    rl_proto_cfg[rl_proto_cfg.Key(proto)] = rl_proto_cfg.Leaf(pps)

            elif t == "ip_ratelimit":
                try:
                    pps = int(r.get("value", "0"))
                except (ValueError, TypeError):
                    continue
                if src := r.get("src"):
                    try:
                        net = ipaddress.ip_network(src, strict=False)
                        addr = ip_to_be(src)
                        rl_ip_cfg[rl_ip_cfg.Key(prefixlen=net.prefixlen, addr=addr)] = rl_ip_cfg.Leaf(pps=pps, enabled=1, pad=[0,0,0])
                    except ValueError:
                        continue

            elif t == "dns":
                dns_wl = b["dns_wl"]
                val = r.get("value", "both")
                if val in ("query", "both"):
                    dns_wl[dns_wl.Key(0)] = dns_wl.Leaf(1)
                if val in ("response", "both"):
                    dns_wl[dns_wl.Key(1)] = dns_wl.Leaf(1)
                if val == "both":
                    dns_wl[dns_wl.Key(2)] = dns_wl.Leaf(1)

            elif t == "forward":
                port_str = r.get("dst_port") or r.get("value", "0")
                try:
                    port = int(port_str)
                except (ValueError, TypeError):
                    continue
                if proto:
                    pk = (proto << 16) | port
                    wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=proto, port=port, action=1, rate_limit=0)
                else:
                    for p in (6, 17):
                        pk = (p << 16) | port
                        wl_port[wl_port.Key(pk)] = wl_port.Leaf(proto=p, port=port, action=1, rate_limit=0)

            elif t == "conn_timeout":
                try:
                    secs = int(r.get("value", "0"))
                except (ValueError, TypeError):
                    continue
                if secs > 0:
                    conn_timeout_cfg[0] = conn_timeout_cfg.Leaf(secs * 1_000_000_000)

    def _apply_nat(self, rules):
        self._flush_nat()
        for r in rules:
            if r.get("type") != "forward" or not r.get("enabled", True):
                continue
            proto = r.get("protocol", "tcp")
            if proto in ("any", ""):
                proto = "tcp"
            port = r.get("dst_port") or r.get("value", "")
            fwd_ip = r.get("forward_ip", "")
            fwd_prt = r.get("forward_port") or port
            if not port or not fwd_ip:
                continue
            try:
                ipaddress.ip_address(fwd_ip)
                int(port)
                int(fwd_prt)
            except (ValueError, TypeError):
                continue
            try:
                subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", proto, "--dport", str(port), "-j", "DNAT", "--to-destination", f"{fwd_ip}:{fwd_prt}"], check=True, capture_output=True, timeout=5)
                subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"], check=True, capture_output=True, timeout=5)
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True, timeout=5)
                self._nat_rules.append(r)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass

    def _flush_nat(self):
        try:
            subprocess.run(["iptables", "-t", "nat", "-F", "PREROUTING"], capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        self._nat_rules = []

    def read_raw_stats(self):
        if not BCC_AVAILABLE or not self.bpf or not self.loaded:
            return {"passed": 0, "dropped": 0, "rl_dropped": 0, "bl_dropped": 0, "icmp_dropped": 0, "ct_passed": 0, "ct_tracked": 0, "out_dropped": 0}
        try:
            s = self.bpf["stats"]
            return {
                "passed": int(s[0].value),
                "dropped": int(s[1].value),
                "rl_dropped": int(s[2].value),
                "bl_dropped": int(s[3].value),
                "icmp_dropped": int(s[4].value),
                "ct_passed": int(s[5].value),
                "ct_tracked": int(s[6].value),
                "out_dropped": int(s[7].value),
            }
        except Exception:
            return {"passed": 0, "dropped": 0, "rl_dropped": 0, "bl_dropped": 0, "icmp_dropped": 0, "ct_passed": 0, "ct_tracked": 0, "out_dropped": 0}

    def _gc_conntrack(self):
        if not self.bpf or not self.loaded:
            return
        try:
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
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
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
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
        self._run = False
        if self._poll and self._poll.is_alive():
            self._poll.join(timeout=1)
        self._run = True
        def _loop():
            gc_tick = 0
            while self._run:
                time.sleep(1)
                try:
                    st = self.read_raw_stats()
                    ring.push(time.monotonic(), st["passed"], st["dropped"])
                except Exception:
                    pass
                gc_tick += 1
                if gc_tick >= 10:
                    gc_tick = 0
                    self._gc_conntrack()
                    self._gc_rl_state()
        self._poll = threading.Thread(target=_loop, daemon=True)
        self._poll.start()

    def detach(self):
        self._run = False
        self._flush_nat()
        self._detach_tc()
        with self._lock:
            if self.bpf and self.loaded:
                try:
                    if BCC_AVAILABLE:
                        for ifc in self.ifaces:
                            self.bpf.remove_xdp(ifc, flags=BPF.XDP_FLAGS_SKB_MODE)
                except Exception:
                    pass
                self.loaded = False
                self.ifaces = []


xdp = XDPFirewall()
app = FastAPI(title="XDP Firewall", version="5.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PUBLIC_PATHS = frozenset({"/", "/docs", "/openapi.json"})

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS:
        return await call_next(request)
    key = request.headers.get("x-api-key") or request.query_params.get("key") or ""
    if not hmac.compare_digest(key, API_KEY):
        return JSONResponse(status_code=401, content={"detail": "Ungültiger API-Key"})
    return await call_next(request)


@app.get("/")
async def root():
    html = (BASE_DIR / "index.html").read_text()
    html = html.replace("var API='/api'", f"var API='/api',API_KEY='{API_KEY}'")
    return StreamingResponse(iter([html]), media_type="text/html")

@app.get("/api/rules")
async def get_rules():
    return xdp.load_rules()

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
    rules = xdp.load_rules()
    for r in rules:
        if r.get("id") == rule_id:
            r["enabled"] = not r.get("enabled", True)
            xdp.save_rules(rules)
            return {"ok": True, "enabled": r["enabled"]}
    raise HTTPException(404, "Nicht gefunden")

@app.post("/api/rules/{rule_id}/duplicate")
async def duplicate_rule(rule_id: str):
    rules = xdp.load_rules()
    for r in rules:
        if r.get("id") == rule_id:
            new_rule = dict(r)
            new_rule["id"] = uuid.uuid4().hex[:8]
            new_rule["comment"] = (r.get("comment", "") + " (Kopie)").strip()
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
        msg = xdp.compile_and_attach(rules, iface)
        return {"ok": True, "message": msg}
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
    return {**raw, "pass_pps": round(pp, 1), "drop_pps": round(dp, 1), "total_pps": round(pp + dp, 1), "loaded": xdp.loaded, "iface": ",".join(xdp.ifaces) if xdp.ifaces else "", "rules": len(xdp.load_rules()), "history": ring.history(60), "tc_active": len(xdp.tc_attached) > 0}

@app.get("/api/status")
async def status():
    return {"loaded": xdp.loaded, "iface": ",".join(xdp.ifaces) if xdp.ifaces else "", "rules": len(xdp.load_rules()), "bcc": BCC_AVAILABLE, "pyroute2": PYROUTE2_AVAILABLE, "tc_active": len(xdp.tc_attached) > 0}

@app.get("/api/stream")
async def stream():
    async def gen() -> AsyncIterator[str]:
        while True:
            raw = xdp.read_raw_stats()
            pp, dp = ring.pps()
            d = {**raw, "pass_pps": round(pp, 1), "drop_pps": round(dp, 1), "total_pps": round(pp + dp, 1), "loaded": xdp.loaded, "iface": ",".join(xdp.ifaces) if xdp.ifaces else "", "rules": len(xdp.load_rules()), "tc_active": len(xdp.tc_attached) > 0}
            yield f"data: {json.dumps(d)}\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.on_event("startup")
async def on_start():
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.access").disabled = True
    rules = xdp.load_rules()
    if rules:
        try:
             xdp.compile_and_attach(rules, IFACE)
        except Exception:
             pass

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
    uvicorn.run(app, host="0.0.0.0", port=8000, log_config=_LOG_CFG)