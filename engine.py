"""Matching engine: header checks first (cheap), then payload checks, then thresholds."""
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class Packet:
    ts: float
    proto: str          # tcp / udp / icmp
    src: str
    dst: str
    sport: int = 0
    dport: int = 0
    flags: str = ""     # e.g. "S", "SA", "PA"
    icmp_type: int = -1
    payload: bytes = b""


@dataclass
class Alert:
    ts: float
    sid: int
    msg: str
    severity: str
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    snippet: str = ""


def _ip_ok(spec, ip):
    if spec is None:
        return True
    neg, nets = spec
    addr = ipaddress.ip_address(ip)
    hit = any(addr in n for n in nets)
    return hit != neg


def _port_ok(spec, port):
    if spec is None:
        return True
    neg, ranges = spec
    hit = any(lo <= port <= hi for lo, hi in ranges)
    return hit != neg


def _snippet(payload, n=60):
    s = payload[:n].decode("latin-1")
    return "".join(c if 32 <= ord(c) < 127 else "." for c in s)


class Engine:
    def __init__(self, rules):
        self.rules = rules
        self._by_proto = defaultdict(list)
        for r in rules:
            if r.proto == "ip":
                for p in ("tcp", "udp", "icmp"):
                    self._by_proto[p].append(r)
            else:
                self._by_proto[r.proto].append(r)
        self._events = defaultdict(deque)   # (sid, key) -> timestamps
        self.packets_seen = 0

    # -- individual checks ------------------------------------------------
    def _header(self, r, p):
        if not _ip_ok(r.src_ip, p.src) or not _ip_ok(r.dst_ip, p.dst):
            return False
        if p.proto in ("tcp", "udp"):
            if not _port_ok(r.src_port, p.sport) or not _port_ok(r.dst_port, p.dport):
                return False
        if r.flags is not None:
            if p.proto != "tcp":
                return False
            need, more = r.flags
            have = set(p.flags)
            if not (need <= have if more else need == have):
                return False
        if r.itype is not None and (p.proto != "icmp" or p.icmp_type != r.itype):
            return False
        if r.dsize is not None:
            op, n = r.dsize
            size = len(p.payload)
            if not ((op == "=" and size == n) or (op == ">" and size > n) or (op == "<" and size < n)):
                return False
        return True

    def _payload(self, r, p):
        if not r.contents and r.pcre is None:
            return True
        data = p.payload
        if not data:
            return False
        hay = data.lower() if r.nocase else data
        if not all(c in hay for c in r.contents):
            return False
        if r.pcre is not None and not r.pcre.search(data):
            return False
        return True

    def _threshold(self, r, p):
        t = r.threshold
        if t is None:
            return True
        key = (r.sid, p.src if t["track"] == "by_src" else p.dst)
        q = self._events[key]
        q.append(p.ts)
        while q and p.ts - q[0] > t["seconds"]:
            q.popleft()
        if len(q) >= t["count"]:
            q.clear()            # re-arm: needs another full burst to fire again
            return True
        return False

    # -- public -----------------------------------------------------------
    def inspect(self, p):
        self.packets_seen += 1
        alerts = []
        for r in self._by_proto.get(p.proto, ()):
            if self._header(r, p) and self._payload(r, p) and self._threshold(r, p):
                alerts.append(Alert(p.ts, r.sid, r.msg, r.severity, p.proto,
                                    p.src, p.sport, p.dst, p.dport, _snippet(p.payload)))
        return alerts
