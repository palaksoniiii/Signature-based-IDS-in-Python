"""Rule file parser for the signature-based IDS.

Rule syntax (Snort-like, simplified):

  action proto src_ip src_port -> dst_ip dst_port (option; option; ...)

Example:
  alert tcp any any -> any 80 (msg:"SQLi"; content:"union select"; nocase; sid:1001; severity:high;)

Supported options:
  msg, sid, severity (low|medium|high), content (repeatable, supports |hex|),
  nocase, pcre, flags, itype, dsize, threshold, reference
"""
import ipaddress
import re
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    sid: int
    msg: str
    proto: str
    src_ip: object   # None = any, else (negated, [networks])
    src_port: object
    dst_ip: object
    dst_port: object
    severity: str = "medium"
    contents: list = field(default_factory=list)   # list of bytes
    nocase: bool = False
    pcre: object = None                             # compiled regex over payload
    flags: object = None                            # (set_of_letters, allow_more)
    itype: object = None
    dsize: object = None                            # (op, n)
    threshold: object = None                        # dict(track, count, seconds)
    raw: str = ""


def _split_options(body):
    """Split on ';' that are not inside double quotes and not escaped."""
    parts, buf, in_q, esc = [], [], False, False
    for ch in body:
        if esc:
            buf.append(ch); esc = False; continue
        if ch == "\\":
            buf.append(ch); esc = True; continue
        if ch == '"':
            in_q = not in_q
        if ch == ";" and not in_q:
            parts.append("".join(buf).strip()); buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def _unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v.replace('\\"', '"').replace("\\;", ";")


def _decode_content(text):
    """'GET |0d 0a|' -> bytes. Text outside pipes is ASCII, inside pipes is hex."""
    out, parts = b"", text.split("|")
    for i, part in enumerate(parts):
        if i % 2 == 0:
            out += part.encode("latin-1", "replace")
        else:
            hexs = part.replace(" ", "")
            try:
                out += bytes.fromhex(hexs)
            except ValueError:
                raise RuleError(f"bad hex in content: |{part}|")
    return out


def _parse_ip(tok):
    if tok == "any":
        return None
    neg = tok.startswith("!")
    tok = tok.lstrip("!").strip("[]")
    try:
        nets = [ipaddress.ip_network(t, strict=False) for t in tok.split(",")]
    except ValueError as e:
        raise RuleError(f"bad IP/CIDR '{tok}': {e}")
    return (neg, nets)


def _parse_port(tok):
    if tok == "any":
        return None
    neg = tok.startswith("!")
    tok = tok.lstrip("!").strip("[]")
    ranges = []
    for t in tok.split(","):
        try:
            if ":" in t:
                lo, hi = t.split(":", 1)
                ranges.append((int(lo) if lo else 0, int(hi) if hi else 65535))
            else:
                ranges.append((int(t), int(t)))
        except ValueError:
            raise RuleError(f"bad port '{t}'")
    return (neg, ranges)


def parse_rule(line, lineno=0):
    m = re.match(r"^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$", line)
    if not m:
        raise RuleError(f"line {lineno}: malformed rule")
    action, proto, sip, sport, dip, dport, body = m.groups()
    if action != "alert":
        raise RuleError(f"line {lineno}: only 'alert' action supported")
    proto = proto.lower()
    if proto not in ("tcp", "udp", "icmp", "ip"):
        raise RuleError(f"line {lineno}: unknown protocol '{proto}'")

    r = Rule(sid=0, msg="", proto=proto, src_ip=_parse_ip(sip), src_port=_parse_port(sport),
             dst_ip=_parse_ip(dip), dst_port=_parse_port(dport), raw=line)

    for opt in _split_options(body):
        key, _, val = opt.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "msg":
            r.msg = _unquote(val)
        elif key == "sid":
            r.sid = int(val)
        elif key == "severity":
            if val.lower() not in SEVERITIES:
                raise RuleError(f"line {lineno}: severity must be one of {SEVERITIES}")
            r.severity = val.lower()
        elif key == "content":
            r.contents.append(_decode_content(_unquote(val)))
        elif key == "nocase":
            r.nocase = True
        elif key == "pcre":
            pat = _unquote(val)
            fl = re.I if pat.endswith("/i") else 0
            pat = re.sub(r"^/|/[a-z]*$", "", pat)
            r.pcre = re.compile(pat.encode("latin-1", "replace"), fl)
        elif key == "flags":
            more = val.endswith("+")
            r.flags = (set(val.rstrip("+").upper()), more)
        elif key == "itype":
            r.itype = int(val)
        elif key == "dsize":
            mm = re.match(r"^([<>]?)\s*(\d+)$", val)
            if not mm:
                raise RuleError(f"line {lineno}: bad dsize '{val}'")
            r.dsize = (mm.group(1) or "=", int(mm.group(2)))
        elif key == "threshold":
            d = {"track": "by_src", "count": 1, "seconds": 60}
            for chunk in val.split(","):
                k, _, v = chunk.strip().partition(" ")
                if k == "track":
                    d["track"] = v.strip()
                elif k in ("count", "seconds"):
                    d[k] = int(v)
            if d["track"] not in ("by_src", "by_dst"):
                raise RuleError(f"line {lineno}: track must be by_src or by_dst")
            r.threshold = d
        elif key in ("reference", "classtype", "rev"):
            pass
        else:
            raise RuleError(f"line {lineno}: unknown option '{key}'")

    if not r.sid:
        raise RuleError(f"line {lineno}: rule needs a sid")
    if not r.msg:
        raise RuleError(f"line {lineno}: rule needs a msg")
    if r.nocase:
        r.contents = [c.lower() for c in r.contents]
    return r


def load_rules(path):
    """Return (rules, errors). Bad lines are reported, not fatal."""
    rules, errors, seen = [], [], set()
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                r = parse_rule(line, n)
                if r.sid in seen:
                    raise RuleError(f"line {n}: duplicate sid {r.sid}")
                seen.add(r.sid)
                rules.append(r)
            except (RuleError, ValueError, re.error) as e:
                errors.append(str(e))
    return rules, errors
