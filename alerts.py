"""Alert sinks: console + JSON-lines log file."""
import json
import threading
import time

COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"


class AlertLog:
    def __init__(self, path, color=True):
        self.path, self.color = path, color
        self._lock = threading.Lock()
        self.count = 0

    def emit(self, a):
        rec = {"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.ts)),
               "ts": a.ts, "sid": a.sid, "msg": a.msg, "severity": a.severity,
               "proto": a.proto, "src": a.src, "sport": a.sport,
               "dst": a.dst, "dport": a.dport, "snippet": a.snippet}
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            self.count += 1
        c, r = (COLORS[a.severity], RESET) if self.color else ("", "")
        print(f"{c}[{a.severity.upper():6}]{r} sid:{a.sid} {a.msg}  "
              f"{a.src}:{a.sport} -> {a.dst}:{a.dport}")
