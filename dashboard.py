"""Tiny web dashboard. Reads the alert log, serves a page + JSON API. Stdlib only."""
import json
import os
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signature IDS</title>
<style>
:root{--bg:#e8ecef;--panel:#f7f9fa;--ink:#16202c;--mute:#5d6b79;--line:#c9d1d8;
--high:#b3261e;--medium:#b86e00;--low:#2f6aa3}
@media (prefers-color-scheme:dark){:root{--bg:#10171e;--panel:#18222c;--ink:#e6ecf1;--mute:#93a1ae;--line:#2b3946;
--high:#ff7b72;--medium:#e3a03a;--low:#6aa8e6}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font:600 26px/1.2 Georgia,"Times New Roman",serif;margin:0 0 4px}
.sub{color:var(--mute);margin:0 0 22px}
.band{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--line);margin:6px 0 10px}
.band span{display:block;transition:width .4s}
.legend{display:flex;gap:22px;flex-wrap:wrap;margin-bottom:26px}
.legend div{display:flex;align-items:baseline;gap:8px}
.legend b{font:600 30px/1 Georgia,serif}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.grid{display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-bottom:20px}
@media (max-width:760px){.grid{grid-template-columns:1fr}}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px}
h2{font-size:15px;margin:0 0 10px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--mute);font-weight:500;padding:4px 8px 6px 0;border-bottom:1px solid var(--line)}
td{padding:6px 8px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
.sev{font-weight:600}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}.sev.low{color:var(--low)}
code{font:12.5px ui-monospace,Menlo,Consolas,monospace;color:var(--mute);word-break:break-all}
.bar{height:6px;background:var(--ink);opacity:.75;border-radius:3px;margin-top:3px}
.scroll{overflow-x:auto}
.empty{color:var(--mute);padding:18px 0}
.status{float:right;font-size:12px;color:var(--mute)}
</style></head><body><main>
<h1>Signature IDS</h1>
<p class="sub">Alerts from <span id="rules">0</span> rules &middot; <span id="total">0</span> alerts logged <span class="status" id="status"></span></p>
<div class="band" id="band" role="img" aria-label="Alerts by severity"></div>
<div class="legend" id="legend"></div>
<div class="grid">
 <section><h2>Latest alerts</h2><div class="scroll"><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Target</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty" hidden>No alerts yet. Start the IDS or run it with <code>--demo</code>.</div></div></section>
 <div>
  <section style="margin-bottom:20px"><h2>Top sources</h2><div id="src"></div></section>
  <section><h2>Top rules</h2><div id="top"></div></section>
 </div>
</div>
</main>
<script>
const $=id=>document.getElementById(id);
function bars(el,items){el.textContent="";const max=Math.max(1,...items.map(i=>i[1]));
 items.forEach(([k,v])=>{const d=document.createElement("div");d.style.marginBottom="8px";
  d.textContent=k+"  ("+v+")";const b=document.createElement("div");b.className="bar";b.style.width=(v/max*100)+"%";d.appendChild(b);el.appendChild(d)});
 if(!items.length)el.innerHTML='<div class="empty">Nothing yet</div>'}
async function tick(){
 try{
  const s=await (await fetch("/api/summary")).json();
  $("total").textContent=s.total;$("rules").textContent=s.rules;
  const tot=Math.max(1,s.total);
  $("band").innerHTML=["high","medium","low"].map(k=>`<span style="width:${s.severity[k]/tot*100}%;background:var(--${k})"></span>`).join("");
  $("legend").innerHTML=["high","medium","low"].map(k=>`<div><span class="dot" style="background:var(--${k})"></span><b>${s.severity[k]}</b>${k}</div>`).join("");
  bars($("src"),s.top_sources);bars($("top"),s.top_rules);
  const body=$("rows");body.textContent="";$("empty").hidden=s.latest.length>0;
  s.latest.forEach(a=>{const tr=document.createElement("tr");
   [a.time.slice(11),a.severity,"sid "+a.sid+" "+a.msg,a.src+":"+a.sport,a.dst+":"+a.dport].forEach((t,i)=>{
    const td=document.createElement("td");td.textContent=t;if(i==1)td.className="sev "+a.severity;tr.appendChild(td)});
   body.appendChild(tr)});
  $("status").textContent="updated "+new Date().toLocaleTimeString();
 }catch(e){$("status").textContent="connection lost"}
}
tick();setInterval(tick,2000);
</script></body></html>"""


def summarize(log_path, rule_count=0, latest_n=40):
    alerts = []
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    sev = Counter(a["severity"] for a in alerts)
    return {
        "total": len(alerts), "rules": rule_count,
        "severity": {k: sev.get(k, 0) for k in ("high", "medium", "low")},
        "top_sources": Counter(a["src"] for a in alerts).most_common(6),
        "top_rules": Counter(f'sid {a["sid"]} {a["msg"]}' for a in alerts).most_common(6),
        "latest": alerts[-latest_n:][::-1],
    }


def make_handler(log_path, rule_count):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/summary":
                body, ctype = json.dumps(summarize(log_path, rule_count)).encode(), "application/json"
            elif self.path in ("/", "/index.html"):
                body, ctype = PAGE.encode(), "text/html; charset=utf-8"
            else:
                self.send_error(404); return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return H


def serve(log_path, rule_count=0, host="127.0.0.1", port=8080, background=True):
    srv = ThreadingHTTPServer((host, port), make_handler(log_path, rule_count))
    if background:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    else:
        srv.serve_forever()
    return srv
