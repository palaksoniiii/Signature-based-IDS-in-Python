# Signature-based IDS in Python
Exp 7 - Intrusion Detection System | Palak Soni | 23ESKCY038 | CSL-G37

A lightweight network IDS with four parts:

| Part | File | Job |
|---|---|---|
| Packet capture | `capture.py` | Live sniffing / pcap replay (scapy) and a synthetic demo generator |
| Rule file parser | `rules.py` | Reads `local.rules` (Snort-like syntax), validates, reports bad lines |
| Matching engine | `engine.py` | Header match -> payload match -> threshold check |
| Alert log + dashboard | `alerts.py`, `dashboard.py` | JSON-lines log, coloured console, web dashboard on :8080 |

## Run
```bash
python ids.py --demo                    # no root, no scapy needed; open http://127.0.0.1:8080
python ids.py --demo --delay 0.2 --keep-alive     # slow replay so you can watch the dashboard fill
pip install scapy
python ids.py --pcap sample.pcap
sudo python ids.py --live -i eth0 --bpf "tcp or icmp"
python ids.py --check-rules             # validate rule file
python test_ids.py                      # 13 unit tests
```

## Rule syntax
```
action proto src_ip src_port -> dst_ip dst_port (options)
alert tcp any any -> any 80 (msg:"SQLi"; content:"union"; content:"select"; nocase; severity:high; sid:1001;)
```
- IPs: `any`, `10.0.0.5`, `192.168.0.0/16`, `!10.0.0.0/8`, `[a,b]`. Ports: `any`, `80`, `1:1023`, `!22`, `[80,443]`.
- `content:"..."` (repeatable, all must match; `|0d 0a|` for hex bytes), `nocase`, `pcre:"/regex/i"`
- `flags:S` (exact set of TCP flags; `flags:S+` = at least S), `itype:8`, `dsize:>1000`
- `threshold:track by_src, count 5, seconds 10;` fires once `count` matching packets arrive within the window
- `severity:low|medium|high`, mandatory `msg` and unique `sid`

## How matching works
1. Packets are indexed by protocol so only relevant rules are tried.
2. Cheap header checks run first (IP/CIDR, ports, flags, ICMP type, payload size).
3. Payload checks (content, pcre) run only on survivors.
4. Threshold rules keep a sliding window of timestamps per (rule, source) and re-arm after firing.

## Limits (state these in your viva)
No TCP stream reassembly (a pattern split across two packets is missed), IPv4 only, no
IPS/blocking, payload rules only see unencrypted traffic, and signatures cannot catch unknown attacks.
