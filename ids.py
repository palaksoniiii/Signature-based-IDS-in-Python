#!/usr/bin/env python3
"""Signature-based IDS - Exp 7.

  python ids.py --demo                    # synthetic traffic, no root needed
  python ids.py --pcap capture.pcap       # replay a capture file
  sudo python ids.py --live -i eth0       # sniff a real interface
  python ids.py --check-rules             # validate rules file and exit
  python ids.py --dashboard-only          # just serve the dashboard
"""
import argparse
import sys
import time

import alerts as alerts_mod
import dashboard
from engine import Engine
from rules import load_rules


def main():
    ap = argparse.ArgumentParser(description="Lightweight signature-based IDS")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--live", action="store_true", help="sniff a live interface (needs root)")
    src.add_argument("--pcap", metavar="FILE", help="replay a pcap file")
    src.add_argument("--demo", action="store_true", help="run on built-in synthetic traffic")
    src.add_argument("--dashboard-only", action="store_true")
    src.add_argument("--check-rules", action="store_true")
    ap.add_argument("-i", "--iface", help="interface for --live")
    ap.add_argument("--bpf", help="BPF capture filter for --live, e.g. 'tcp port 80'")
    ap.add_argument("-r", "--rules", default="local.rules")
    ap.add_argument("-l", "--log", default="alerts.jsonl")
    ap.add_argument("--port", type=int, default=8080, help="dashboard port")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between packets (demo/pcap)")
    ap.add_argument("--keep-alive", action="store_true", help="keep dashboard up after replay ends")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    rules, errors = load_rules(args.rules)
    for e in errors:
        print(f"[rule error] {e}", file=sys.stderr)
    print(f"Loaded {len(rules)} rules from {args.rules} ({len(errors)} errors)")
    if args.check_rules:
        sys.exit(1 if errors else 0)

    if args.dashboard_only:
        print(f"Dashboard: http://127.0.0.1:{args.port}")
        try:
            dashboard.serve(args.log, len(rules), port=args.port, background=False)
        except KeyboardInterrupt:
            pass
        return

    if not (args.live or args.pcap or args.demo):
        ap.error("choose one of --live, --pcap FILE, --demo")

    import capture
    if args.live:
        packets = capture.live(args.iface, args.bpf)
    elif args.pcap:
        packets = capture.pcap(args.pcap)
    else:
        packets = capture.demo()

    open(args.log, "w").close()          # fresh log per run
    log = alerts_mod.AlertLog(args.log, color=not args.no_color)
    engine = Engine(rules)
    if not args.no_dashboard:
        dashboard.serve(args.log, len(rules), port=args.port)
        print(f"Dashboard: http://127.0.0.1:{args.port}")

    try:
        for pkt in packets:
            for a in engine.inspect(pkt):
                log.emit(a)
            if args.delay:
                time.sleep(args.delay)
        print(f"\nDone. {engine.packets_seen} packets inspected, {log.count} alerts -> {args.log}")
        if args.keep_alive and not args.no_dashboard:
            print("Dashboard still running. Ctrl+C to quit.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print(f"\nStopped. {engine.packets_seen} packets inspected, {log.count} alerts.")


if __name__ == "__main__":
    main()
