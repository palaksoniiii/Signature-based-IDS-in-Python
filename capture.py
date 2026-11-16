"""Packet sources: live sniffing, pcap replay, and a synthetic demo generator."""
import time
from engine import Packet


def _convert(pkt):
    """scapy packet -> Packet (None if not IPv4 TCP/UDP/ICMP)."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    if IP not in pkt:
        return None
    ip = pkt[IP]
    ts = float(pkt.time)
    if TCP in pkt:
        t = pkt[TCP]
        return Packet(ts, "tcp", ip.src, ip.dst, t.sport, t.dport,
                      str(t.flags), -1, bytes(t.payload))
    if UDP in pkt:
        u = pkt[UDP]
        return Packet(ts, "udp", ip.src, ip.dst, u.sport, u.dport, "", -1, bytes(u.payload))
    if ICMP in pkt:
        return Packet(ts, "icmp", ip.src, ip.dst, 0, 0, "", pkt[ICMP].type, bytes(pkt[ICMP].payload))
    return None


def live(iface=None, bpf=None, count=0):
    """Yield packets from a network interface. Needs root/Administrator."""
    from scapy.all import AsyncSniffer
    import queue
    q = queue.Queue()
    sniffer = AsyncSniffer(iface=iface, filter=bpf, store=False,
                           prn=lambda p: q.put(p), count=count)
    sniffer.start()
    try:
        while True:
            try:
                p = _convert(q.get(timeout=0.5))
            except queue.Empty:
                if not sniffer.running:
                    return
                continue
            if p:
                yield p
    finally:
        if sniffer.running:
            sniffer.stop()


def pcap(path):
    from scapy.utils import PcapReader
    with PcapReader(path) as reader:
        for raw in reader:
            p = _convert(raw)
            if p:
                yield p


def demo():
    """Synthetic traffic exercising every sample rule. No root or scapy needed."""
    t = time.time()
    web, ssh, dns = "10.0.0.10", "10.0.0.22", "10.0.0.53"
    good, bad, scan = "192.168.1.20", "203.0.113.66", "198.51.100.7"

    def http(src, path, ua="Mozilla/5.0", dt=0.2):
        nonlocal t
        t += dt
        body = f"GET {path} HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: {ua}\r\n\r\n".encode()
        return Packet(t, "tcp", src, web, 40000, 80, "PA", -1, body)

    for i in range(5):                                           # benign
        yield http(good, f"/products?id={i}")
    yield http(bad, "/products?id=1' UNION SELECT user,pass FROM users--")   # SQLi
    yield http(bad, "/search?q=<script>alert(1)</script>")                    # XSS
    yield http(bad, "/download?file=../../etc/passwd")                        # traversal
    yield http(scan, "/", ua="Nmap Scripting Engine")                         # scanner UA
    t += 0.2
    yield Packet(t, "tcp", bad, web, 51000, 80, "PA", -1,                     # Shellshock
                 b"GET /cgi-bin/x HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash -c id\r\n\r\n")
    for i in range(7):                                                        # SSH brute force
        t += 0.8
        yield Packet(t, "tcp", bad, ssh, 52000 + i, 22, "S")
    for port in range(1, 25):                                                 # SYN port scan
        t += 0.05
        yield Packet(t, "tcp", scan, web, 44444, port * 37, "S")
    for _ in range(3):                                                        # ping sweep
        t += 0.3
        yield Packet(t, "icmp", scan, web, icmp_type=8, payload=b"abcdefgh")
    t += 0.3
    yield Packet(t, "icmp", bad, web, icmp_type=8, payload=b"A" * 1200)       # oversized ping
    t += 0.3
    yield Packet(t, "udp", good, dns, 5353, 53, "", -1, b"\x12\x34\x01\x00\x00\x01example\x03com")
    t += 0.3
    yield Packet(t, "tcp", "10.0.0.99", "203.0.113.5", 4444, 4444, "PA", -1, b"whoami\n")
