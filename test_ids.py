import unittest
from rules import parse_rule, load_rules, RuleError
from engine import Engine, Packet
import capture


def P(**k):
    d = dict(ts=0.0, proto="tcp", src="1.1.1.1", dst="10.0.0.1", sport=1234, dport=80)
    d.update(k)
    return Packet(**d)


class RuleParsing(unittest.TestCase):
    def test_basic(self):
        r = parse_rule('alert tcp any any -> any 80 (msg:"a;b"; content:"x"; sid:1;)')
        self.assertEqual((r.sid, r.msg, r.contents), (1, "a;b", [b"x"]))

    def test_hex_content(self):
        r = parse_rule('alert tcp any any -> any any (msg:"m"; content:"A|0d 0a|B"; sid:2;)')
        self.assertEqual(r.contents, [b"A\r\nB"])

    def test_errors(self):
        for bad in ['alert tcp any any -> any 80 (msg:"m";)',                 # no sid
                    'alert tcp any any -> any 80 (sid:1;)',                  # no msg
                    'alert tcp any any any 80 (msg:"m"; sid:1;)',            # no arrow
                    'alert tcp any any -> any 80 (msg:"m"; sid:1; bogus:1;)']:
            with self.assertRaises(RuleError):
                parse_rule(bad)

    def test_shipped_rules_load_clean(self):
        rules, errs = load_rules("local.rules")
        self.assertEqual(errs, [])
        self.assertGreater(len(rules), 5)


class Matching(unittest.TestCase):
    def eng(self, line):
        return Engine([parse_rule(line)])

    def test_content_nocase_and_port(self):
        e = self.eng('alert tcp any any -> any 80 (msg:"m"; content:"union"; nocase; sid:1;)')
        self.assertEqual(len(e.inspect(P(payload=b"x UNION y"))), 1)
        self.assertEqual(len(e.inspect(P(payload=b"x UNION y", dport=81))), 0)
        self.assertEqual(len(e.inspect(P(payload=b"nothing"))), 0)

    def test_case_sensitive(self):
        e = self.eng('alert tcp any any -> any any (msg:"m"; content:"Abc"; sid:1;)')
        self.assertEqual(len(e.inspect(P(payload=b"abc"))), 0)
        self.assertEqual(len(e.inspect(P(payload=b"zAbc"))), 1)

    def test_cidr_negation(self):
        e = self.eng('alert tcp !10.0.0.0/8 any -> any any (msg:"m"; sid:1;)')
        self.assertEqual(len(e.inspect(P(src="8.8.8.8"))), 1)
        self.assertEqual(len(e.inspect(P(src="10.1.2.3"))), 0)

    def test_port_range(self):
        e = self.eng('alert tcp any any -> any 1:1023 (msg:"m"; sid:1;)')
        self.assertEqual(len(e.inspect(P(dport=22))), 1)
        self.assertEqual(len(e.inspect(P(dport=8080))), 0)

    def test_flags_exact(self):
        e = self.eng('alert tcp any any -> any any (msg:"m"; flags:S; sid:1;)')
        self.assertEqual(len(e.inspect(P(flags="S"))), 1)
        self.assertEqual(len(e.inspect(P(flags="SA"))), 0)

    def test_threshold_window(self):
        e = self.eng('alert tcp any any -> any 22 (msg:"m"; flags:S; threshold:track by_src, count 3, seconds 10; sid:1;)')
        hits = [len(e.inspect(P(ts=t, dport=22, flags="S"))) for t in (0, 1, 2)]
        self.assertEqual(hits, [0, 0, 1])
        slow = [len(e.inspect(P(ts=100 + t * 20, dport=22, flags="S"))) for t in range(4)]
        self.assertEqual(sum(slow), 0)                       # too slow
        other = [len(e.inspect(P(ts=300 + t, src="2.2.2.2", dport=22, flags="S"))) for t in range(3)]
        self.assertEqual(other, [0, 0, 1])                   # tracked per source

    def test_icmp_dsize(self):
        e = self.eng('alert icmp any any -> any any (msg:"m"; itype:8; dsize:>100; sid:1;)')
        self.assertEqual(len(e.inspect(P(proto="icmp", icmp_type=8, payload=b"A" * 200))), 1)
        self.assertEqual(len(e.inspect(P(proto="icmp", icmp_type=8, payload=b"A" * 10))), 0)
        self.assertEqual(len(e.inspect(P(proto="icmp", icmp_type=0, payload=b"A" * 200))), 0)


class EndToEnd(unittest.TestCase):
    def test_demo_triggers_expected_rules(self):
        rules, _ = load_rules("local.rules")
        e = Engine(rules)
        sids = {a.sid for p in capture.demo() for a in e.inspect(p)}
        self.assertTrue({1001, 1003, 1004, 1005, 1006, 2001, 2002, 2003, 2004, 3001} <= sids, sids)

    def test_benign_traffic_is_quiet(self):
        rules, _ = load_rules("local.rules")
        e = Engine(rules)
        self.assertEqual(e.inspect(P(payload=b"GET /index.html HTTP/1.1\r\n\r\n")), [])


if __name__ == "__main__":
    unittest.main()
