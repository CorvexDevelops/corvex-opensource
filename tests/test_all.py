"""Tests for the open-source tools: bench, pcapgen, pcapread, nvdmatch, netlists.

    python -m unittest discover -s tests -v       (from the repository root)

Offline: no test talks to the internet. The web targets start on 127.0.0.1 on free ports.
"""
import contextlib
import importlib.util
import io
import ipaddress
import json
import os
import random
import shutil
import socket
import struct
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("bench", "pcapgen", "pcapread", "nvdmatch", "netlists"):
    sys.path.insert(0, os.path.join(ROOT, sub))

import bench  # noqa: E402
import netindex  # noqa: E402
import nvdmatch  # noqa: E402
import pcapgen as G  # noqa: E402
import pcapread as R  # noqa: E402
import sharedcloud  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="corvexai-tests-")
        self._quiet = contextlib.redirect_stdout(io.StringIO())  # the command-line tools print reports
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)


# --------------------------------------------------------------------------- pcapgen + pcapread

class Captures(Tmp):
    def roundtrip(self, packets, writer, **kw):
        p = self.path("c.cap")
        writer(p, packets, **kw)
        return list(R.read(p))

    def test_formats_keep_packets_and_timestamps(self):
        pk = G.attacks()
        cases = [(G.write_pcap, {}), (G.write_pcap, {"big_endian": True}), (G.write_pcap, {"nanoseconds": True}),
                 (G.write_pcapng, {}), (G.write_pcapng, {"tsresol": 9}), (G.write_pcapng, {"tsresol": 0x80 | 20})]
        for writer, kw in cases:
            with self.subTest(writer=writer.__name__, **kw):
                got = self.roundtrip(pk, writer, **kw)
                self.assertEqual(len(got), len(pk))
                self.assertEqual([d for _, _, d in got], [d for _, d in pk])
                self.assertTrue(all(abs(a[0] - b[0]) < 2e-6 for a, b in zip(got, pk)))

    def test_deterministic(self):
        self.assertEqual(G.attacks(), G.attacks())
        self.assertEqual(G.clean(), G.clean())

    def test_signals_cover_attack_capture(self):
        p = self.path("a.pcap")
        G.write_pcap(p, G.attacks())
        seen = set()
        for pk in R.packets(p):
            seen |= {pk["src"], pk["dst"], str(pk["dport"])}
            if pk.get("arp"):
                seen.add(pk["arp"]["sender_ip"])
            if pk["proto"] == 17 and pk["payload"]:
                try:
                    _, rcode, qs, _ = R.parse_dns(pk["payload"])
                    seen |= {n for n, _ in qs} | ({"NXDOMAIN"} if rcode == 3 else set())
                except ValueError:
                    pass
            if pk["payload"][:4] in (b"GET ", b"POST"):
                seen.add(pk["payload"].decode("latin-1"))
            hello = R.parse_tls_hello(pk["payload"]) if pk["proto"] == 6 else None
            if hello and hello["type"] == "client":
                seen.add(hello["sni"])
        for s in G.SIGNALS:
            wheres = s["where"] if isinstance(s["where"], list) else [s["where"]]
            self.assertTrue(all(any(w in str(x) for x in seen) for w in wheres), s["id"])
        self.assertEqual(len({s["id"] for s in G.SIGNALS}), len(G.SIGNALS))

    def test_decode_tcp_udp(self):
        d = R.decode(0, 1, G.tcp_pkt("192.168.1.20", 50000, "198.51.100.1", 443, b"hi"))
        self.assertEqual((d["proto"], d["src"], d["dst"], d["sport"], d["dport"], d["payload"]), (6, "192.168.1.20", "198.51.100.1", 50000, 443, b"hi"))
        self.assertEqual(d["src_mac"], "02:00:00:00:00:20")
        u = R.decode(0, 1, G.udp_pkt("192.168.1.20", 5353, "224.0.0.251", 5353, b"x"))
        self.assertEqual((u["proto"], u["dport"], u["payload"]), (17, 5353, b"x"))

    def test_decode_vlan_ipv6_raw_loopback_cooked(self):
        inner = G.ip4("10.0.0.1", "10.0.0.2", 17, G.udp(1, 2, b"z"))
        self.assertEqual(R.decode(0, 1, G.eth(inner, vlan=42))["dst"], "10.0.0.2")
        six = G.ip6("2001:db8::1", "2001:db8::2", 6, G.tcp(1, 443))
        d6 = R.decode(0, 1, G.eth(six, 0x86DD))
        self.assertEqual((d6["src"], d6["dport"]), ("2001:db8::1", 443))
        hop = bytes([6, 0]) + b"\0" * 6  # hop-by-hop header, then TCP
        self.assertEqual(R.decode(0, 1, G.eth(G.ip6("2001:db8::1", "2001:db8::2", 0, hop + G.tcp(1, 22)), 0x86DD))["dport"], 22)
        self.assertEqual(R.decode(0, 101, inner)["src"], "10.0.0.1")
        self.assertEqual(R.decode(0, 0, struct.pack("<I", 2) + inner)["src"], "10.0.0.1")
        self.assertEqual(R.decode(0, 108, struct.pack(">I", 2) + inner)["src"], "10.0.0.1")
        sll = struct.pack(">HHH", 0, 1, 6) + b"\x02\0\0\0\0\x09" + b"\0\0" + struct.pack(">H", 0x0800)
        cooked = R.decode(0, 113, sll + inner)
        self.assertEqual((cooked["src"], cooked["src_mac"]), ("10.0.0.1", "02:00:00:00:00:09"))

    def test_fragments_and_arp(self):
        first = R.decode(0, 1, G.eth(G.ip4("10.0.0.1", "10.0.0.2", 17, G.udp(1, 2, b"a" * 8), more=True)))
        later = R.decode(0, 1, G.eth(G.ip4("10.0.0.1", "10.0.0.2", 17, b"b" * 8, frag=16)))
        self.assertEqual(first["dport"], 2)
        self.assertIsNone(later["proto"])
        a = R.decode(0, 1, G.arp_reply("192.168.1.1", G.MAC_ROGUE))["arp"]
        self.assertEqual((a["op"], a["sender_ip"], a["sender_mac"]), ("reply", "192.168.1.1", "02:00:00:00:00:66"))

    def test_dns_and_tls_helpers(self):
        self.assertEqual(R.parse_dns(G.dns_query("a.example", 16))[2], [("a.example", 16)])
        self.assertEqual(R.parse_dns(G.dns_answer("a.example", "198.51.100.9"))[3], [("a.example", "198.51.100.9")])
        loop = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            R.parse_dns(loop)
        self.assertEqual(R.parse_tls_hello(G.tls_client_hello("x.example"))["sni"], "x.example")
        self.assertEqual(R.parse_tls_hello(G.tls_server_hello(0x0301, 0x0005)), {"type": "server", "version": 0x0301, "cipher": 5})
        self.assertEqual(R.parse_tls_hello(G.tls_server_hello(0x0303, 0x1301, tls13=True))["version"], 0x0304)
        self.assertIsNone(R.parse_tls_hello(b"GET / HTTP/1.1\r\n"))

    def test_damaged_files(self):
        p = self.path("bad.pcap")
        with open(p, "wb") as f:
            f.write(b"not a capture at all")
        with self.assertRaises(R.FormatError):
            list(R.read(p))
        good = self.path("good.pcap")
        G.write_pcap(good, G.clean())
        data = open(good, "rb").read()
        with open(p, "wb") as f:
            f.write(data[:len(data) - 7])  # cut in the middle of the last packet
        self.assertEqual(len(list(R.read(p))), len(G.clean()) - 1)
        huge = data[:24] + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        with open(p, "wb") as f:
            f.write(huge)
        self.assertEqual(list(R.read(p)), [])
        rnd = random.Random(1)
        for _ in range(200):  # random garbage after a valid header never raises anything but FormatError
            with open(p, "wb") as f:
                f.write(data[:24] + bytes(rnd.randrange(256) for _ in range(rnd.randrange(400))))
            for pk in R.packets(p):
                R.parse_tls_hello(pk["payload"])

    def test_cli(self):
        p = self.path("c.pcapng")
        self.assertEqual(G.main(["clean", p]), 0)
        self.assertEqual(R.summary(p)["packets"], len(G.clean()))
        self.assertEqual(G.main(["indicators", self.path("i.json")]), 0)
        self.assertEqual(json.load(open(self.path("i.json"))), G.INDICATORS)


# --------------------------------------------------------------------------- bench

def sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake", "rules": rules or []}}, "results": results}]}


def res(rule, msg, uri, line=None, level="warning"):
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    if line:
        loc["physicalLocation"]["region"] = {"startLine": line}
    return {"ruleId": rule, "message": {"text": msg}, "level": level, "locations": [loc]}


class Bench(Tmp):
    def write(self, name, doc):
        with open(self.path(name), "w") as f:
            json.dump(doc, f)

    def test_expected_is_consistent(self):
        exp = bench.load_expected()
        ids = [e["id"] for s in exp["targets"].values() for e in s.get("expected", [])]
        self.assertEqual(len(ids), len(set(ids)))
        for name, spec in exp["targets"].items():
            for e in spec.get("expected", []):
                self.assertTrue(e["keywords"], e["id"])
                if spec["kind"] == "code":
                    self.assertTrue(os.path.exists(os.path.join(bench.TARGETS_DIR, name, e["file"])), e["id"])
                    if e.get("contains"):
                        bench.resolve_line(name, e["file"], e["contains"])
        self.assertEqual([e["signal"] for e in exp["targets"]["traffic-attacks"]["expected"]], [s["id"] for s in G.SIGNALS])

    def test_clean_code_has_no_flaw_snippets(self):
        snippets = {e["contains"] for e in bench.load_expected()["targets"]["code-vulnerable"]["expected"] if e.get("contains")}
        for base, _, files in os.walk(os.path.join(bench.TARGETS_DIR, "code-clean")):
            for fn in files:
                text = open(os.path.join(base, fn), encoding="utf-8").read()
                for s in snippets - {'"axios"', '"express"', '"jsonwebtoken"', '"lodash"', '"minimist"', "Math.random()"}:
                    self.assertNotIn(s, text, f"{fn}: {s}")

    def test_cwe_parsing(self):
        self.assertEqual(bench.cwes("CWE-89", ["external/cwe/cwe-079"], 22, "cwe_352", "nothing"), {89, 79, 22, 352})

    def test_sarif_scoring_and_matching(self):
        rules = [{"id": "py.sqli", "properties": {"tags": ["CWE-89"]}}, {"id": "hash", "properties": {"cwe": "CWE-328"}}]
        self.write("code-vulnerable.sarif", sarif([
            res("py.sqli", "query built from input", "file:///tmp/x/code-vulnerable/app.py", 24),   # CWE match, line within 2
            res("hash", "weak digest", "app.py", 47),                                             # CWE match
            res("random", "insecure random generator", "./app.py", 48),                           # keyword match
            res("random", "insecure random generator", "app.py", 48),                             # duplicate: uncatalogued
            res("sqli", "SQL injection", "server.js", 99),                                         # wrong line
            res("vuln-dep", "pyyaml 5.3.1 has known flaws", "requirements.txt", 3),                # dependency, exact line
            res("vuln-dep", "flask 2.0.1 has known flaws", "requirements.txt", 2),                 # wrong line for flask (tolerance 0)
            res("root", "container runs as root", "Dockerfile"),                                   # file only
        ], rules))
        self.write("code-clean.json", [{"rule": "debug", "message": "debug on", "file": "app.py", "line": 18},
                                       {"rule": "lic", "message": "unknown licence", "file": "package.json"}])
        rep = bench.score(self.tmp)
        t = rep["targets"]["code-vulnerable"]
        found = {i.split("/")[1] for i in t["found"]}
        self.assertEqual(found, {"C01", "C09", "C10", "C24", "C23"})
        self.assertEqual(len(t["uncatalogued"]), 3)
        self.assertEqual(rep["targets"]["code-clean"]["false_alarms"], ["code-clean · debug · app.py:18"])
        self.assertIn("web-vulnerable", rep["skipped"])

    def test_one_finding_counts_once_and_matching_is_maximal(self):
        exp = {"kind": "web", "expected": [
            {"id": "A", "title": "a", "cwe": [693], "keywords": ["csp"], "path": ""},
            {"id": "B", "title": "b", "cwe": [693], "keywords": ["nosniff"], "path": ""}]}
        one = [bench._finding("h", "missing headers", [693], location="http://h/")]
        self.assertEqual(len(bench.score_target("t", exp, one, {})["found"]), 1)
        two = [bench._finding("h", "missing CSP", [693], location="http://h/"),     # could serve A or B
               bench._finding("x", "other", [693], location="http://h/")]           # only via CWE
        self.assertEqual(len(bench.score_target("t", exp, two, {})["found"]), 2)

    def test_web_and_traffic_locations(self):
        self.write("web-vulnerable.json", {"findings": [
            {"rule": "xss", "message": "Reflected XSS", "location": "http://127.0.0.1:9/search?q=x"},
            {"rule": "xss", "message": "Reflected XSS", "location": "http://127.0.0.1:9/product?id=1"},
            {"rule": "redir", "cwe": "CWE-601", "location": "http://127.0.0.1:9/logout?next=//evil"}]})
        self.write("traffic-attacks.json", [{"rule": "beacon", "message": "periodic connections to 198.51.100.77:443"},
                                            {"rule": "beacon", "message": "periodic connections to 198.51.100.99"}])
        rep = bench.score(self.tmp)
        self.assertEqual(rep["targets"]["web-vulnerable"]["found"], ["web-vulnerable/W11", "web-vulnerable/W13"])
        self.assertEqual(len(rep["targets"]["traffic-attacks"]["found"]), 1)

    def test_baseline(self):
        self.write("code-vulnerable.json", [{"rule": "sql", "message": "SQL injection", "file": "app.py", "line": 23}])
        base = self.path("baseline.json")
        self.assertEqual(bench.main(["score", self.tmp, "--baseline", base, "--update"]), 0)
        self.assertEqual(bench.main(["score", self.tmp, "--baseline", base]), 0)
        self.write("code-vulnerable.json", [])
        self.assertEqual(bench.main(["score", self.tmp, "--baseline", base]), 1)
        diff = bench.compare(bench.score(self.tmp), json.load(open(base)))
        self.assertEqual(diff["lost"], ["code-vulnerable/C01"])
        os.remove(self.path("code-vulnerable.json"))
        self.write("web-clean.json", [])  # other targets only: the code baseline is not compared
        self.assertEqual(bench.compare(bench.score(self.tmp), json.load(open(base)))["lost"], [])

    def test_min_level(self):
        self.write("code-clean.sarif", sarif([res("x", "style", "app.py", 1, level="note")]))
        self.assertEqual(len(bench.score(self.tmp)["targets"]["code-clean"]["false_alarms"]), 1)
        self.assertEqual(len(bench.score(self.tmp, min_level="warning")["targets"]["code-clean"]["false_alarms"]), 0)

    def test_prepare(self):
        out = self.path("work")
        self.assertEqual(bench.main(["prepare", out]), 0)
        for name in ("code-vulnerable/app.py", "code-clean/app.py", "traffic-attacks.pcap", "traffic-clean.pcap", "indicators.json"):
            self.assertTrue(os.path.exists(os.path.join(out, name)), name)


class WebTargets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = load("web_vulnerable", os.path.join(bench.TARGETS_DIR, "web-vulnerable", "server.py"))
        cls.clean = load("web_clean", os.path.join(bench.TARGETS_DIR, "web-clean", "server.py"))
        cls.ports = []
        cls.servers = []
        for mod in (cls.vuln, cls.clean):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            cls.servers.append(mod.start_background(port))
            cls.ports.append(port)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def get(self, which, path, data=None):
        url = f"http://127.0.0.1:{self.ports[which]}{path}"
        opener = urllib.request.build_opener(type("NoRedirect", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda *a: None}))
        try:
            r = opener.open(urllib.request.Request(url, data=data, headers={"Origin": "https://evil.example"}), timeout=5)
            return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def test_vulnerable_behaves_as_described(self):
        self.assertIn("<script>x</script>", self.get(0, "/search?q=<script>x</script>")[2])
        self.assertEqual(self.get(0, "/product?id=1'")[0], 500)
        self.assertEqual(self.get(0, "/logout?next=https://evil.example")[1]["Location"], "https://evil.example")
        self.assertEqual(self.get(0, "/")[1]["Access-Control-Allow-Origin"], "https://evil.example")
        self.assertEqual(self.get(0, "/.env")[0], 200)
        self.assertIn("__schema", self.get(0, "/graphql", b'{"query":"{__schema{types{name}}}"}')[2])

    def test_clean_behaves_safely(self):
        self.assertNotIn("<script>x</script>", self.get(1, "/search?q=<script>x</script>")[2])
        self.assertEqual(self.get(1, "/product?id=1'")[0], 400)
        self.assertEqual(self.get(1, "/logout?next=https://evil.example")[1]["Location"], "/")
        h = self.get(1, "/")[1]
        self.assertNotIn("Access-Control-Allow-Origin", h)
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(self.get(1, "/.env")[0], 404)
        codes = [self.get(1, "/login", b"email=a&password=b")[0] for _ in range(7)]
        self.assertEqual(codes[-1], 429)


# --------------------------------------------------------------------------- nvdmatch

def cve(cid, score, *matches):
    return {"cve": {"id": cid, "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
                    "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}]}}


def m(criteria, **bounds):
    return dict({"vulnerable": True, "criteria": criteria}, **bounds)


ANSWER = [
    cve("CVE-1", 9.8, m("cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*", versionEndExcluding="2.4.2")),
    cve("CVE-2", 5.0, m("cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*", versionStartIncluding="2.0", versionEndIncluding="2.3.9")),
    cve("CVE-3", 7.5, m("cpe:2.3:a:acme:tool:2.4.1:*:*:*:*:*:*:*")),
    cve("CVE-4", 8.0, m("cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*")),                                   # no bound: skipped
    cve("CVE-5", 6.0, m("cpe:2.3:a:other:tool:*:*:*:*:*:*:*:*", versionEndExcluding="9")),           # other vendor
    cve("CVE-6", 4.0, dict(m("cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*", versionEndExcluding="3"), vulnerable=False)),
    cve("CVE-7", 3.1, m("cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*", versionStartExcluding="2.4")),        # open-ended
]


class NVD(Tmp):
    def test_versions(self):
        self.assertEqual(nvdmatch.vtuple("120.0.6099.62"), (120, 0, 6099, 62))
        self.assertEqual(nvdmatch.vtuple("2.4.0"), nvdmatch.vtuple("2.4"))
        self.assertLess(nvdmatch.vtuple("2.9"), nvdmatch.vtuple("2.10"))
        self.assertEqual(nvdmatch.clean_version("2.4.1 (build 77)"), "2.4.1")

    def test_affecting(self):
        got = nvdmatch.affecting(ANSWER, "acme", "tool", "2.4.1")
        self.assertEqual([c["id"] for c in got], ["CVE-1", "CVE-3", "CVE-7"])
        self.assertEqual(got[0]["severity"], "critical")
        self.assertEqual(nvdmatch.min_fixed(got), "2.4.2")
        self.assertEqual([c["id"] for c in nvdmatch.affecting(ANSWER, "acme", "tool", "2.3")], ["CVE-1", "CVE-2"])
        self.assertEqual(nvdmatch.affecting(ANSWER, "acme", "tool", "2.4.2"), [{"id": "CVE-7", "cvss": 3.1, "severity": "low", "fixed_in": ""}])

    def test_client_last_page_cache_and_validation(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if "resultsPerPage=1&" in url or url.endswith("resultsPerPage=1"):
                return {"totalResults": 1200}
            return {"vulnerabilities": ANSWER}
        cache = self.path("c/nvd.json")
        c = nvdmatch.NVDClient(cache, key="", fetch=fetch, pause=0)
        self.assertEqual(len(c.lookup("acme", "tool", "2.4.1")), 3)
        self.assertIn("startIndex=700", calls[-1])
        self.assertIn("virtualMatchString=cpe:2.3:a:acme:tool:2.4.1", calls[-1])
        n = len(calls)
        c.lookup("acme", "tool", "2.4.1")
        self.assertEqual(len(calls), n)  # from the cache
        c.lookup("acme", "tool", "2.3", all_pages=True)
        self.assertEqual([u.split("startIndex=")[1] for u in calls[n + 1:]], ["0", "500", "1000"])
        with self.assertRaises(ValueError):
            c.lookup("acme", "tool&x=1", "1")

    def test_check(self):
        def fetch(url):
            if "bad" in url:
                raise OSError("down")
            return {"totalResults": 1, "vulnerabilities": ANSWER}
        client = nvdmatch.NVDClient(None, key="", fetch=fetch, pause=0)
        out = nvdmatch.check([{"vendor": "acme", "product": "tool", "version": "2.4.1 beta", "name": "Tool"},
                              {"vendor": "acme", "product": "tool", "version": "9"},
                              {"vendor": "bad", "product": "x", "version": "1"}], client, log=lambda m: None)
        self.assertEqual([(r["name"], r["version"], r["fixed_in"]) for r in out], [("Tool", "2.4.1", "2.4.2"), ("tool", "9", "")])


# --------------------------------------------------------------------------- netlists

class Networks(Tmp):
    def test_exact_networks_v6_mapped(self):
        ix = netindex.NetIndex()
        ix.add("203.0.113.66", "list")
        ix.add("198.51.100.0/24", "nets")
        ix.add("2001:db8::/32", "v6")
        self.assertFalse(ix.add("not-an-ip"))
        self.assertEqual(ix.get("203.0.113.66"), "list")
        self.assertEqual(ix.get("198.51.100.200"), "nets")
        self.assertEqual(ix.get("::ffff:198.51.100.7"), "nets")
        self.assertEqual(ix.get("2001:db8:1::5"), "v6")
        self.assertIsNone(ix.get("198.51.101.1"))
        self.assertNotIn("8.8.8.8", ix)
        self.assertEqual(len(ix), 3)

    def test_same_answer_as_a_linear_scan(self):
        rnd = random.Random(5)
        ix, nets = netindex.NetIndex(), []
        for i in range(1500):
            prefix = rnd.choice([8, 12, 16, 20, 24, 28])
            net = ipaddress.ip_network(f"{rnd.randrange(1, 224)}.{rnd.randrange(256)}.{rnd.randrange(256)}.0/{prefix}", strict=False)
            nets.append((net, i))
            ix.add(str(net), i)
        for _ in range(4000):
            a = ipaddress.ip_address(rnd.getrandbits(32))
            want = next((lbl for n, lbl in nets if a in n), None)
            self.assertEqual(ix.get(str(a)), want, str(a))

    def test_lists(self):
        text = "; header\n1.10.16.0/20 ; SBL256894\n203.0.113.5 # comment\n198.51.100.0/24,extra\n\n"
        self.assertEqual(netindex.parse_lines(text), ["1.10.16.0/20", "203.0.113.5", "198.51.100.0/24"])
        p = self.path("l.txt")
        open(p, "w").write(text)
        self.assertEqual(netindex.load(p, "drop").get("1.10.17.1"), "drop")
        self.assertEqual(netindex.main([p, "1.10.17.1"]), 0)

    def test_sharedcloud_build(self):
        bodies = {
            "https://www.cloudflare.com/ips-v4": "104.16.0.0/13\n",
            "https://www.cloudflare.com/ips-v6": "2606:4700::/32\n",
            "https://api.fastly.com/public-ip-list": json.dumps({"addresses": ["151.101.0.0/16"], "ipv6_addresses": []}),
            "https://ip-ranges.amazonaws.com/ip-ranges.json": json.dumps({"prefixes": [
                {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"}, {"ip_prefix": "3.0.0.0/9", "service": "EC2"}]}),
            "https://www.gstatic.com/ipranges/goog.json": json.dumps({"prefixes": [{"ipv4Prefix": "8.8.4.0/24"}]}),
        }

        def fetch(url):
            if url not in bodies:
                raise OSError("offline")
            return bodies[url]
        doc = sharedcloud.build(fetch, previous={"networks": {"GitHub": ["140.82.112.0/20"]}})
        ix = sharedcloud.index(doc)
        self.assertEqual(ix.get("104.16.1.1"), "Cloudflare")
        self.assertEqual(ix.get("13.32.0.1"), "AWS CloudFront")
        self.assertIsNone(ix.get("3.0.0.1"))            # rented machines stay out
        self.assertEqual(ix.get("140.82.112.3"), "GitHub")  # failed download: previous list kept
        self.assertEqual(ix.get("17.1.2.3"), "Apple")


if __name__ == "__main__":
    unittest.main()
