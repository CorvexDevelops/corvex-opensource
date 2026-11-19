"""pcapgen: build network captures by hand, with one example of each common attack and a clean baseline.

Standard library only. The captures are deterministic (same bytes every run) and use documentation
addresses (RFC 5737, RFC 3849) and reserved names (.example), so they are safe to share and to commit.

Use them to test a network analyser: every attack in attacks() is listed in SIGNALS with the address or
name a good analyser should report. clean() is ordinary traffic: every alert on it is a false alarm.

    python pcapgen.py attacks attacks.pcap
    python pcapgen.py clean clean.pcapng --format pcapng
    python pcapgen.py indicators indicators.json     the fake threat list that goes with attacks()
    python pcapgen.py signals                         print what an analyser should find

Licence: Apache-2.0
"""
import argparse
import base64
import json
import random
import socket
import struct
import sys

PC, GW, ROGUE = "192.168.1.20", "192.168.1.1", "192.168.1.66"
PC6 = "2001:db8::20"
MAC_PC, MAC_GW, MAC_ROGUE = b"\x02\x00\x00\x00\x00\x20", b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x66"
PASSWORD = "Secret-Long-42"
START = 1_700_000_000.0

# The fake threat list that goes with attacks(): one bad address and one bad domain.
INDICATORS = {"ips": ["203.0.113.66"], "domains": ["malware.example"]}

# What an analyser should find in attacks(). «where» is the address, port or name the alert should mention:
# a list means any of them is fine (a server can be named by address or by TLS name).
SIGNALS = [
    {"id": "cleartext-http-basic", "title": "Credentials sent with HTTP Basic auth", "where": "198.51.100.10"},
    {"id": "cleartext-http-form", "title": "Password sent in a cleartext HTTP form", "where": "198.51.100.11"},
    {"id": "cleartext-ftp", "title": "FTP login in cleartext", "where": "198.51.100.12"},
    {"id": "cleartext-imap", "title": "IMAP login in cleartext", "where": "198.51.100.13"},
    {"id": "cleartext-smtp", "title": "SMTP AUTH PLAIN without TLS", "where": "198.51.100.14"},
    {"id": "cleartext-ldap", "title": "LDAP simple bind in cleartext", "where": "192.168.1.5"},
    {"id": "insecure-telnet", "title": "Telnet session", "where": "192.168.1.9"},
    {"id": "insecure-smbv1", "title": "SMB version 1 negotiation", "where": "192.168.1.6"},
    {"id": "insecure-snmp", "title": "SNMP v2c with the default community", "where": "192.168.1.2"},
    {"id": "llmnr", "title": "LLMNR name query (poisoning risk)", "where": ["office-printer", "192.168.1.20"]},
    {"id": "tls-old-version", "title": "TLS 1.0 negotiated", "where": ["198.51.100.20", "old.example"]},
    {"id": "tls-weak-cipher", "title": "RC4 cipher suite negotiated", "where": ["198.51.100.20", "old.example"]},
    {"id": "bad-domain", "title": "TLS connection to a listed bad domain (SNI)", "where": "bad.malware.example"},
    {"id": "bad-ip", "title": "Traffic with a listed bad address", "where": "203.0.113.66"},
    {"id": "suspicious-port", "title": "Session on a port typical of remote shells (4444)", "where": "4444"},
    {"id": "cleartext-http", "title": "Web browsing in cleartext HTTP", "where": "news.example"},
    {"id": "dns-tunnel", "title": "Long random DNS names under one domain (tunnel)", "where": "tunnel.example"},
    {"id": "dga", "title": "Many NXDOMAIN answers for random names (generated domains)", "where": "NXDOMAIN"},
    {"id": "beacon", "title": "Regular connections every 60 seconds (beacon)", "where": "198.51.100.77"},
    {"id": "arp-spoofing", "title": "The router address claimed by a second MAC (ARP spoofing)", "where": "192.168.1.1"},
    {"id": "rogue-dhcp", "title": "A second DHCP server on the network", "where": "192.168.1.66"},
]


# --------------------------------------------------------------------------- layers

def eth(payload, ethertype=0x0800, src=MAC_PC, dst=MAC_GW, vlan=None):
    tag = struct.pack(">HH", 0x8100, vlan & 0x0FFF) if vlan is not None else b""
    return dst + src + tag + struct.pack(">H", ethertype) + payload


def ip4(src, dst, proto, payload, ident=1, frag=0, more=False):
    flags = (0x2000 if more else 0) | (frag // 8)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def ip6(src, dst, proto, payload):
    return (struct.pack(">IHBB", 6 << 28, len(payload), proto, 64)
            + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload)


def tcp(sport, dport, payload=b"", flags=0x18, seq=1):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp_pkt(src, sport, dst, dport, payload=b"", flags=0x18):
    return eth(ip4(src, dst, 6, tcp(sport, dport, payload, flags)))


def udp_pkt(src, sport, dst, dport, payload, mac=MAC_PC):
    return eth(ip4(src, dst, 17, udp(sport, dport, payload)), src=mac)


# --------------------------------------------------------------------------- application payloads

def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(name, qtype=1, tid=1):
    return struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)


def dns_nxdomain(name, tid=1):
    return struct.pack(">HHHHHH", tid, 0x8183, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", 1, 1)


def dns_answer(name, ip, tid=1):
    return (struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0) + dns_name(name) + struct.pack(">HH", 1, 1)
            + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip))


def tls_client_hello(sni):
    ext_sni = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni.encode()
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack(">H", len(ext_sni)) + ext_sni)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def tls_server_hello(version, cipher, tls13=False):
    exts = struct.pack(">HHH", 0x002B, 2, 0x0304) if tls13 else b""
    body = (struct.pack(">H", version) + b"\x22" * 32 + b"\x00" + struct.pack(">H", cipher) + b"\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def arp_reply(ip, mac, to_ip=PC, to_mac=MAC_PC):
    p = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) + mac + socket.inet_aton(ip) + to_mac + socket.inet_aton(to_ip)
    return eth(p, 0x0806, src=mac, dst=to_mac)


def dhcp_offer(server, mac):
    p = bytearray(240)
    p[0] = 2
    p[236:240] = b"\x63\x82\x53\x63"
    p += bytes([53, 1, 2, 54, 4]) + socket.inet_aton(server) + bytes([255])
    return eth(ip4(server, "255.255.255.255", 17, udp(67, 68, bytes(p))), src=mac, dst=b"\xff" * 6)


def snmp_get(community):
    c = community.encode()
    inner = b"\x02\x01\x01" + b"\x04" + bytes([len(c)]) + c + b"\xa0\x00"
    return b"\x30" + bytes([len(inner)]) + inner


def ldap_bind(user, password):
    u, p = user.encode(), password.encode()
    bind = b"\x02\x01\x03" + b"\x04" + bytes([len(u)]) + u + b"\x80" + bytes([len(p)]) + p
    msg = b"\x02\x01\x01" + b"\x60" + bytes([len(bind)]) + bind
    return b"\x30" + bytes([len(msg)]) + msg


# --------------------------------------------------------------------------- scenarios

class _Clock:
    def __init__(self, step):
        self.t, self.step, self.packets = START, step, []

    def add(self, data, dt=None):
        self.t += self.step if dt is None else dt
        self.packets.append((self.t, data))


def attacks():
    """One example of each signal in SIGNALS. Returns [(timestamp, ethernet frame)]."""
    c, rnd = _Clock(0.01), random.Random(7)
    add = c.add
    add(tcp_pkt(PC, 50001, "198.51.100.10", 80, b"GET /admin HTTP/1.1\r\nHost: panel.example\r\nAuthorization: Basic "
                + base64.b64encode(f"jane.doe:{PASSWORD}".encode()) + b"\r\n\r\n"))
    add(tcp_pkt(PC, 50002, "198.51.100.11", 80, b"POST /login HTTP/1.1\r\nHost: panel.example\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n\r\nusername=john&password=" + PASSWORD.encode()))
    add(tcp_pkt("198.51.100.12", 21, PC, 50003, b"220 FTP ready\r\n"))
    add(tcp_pkt(PC, 50003, "198.51.100.12", 21, b"USER backup\r\n"))
    add(tcp_pkt(PC, 50003, "198.51.100.12", 21, b"PASS " + PASSWORD.encode() + b"\r\n"))
    add(tcp_pkt(PC, 50004, "198.51.100.13", 143, b"a001 LOGIN anna " + PASSWORD.encode() + b"\r\n"))
    add(tcp_pkt(PC, 50005, "198.51.100.14", 587, b"AUTH PLAIN " + base64.b64encode(b"\0mail@company.example\0" + PASSWORD.encode()) + b"\r\n"))
    add(tcp_pkt(PC, 50006, "192.168.1.5", 389, ldap_bind("cn=admin,dc=company", PASSWORD)))
    add(tcp_pkt(PC, 50007, "192.168.1.9", 23, b"\xff\xfd\x18login: root\r\n"))
    add(tcp_pkt(PC, 50008, "192.168.1.6", 445, b"\x00\x00\x00\x2f\xffSMBr" + b"\0" * 40))
    add(udp_pkt(PC, 50009, "192.168.1.2", 161, snmp_get("public")))
    add(udp_pkt(PC, 50010, "224.0.0.252", 5355, dns_query("office-printer")))
    add(tcp_pkt(PC, 50011, "198.51.100.20", 443, tls_client_hello("old.example")))
    add(tcp_pkt("198.51.100.20", 443, PC, 50011, tls_server_hello(0x0301, 0x0005)))  # TLS 1.0, RC4-SHA
    add(tcp_pkt(PC, 50012, "198.51.100.30", 443, tls_client_hello("bad.malware.example")))
    add(tcp_pkt(PC, 50013, "203.0.113.66", 8443, b"\x00" * 64))
    add(tcp_pkt("203.0.113.66", 8443, PC, 50013, b"\x01" * 64))
    add(tcp_pkt(PC, 50014, "198.51.100.44", 4444, b"x" * 16))
    add(tcp_pkt("198.51.100.44", 4444, PC, 50014, b"y" * 16))
    add(tcp_pkt(PC, 50015, "198.51.100.50", 80, b"GET / HTTP/1.1\r\nHost: news.example\r\n\r\n"))
    for i in range(45):  # DNS tunnel: long random labels under one domain, many TXT queries
        label = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(40))
        add(udp_pkt(PC, 40000 + i, GW, 53, dns_query(f"{label}.t.tunnel.example", 16 if i % 3 == 0 else 1, i)))
    for i in range(20):  # generated domains: NXDOMAIN for random names
        label = "".join(rnd.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(16))
        add(udp_pkt(GW, 53, PC, 41000 + i, dns_nxdomain(f"{label}.com", i)))
    for i in range(10):  # beacon: one connection every 60 s, ± 0.3 s
        add(tcp_pkt(PC, 42000 + i, "198.51.100.77", 443, flags=0x02), 60 + rnd.uniform(-0.3, 0.3))
    add(arp_reply(GW, MAC_GW))
    for _ in range(25):  # ARP spoofing: the router address claimed by another MAC
        add(arp_reply(GW, MAC_ROGUE))
    add(dhcp_offer(GW, MAC_GW))
    add(dhcp_offer(ROGUE, MAC_ROGUE))  # a second DHCP server
    return c.packets


def clean():
    """Ordinary traffic: DNS, HTTPS with TLS 1.3 and 1.2, a few regular connections, normal ARP and DHCP."""
    c = _Clock(0.05)
    add = c.add
    sites = (("www.example.org", "198.51.100.101"), ("mail.example", "198.51.100.102"), ("cdn.example", "198.51.100.103"))
    for i, (name, ip) in enumerate(sites):
        add(udp_pkt(PC, 43000 + i, GW, 53, dns_query(name, 1, i)))
        add(udp_pkt(GW, 53, PC, 43000 + i, dns_answer(name, ip, i)))
        add(tcp_pkt(PC, 44000 + i, ip, 443, flags=0x02))
        add(tcp_pkt(PC, 44000 + i, ip, 443, tls_client_hello(name)))
        add(tcp_pkt(ip, 443, PC, 44000 + i, tls_server_hello(0x0303, 0x1301, tls13=True)))
        add(tcp_pkt(ip, 443, PC, 44000 + i, tls_server_hello(0x0303, 0xC02F)))  # TLS 1.2, ECDHE-RSA-AES128-GCM
    for i in range(30):  # many real subdomains of one service: not a tunnel
        add(udp_pkt(PC, 45000 + i, GW, 53, dns_query(f"img{i}.static.example", 1, 100 + i)))
    for i in range(6):  # a few regular connections: below any beacon threshold
        add(tcp_pkt(PC, 46000 + i, "198.51.100.120", 443, flags=0x02), 300)
    add(arp_reply(GW, MAC_GW))
    add(dhcp_offer(GW, MAC_GW))
    return c.packets


SCENARIOS = {"attacks": attacks, "clean": clean}


# --------------------------------------------------------------------------- writers

LINKTYPE_ETHERNET = 1


def write_pcap(path, packets, link=LINKTYPE_ETHERNET, big_endian=False, nanoseconds=False):
    e = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    scale = 1e9 if nanoseconds else 1e6
    with open(path, "wb") as f:
        f.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 262144, link))
        for ts, data in packets:
            sec = int(ts)
            frac = int(round((ts - sec) * scale))
            f.write(struct.pack(e + "IIII", sec, frac, len(data), len(data)) + data)


def write_pcapng(path, packets, link=LINKTYPE_ETHERNET, tsresol=None):
    """tsresol: None for microseconds, 9 for nanoseconds, 0x80 | n for 2^-n seconds."""
    def block(btype, body):
        pad = (-len(body)) % 4
        n = 12 + len(body) + pad
        return struct.pack("<II", btype, n) + body + b"\0" * pad + struct.pack("<I", n)
    div = 10 ** 6 if tsresol is None else (2 ** (tsresol & 0x7F) if tsresol & 0x80 else 10 ** tsresol)
    with open(path, "wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        opts = (struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)) if tsresol is not None else b""
        f.write(block(1, struct.pack("<HHI", link, 0, 262144) + opts))
        for ts, data in packets:
            v = int(round(ts * div))
            f.write(block(6, struct.pack("<IIIII", 0, v >> 32, v & 0xFFFFFFFF, len(data), len(data)) + data))


def write(path, packets, fmt="pcap"):
    (write_pcapng if fmt == "pcapng" else write_pcap)(path, packets)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build deterministic network captures for testing analysers.")
    ap.add_argument("what", choices=["attacks", "clean", "indicators", "signals"])
    ap.add_argument("out", nargs="?", help="output file")
    ap.add_argument("--format", choices=["pcap", "pcapng"], default=None, help="default: from the file extension")
    a = ap.parse_args(argv)
    if a.what == "signals":
        for s in SIGNALS:
            where = " or ".join(s["where"]) if isinstance(s["where"], list) else s["where"]
            print(f"{s['id']:22} {where:32} {s['title']}")
        return 0
    if not a.out:
        ap.error("an output file is needed")
    if a.what == "indicators":
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(INDICATORS, f, indent=1)
        return 0
    fmt = a.format or ("pcapng" if a.out.endswith(".pcapng") else "pcap")
    packets = SCENARIOS[a.what]()
    write(a.out, packets, fmt)
    print(f"{a.out}: {len(packets)} packets ({fmt})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
