"""pcapread: read .pcap and .pcapng captures in pure Python, and decode the common layers.

Standard library only, no capture library needed. Built to be safe on untrusted files: every length is
checked, oversized blocks stop the reading instead of allocating memory, and a damaged file yields the
packets read so far instead of crashing.

Formats: pcap (micro and nanosecond, both byte orders), pcapng (sections in either byte order, several
interfaces, if_tsresol, enhanced, simple and obsolete packet blocks).
Link types: Ethernet (with 802.1Q and QinQ tags), raw IP, IPv4, IPv6, BSD loopback, Linux cooked v1 and v2.
Layers: IPv4 (first fragments), IPv6 with extension headers, TCP, UDP, ICMP, ARP. Helpers for DNS and TLS hellos.

    python pcapread.py capture.pcapng            summary
    python pcapread.py capture.pcap --list       one line per packet
    python pcapread.py capture.pcap --json       one JSON object per packet

Licence: Apache-2.0
"""
import argparse
import collections
import json
import os
import socket
import struct
import sys

MAX_FILE = 1 << 30            # 1 GB
MAX_PACKETS = 3_000_000
MAX_BLOCK = 16 * 1024 * 1024  # largest record or block accepted
LINK_NAMES = {0: "loopback", 1: "Ethernet", 12: "raw IP", 14: "raw IP", 101: "raw IP", 108: "loopback",
              113: "Linux cooked", 228: "IPv4", 229: "IPv6", 276: "Linux cooked v2"}
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
_PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\x4d\x3c\xb2\xa1": ("<", True),
                b"\xa1\xb2\xc3\xd4": (">", False), b"\xa1\xb2\x3c\x4d": (">", True)}


class FormatError(ValueError):
    pass


# --------------------------------------------------------------------------- files

def file_type(head):
    """'pcap', 'pcapng' or None, from the first 4 bytes."""
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if head[:4] in _PCAP_MAGICS:
        return "pcap"
    return None


def read(path, limit=MAX_PACKETS):
    """Yield (timestamp, link type, frame bytes) for every packet of a capture file."""
    if os.path.getsize(path) > MAX_FILE:
        raise FormatError("capture larger than 1 GB")
    with open(path, "rb") as f:
        head = f.read(4)
        kind = file_type(head)
        if kind == "pcapng":
            yield from _pcapng(f, head, limit)
        elif kind == "pcap":
            yield from _pcap(f, head, limit)
        else:
            raise FormatError("not a .pcap or .pcapng capture")


def _pcap(f, magic, limit):
    e, nano = _PCAP_MAGICS[magic]
    rest = f.read(20)
    if len(rest) < 20:
        raise FormatError("incomplete pcap header")
    link = struct.unpack(e + "HHiIII", rest)[5] & 0xFFFF
    div = 1e9 if nano else 1e6
    n = 0
    while n < limit:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(e + "IIII", h)
        if incl > MAX_BLOCK:
            return  # damaged file: stop with what was read
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, link, data
        n += 1


def _tsresol(opts, e):
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack(e + "HH", opts[i:i + 4])
        if code == 0:
            break
        if code == 9 and ln >= 1 and i + 5 <= len(opts):
            v = opts[i + 4]
            return float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** min(v, 18))
        i += 4 + ((ln + 3) & ~3)
    return 1e6


def _pcapng(f, head, limit):
    e, ifaces, n, btype_raw = None, [], 0, head
    while n < limit:
        if btype_raw is None:
            btype_raw = f.read(4)
            if len(btype_raw) < 4:
                return
        lraw = f.read(4)
        if len(lraw) < 4:
            return
        if btype_raw == b"\x0a\x0d\x0d\x0a":  # Section Header Block: sets the byte order of the section
            bom = f.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                e = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                e = ">"
            else:
                raise FormatError("invalid pcapng section")
            blen = struct.unpack(e + "I", lraw)[0]
            if blen < 28 or blen % 4 or blen > MAX_BLOCK:
                raise FormatError("invalid pcapng section")
            if len(f.read(blen - 12)) < blen - 12:
                return
            ifaces, btype_raw = [], None
            continue
        if e is None:
            raise FormatError("pcapng without a section header")
        btype, blen = struct.unpack(e + "I", btype_raw)[0], struct.unpack(e + "I", lraw)[0]
        btype_raw = None
        if blen < 12 or blen % 4 or blen > MAX_BLOCK:
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        try:
            if btype == 1 and len(body) >= 8:  # Interface Description Block
                link, _reserved, _snap = struct.unpack(e + "HHI", body[:8])
                ifaces.append((link, _tsresol(body[8:], e)))
            elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
                iid, th, tl, cap, _orig = struct.unpack(e + "IIIII", body[:20])
                if iid < len(ifaces):
                    link, div = ifaces[iid]
                    yield ((th << 32) | tl) / div, link, body[20:20 + cap]
                    n += 1
            elif btype == 3 and len(body) >= 4 and ifaces:  # Simple Packet Block: no timestamp
                orig = struct.unpack(e + "I", body[:4])[0]
                yield 0.0, ifaces[0][0], body[4:4 + orig]
                n += 1
            elif btype == 2 and len(body) >= 20:  # Packet Block (obsolete)
                iid, _drops, th, tl, cap, _orig = struct.unpack(e + "HHIIII", body[:20])
                if iid < len(ifaces):
                    link, div = ifaces[iid]
                    yield ((th << 32) | tl) / div, link, body[20:20 + cap]
                    n += 1
        except struct.error:
            continue


# --------------------------------------------------------------------------- layers

def _ip4(b):
    return socket.inet_ntop(socket.AF_INET, b)


def _ip6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def mac(b):
    return ":".join(f"{x:02x}" for x in b) if b else None


def link_layer(link, d):
    """(ethertype, payload, source MAC or None) from the link layer, or None."""
    if link == 1:
        if len(d) < 14:
            return None
        et, off = (d[12] << 8) | d[13], 14
        while et in (0x8100, 0x88A8) and len(d) >= off + 4:
            et, off = (d[off + 2] << 8) | d[off + 3], off + 4
        return et, d[off:], d[6:12]
    if link in (101, 12, 14):
        v = d[0] >> 4 if d else 0
        return (0x0800 if v == 4 else 0x86DD if v == 6 else 0), d, None
    if link == 228:
        return 0x0800, d, None
    if link == 229:
        return 0x86DD, d, None
    if link in (0, 108):
        if len(d) < 4:
            return None
        fams = {int.from_bytes(d[:4], "big")} if link == 108 else {int.from_bytes(d[:4], "little"), int.from_bytes(d[:4], "big")}
        if 2 in fams:
            return 0x0800, d[4:], None
        if fams & {10, 24, 28, 30}:  # AF_INET6 differs between systems
            return 0x86DD, d[4:], None
        return None
    if link == 113:
        if len(d) < 16:
            return None
        alen = min((d[4] << 8) | d[5], 8)
        return (d[14] << 8) | d[15], d[16:], d[6:6 + alen] if alen == 6 else None
    if link == 276:
        if len(d) < 20:
            return None
        return (d[0] << 8) | d[1], d[20:], d[12:18] if d[11] == 6 else None
    return None


def ip_layer(et, p):
    """(protocol, source, destination, IP payload), or None (also for IPv4 fragments after the first)."""
    if et == 0x0800:
        if len(p) < 20 or p[0] >> 4 != 4:
            return None
        ihl = (p[0] & 0x0F) * 4
        tot = (p[2] << 8) | p[3]
        if ihl < 20 or len(p) < ihl:
            return None
        if ((p[6] & 0x1F) << 8) | p[7]:
            return None
        end = tot if ihl <= tot <= len(p) else len(p)
        return p[9], _ip4(p[12:16]), _ip4(p[16:20]), p[ihl:end]
    if et == 0x86DD:
        if len(p) < 40:
            return None
        nh, src, dst, off = p[6], _ip6(p[8:24]), _ip6(p[24:40]), 40
        for _ in range(8):
            if nh in (0, 43, 60) and len(p) >= off + 2:  # hop-by-hop, routing, destination options
                nh, off = p[off], off + (p[off + 1] + 1) * 8
            elif nh == 44 and len(p) >= off + 8:  # fragment: only the first one has the transport header
                if ((p[off + 2] << 8) | p[off + 3]) >> 3:
                    return None
                nh, off = p[off], off + 8
            elif nh == 51 and len(p) >= off + 2:  # authentication header
                nh, off = p[off], off + (p[off + 1] + 2) * 4
            else:
                break
        return nh, src, dst, p[off:]
    return None


def arp(p):
    """{'op', 'sender_mac', 'sender_ip', 'target_mac', 'target_ip'} for Ethernet/IPv4 ARP, or None."""
    if len(p) < 28 or p[:6] != b"\x00\x01\x08\x00\x06\x04":
        return None
    return {"op": "reply" if p[7] == 2 else "request" if p[7] == 1 else str(p[7]), "sender_mac": mac(p[8:14]),
            "sender_ip": _ip4(p[14:18]), "target_mac": mac(p[18:24]), "target_ip": _ip4(p[24:28])}


def decode(ts, link, frame):
    """A dict describing one packet. Keys always present: ts, link, src_mac, ethertype, proto, src, dst,
    sport, dport, tcp_flags, payload. Unknown layers leave the fields at None."""
    pkt = {"ts": ts, "link": link, "src_mac": None, "ethertype": None, "proto": None, "src": None, "dst": None,
           "sport": None, "dport": None, "tcp_flags": None, "payload": b""}
    l2 = link_layer(link, frame)
    if not l2:
        return pkt
    et, p, src_mac = l2
    pkt.update(ethertype=et, src_mac=mac(src_mac))
    if et == 0x0806:
        pkt["arp"] = arp(p)
        return pkt
    l3 = ip_layer(et, p)
    if not l3:
        return pkt
    proto, src, dst, body = l3
    pkt.update(proto=proto, src=src, dst=dst, payload=body)
    if proto == 6 and len(body) >= 20:
        off = (body[12] >> 4) * 4
        pkt.update(sport=(body[0] << 8) | body[1], dport=(body[2] << 8) | body[3], tcp_flags=body[13],
                   payload=body[off:] if 20 <= off <= len(body) else b"")
    elif proto == 17 and len(body) >= 8:
        pkt.update(sport=(body[0] << 8) | body[1], dport=(body[2] << 8) | body[3], payload=body[8:])
    return pkt


def packets(path, limit=MAX_PACKETS):
    """Decoded packets of a capture file."""
    for ts, link, frame in read(path, limit):
        yield decode(ts, link, frame)


# --------------------------------------------------------------------------- application helpers

def _dns_name(p, off):
    labels, jumps, end = [], 0, None
    while True:
        if off >= len(p):
            raise ValueError("truncated DNS name")
        ln = p[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(p):
                raise ValueError("truncated DNS pointer")
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 12:
                raise ValueError("DNS pointer loop")
            off = ((ln & 0x3F) << 8) | p[off + 1]
            continue
        if ln & 0xC0:
            raise ValueError("invalid DNS label")
        labels.append(p[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
        if len(labels) > 127:
            raise ValueError("DNS name too long")
    return ".".join(labels).lower(), (end if end is not None else off)


def parse_dns(p):
    """(is_response, rcode, [(name, qtype)], [(name, address)]). Raises ValueError on a damaged message."""
    if len(p) < 12:
        raise ValueError("DNS message too short")
    _id, flags, qd, an = struct.unpack(">HHHH", p[:8])
    off, qs, ans = 12, [], []
    try:
        for _ in range(min(qd, 4)):
            name, off = _dns_name(p, off)
            qtype = struct.unpack(">H", p[off:off + 2])[0]
            off += 4
            qs.append((name, qtype))
        for _ in range(min(an, 32)):
            name, off = _dns_name(p, off)
            typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", p[off:off + 10])
            off += 10
            rd = p[off:off + rdlen]
            off += rdlen
            if typ == 1 and rdlen == 4:
                ans.append((name, _ip4(rd)))
            elif typ == 28 and rdlen == 16:
                ans.append((name, _ip6(rd)))
    except struct.error:
        raise ValueError("truncated DNS message")
    return bool(flags >> 15), flags & 0x0F, qs, ans


def _tls_exts(hs, off):
    if off + 2 > len(hs):
        return
    end = min(off + 2 + ((hs[off] << 8) | hs[off + 1]), len(hs))
    off += 2
    while off + 4 <= end:
        et, ln = (hs[off] << 8) | hs[off + 1], (hs[off + 2] << 8) | hs[off + 3]
        yield et, hs[off + 4:off + 4 + ln]
        off += 4 + ln


def parse_tls_hello(p):
    """From the first handshake record of a TCP payload:
    {'type': 'client', 'sni', 'versions'} or {'type': 'server', 'version', 'cipher'}, or None."""
    if len(p) < 9 or p[0] != 0x16 or p[1] != 3:
        return None
    hs = p[5:]
    kind = hs[0]
    if kind not in (1, 2) or len(hs) < 38:
        return None
    off = 4
    legacy = (hs[off] << 8) | hs[off + 1]
    off += 2 + 32
    off += 1 + hs[off]
    if kind == 2:
        if off + 3 > len(hs):
            return None
        cipher = (hs[off] << 8) | hs[off + 1]
        version = legacy
        for et, ed in _tls_exts(hs, off + 3):
            if et == 0x002B and len(ed) >= 2:  # supported_versions picks the real one
                version = (ed[0] << 8) | ed[1]
        return {"type": "server", "version": version, "cipher": cipher}
    if off + 2 > len(hs):
        return None
    off += 2 + ((hs[off] << 8) | hs[off + 1])
    if off >= len(hs):
        return None
    off += 1 + hs[off]
    sni, offered = None, [legacy]
    for et, ed in _tls_exts(hs, off):
        if et == 0 and len(ed) >= 5 and ed[2] == 0:
            ln = (ed[3] << 8) | ed[4]
            sni = ed[5:5 + ln].decode("ascii", "replace").lower() or None
        elif et == 0x002B and ed:
            offered = [(ed[i] << 8) | ed[i + 1] for i in range(1, min(len(ed) - 1, 1 + ed[0]), 2)]
    return {"type": "client", "sni": sni, "versions": offered}


# --------------------------------------------------------------------------- command line

def _line(p):
    proto = PROTO_NAMES.get(p["proto"], str(p["proto"]) if p["proto"] is not None else "")
    if p.get("arp"):
        a = p["arp"]
        return f"{p['ts']:.6f} ARP {a['op']} {a['sender_ip']} is-at {a['sender_mac']}"
    if p["src"] is None:
        return f"{p['ts']:.6f} ethertype 0x{(p['ethertype'] or 0):04x}"
    s = f"{p['src']}:{p['sport']}" if p["sport"] is not None else p["src"]
    d = f"{p['dst']}:{p['dport']}" if p["dport"] is not None else p["dst"]
    return f"{p['ts']:.6f} {proto} {s} > {d} len {len(p['payload'])}"


def summary(path):
    n, protos, talkers, links, first, last = 0, collections.Counter(), collections.Counter(), collections.Counter(), None, None
    for p in packets(path):
        n += 1
        links[LINK_NAMES.get(p["link"], str(p["link"]))] += 1
        protos["ARP" if p.get("arp") else PROTO_NAMES.get(p["proto"], "other")] += 1
        if p["src"]:
            talkers[(p["src"], p["dst"])] += 1
        if p["ts"]:
            first = p["ts"] if first is None else min(first, p["ts"])
            last = p["ts"] if last is None else max(last, p["ts"])
    return {"packets": n, "links": dict(links), "protocols": dict(protos),
            "duration_s": round(last - first, 3) if first is not None else 0,
            "top_pairs": [{"src": s, "dst": d, "packets": c} for (s, d), c in talkers.most_common(10)]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read .pcap and .pcapng captures in pure Python")
    ap.add_argument("capture")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--list", action="store_true", help="one line per packet")
    g.add_argument("--json", action="store_true", help="one JSON object per packet")
    ap.add_argument("--limit", type=int, default=MAX_PACKETS)
    a = ap.parse_args(argv)
    try:
        if a.list or a.json:
            for p in packets(a.capture, a.limit):
                if a.json:
                    p = dict(p, payload_len=len(p["payload"]))
                    del p["payload"]
                    print(json.dumps(p))
                else:
                    print(_line(p))
        else:
            print(json.dumps(summary(a.capture), indent=1))
    except FormatError as err:
        print(f"{a.capture}: {err}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
