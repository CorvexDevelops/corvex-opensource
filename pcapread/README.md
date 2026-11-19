# pcapread · .pcap and .pcapng in pure Python

Reads capture files without any capture library, and decodes the common layers. Built for untrusted files: every length is checked, oversized records stop the reading instead of allocating memory, and a damaged file yields the packets read so far.

```bash
python3 pcapread.py capture.pcapng            # summary: packets, protocols, duration, top pairs
python3 pcapread.py capture.pcap --list       # one line per packet
python3 pcapread.py capture.pcap --json       # one JSON object per packet
```

```python
import pcapread
for p in pcapread.packets("capture.pcapng"):
    if p["proto"] == 17 and p["dport"] == 53:
        is_response, rcode, questions, answers = pcapread.parse_dns(p["payload"])
    if p["proto"] == 6 and (hello := pcapread.parse_tls_hello(p["payload"])):
        print(hello)   # {'type': 'client', 'sni': ..., 'versions': [...]} or {'type': 'server', 'version': ..., 'cipher': ...}
```

| Supported | |
|---|---|
| Files | pcap (micro and nanoseconds, both byte orders), pcapng (several sections and interfaces, `if_tsresol`, enhanced, simple and obsolete packet blocks), up to 1 GB |
| Links | Ethernet with 802.1Q and QinQ, raw IP, IPv4, IPv6, BSD loopback, Linux cooked v1 and v2 |
| Layers | IPv4 (later fragments are skipped), IPv6 with hop-by-hop, routing, fragment, destination and AH headers, TCP, UDP, ARP |
| Helpers | DNS questions and A/AAAA answers (with pointer-loop protection), TLS ClientHello (SNI, offered versions) and ServerHello (real version, cipher) |

Licence: Apache-2.0
