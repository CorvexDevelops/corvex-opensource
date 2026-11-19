# pcapgen · network captures with known attacks

Builds captures by hand, byte by byte, with one example of each common attack and a clean baseline. Same bytes on every run, documentation addresses and `.example` names only, so the files are safe to commit and share.

```bash
python3 pcapgen.py attacks attacks.pcap            # 21 signals
python3 pcapgen.py clean clean.pcapng              # ordinary traffic: every alert is a false alarm
python3 pcapgen.py indicators indicators.json      # the fake threat list that goes with attacks
python3 pcapgen.py signals                         # what an analyser should report, and where
```

The attack capture contains cleartext credentials (HTTP Basic, HTTP form, FTP, IMAP, SMTP AUTH, LDAP bind), Telnet, SMBv1, SNMP v2c with the default community, LLMNR, TLS 1.0 with RC4, a TLS connection to a listed bad domain, traffic with a listed bad address, a session on port 4444, cleartext web browsing, a DNS tunnel, generated domains (NXDOMAIN bursts), a 60-second beacon, ARP spoofing of the router and a rogue DHCP server.

As a library:

```python
import pcapgen
pcapgen.write_pcapng("x.pcapng", pcapgen.attacks(), tsresol=9)   # nanosecond timestamps
frame = pcapgen.tcp_pkt("192.168.1.20", 50000, "198.51.100.1", 443, pcapgen.tls_client_hello("a.example"))
```

Builders: `eth` (with VLAN tags), `ip4` (with fragments), `ip6`, `tcp`, `udp`, `dns_query`, `dns_answer`, `dns_nxdomain`, `tls_client_hello`, `tls_server_hello`, `arp_reply`, `dhcp_offer`, `snmp_get`, `ldap_bind`. Writers: pcap (both byte orders, micro or nanoseconds) and pcapng.

Licence: Apache-2.0
