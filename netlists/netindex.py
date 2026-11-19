"""netindex: fast lookup of IP addresses in large lists of addresses and networks (IPv4 and IPv6).

Exact addresses go in a dict. Networks become sorted numeric ranges searched with bisect, plus a running
maximum of the range ends that tells the search when to stop, so overlapping and nested networks are handled
without scanning the whole list. Built for threat lists with hundreds of thousands of entries checked
against every flow of a capture. Standard library only.

    ix = NetIndex()
    ix.add("203.0.113.66", "threat list")
    ix.add("198.51.100.0/24", "hijacked networks")
    ix.get("198.51.100.7")            → "hijacked networks"

    python netindex.py list.txt 198.51.100.7 2001:db8::1     one entry per line, # comments allowed

Licence: Apache-2.0
"""
import bisect
import ipaddress
import json
import sys


class NetIndex:
    def __init__(self, memo_size=200_000):
        self.addresses = {}
        self.networks = []          # [(ip_network, label)] in insertion order
        self._pending = False
        self._ranges = {4: [], 6: []}
        self._starts = {4: [], 6: []}
        self._maxend = {4: [], 6: []}
        self._memo = {}
        self._memo_size = memo_size

    def add(self, entry, label=True):
        """Add an address or a network (CIDR). Returns False for an invalid entry."""
        entry = str(entry).strip()
        try:
            if "/" not in entry:
                self.addresses[str(ipaddress.ip_address(entry))] = label
                self._memo.clear()
                return True
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
        if net.num_addresses == 1:
            self.addresses[str(net.network_address)] = label
        else:
            self.networks.append((net, label))
            self._pending = True
        self._memo.clear()
        return True

    def add_many(self, entries, label=True):
        return sum(1 for e in entries if self.add(e, label))

    def _build(self):
        for v in (4, 6):
            self._ranges[v] = sorted((int(n.network_address), int(n.broadcast_address), i)
                                     for i, (n, _) in enumerate(self.networks) if n.version == v)
            self._starts[v] = [r[0] for r in self._ranges[v]]
            mx, out = -1, []
            for _, end, _ in self._ranges[v]:
                mx = max(mx, end)
                out.append(mx)
            self._maxend[v] = out
        self._pending = False

    def get(self, ip, default=None):
        """The label of the first entry that contains this address, or default."""
        try:
            a = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return default
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        key = str(a)
        if key in self.addresses:
            return self.addresses[key]
        if not self.networks:
            return default
        if key in self._memo:
            hit = self._memo[key]
            return default if hit is None else hit
        if self._pending:
            self._build()
        n, found, best = int(a), None, None
        rs, mx = self._ranges[a.version], self._maxend[a.version]
        i = bisect.bisect_right(self._starts[a.version], n) - 1
        while i >= 0 and mx[i] >= n:  # no range before i reaches n: stop
            st, en, idx = rs[i]
            if st <= n <= en and (best is None or idx < best):
                best = idx  # several matches: the one added first wins, like a linear scan
            i -= 1
        if best is not None:
            found = self.networks[best][1]
        if len(self._memo) < self._memo_size:
            self._memo[key] = found
        return default if found is None else found

    def __contains__(self, ip):
        return self.get(ip) is not None

    def __len__(self):
        return len(self.addresses) + len(self.networks)


def parse_lines(text):
    """Entries from a text list: one per line, '#' and ';' start comments, extra columns are ignored."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            out.append(line.split()[0].split(",")[0])
    return out


def load(path, label=None):
    """A NetIndex from a text list, or from a JSON list, or from a JSON object {label: [entries]}."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    ix = NetIndex()
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        nets = doc.get("networks", doc)
        for lbl, entries in nets.items():
            if isinstance(entries, list):
                ix.add_many(entries, lbl)
    elif isinstance(doc, list):
        ix.add_many(doc, label or path)
    else:
        ix.add_many(parse_lines(text), label or path)
    return ix


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("usage: python netindex.py LIST ADDRESS [ADDRESS ...]", file=sys.stderr)
        return 2
    ix = load(argv[0])
    code = 1
    for ip in argv[1:]:
        hit = ix.get(ip)
        print(f"{ip}\t{hit if hit is not None else '-'}")
        code = 0 if hit is not None else code
    return code


if __name__ == "__main__":
    sys.exit(main())
