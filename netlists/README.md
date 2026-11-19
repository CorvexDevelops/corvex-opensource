# netlists · address lookup in large network lists

## netindex.py

Checks whether an address is in a list of addresses and networks, IPv4 and IPv6, fast enough to test every flow of a large capture against threat lists with hundreds of thousands of entries. Exact addresses go in a dict. Networks become sorted numeric ranges searched with bisect, plus a running maximum of the range ends that tells the search when to stop, so nested and overlapping networks give the same answer as a linear scan. IPv4-mapped IPv6 addresses are checked as IPv4.

```python
from netindex import NetIndex
ix = NetIndex()
ix.add_many(["203.0.113.66", "198.51.100.0/24"], "threat list")
ix.get("198.51.100.7")       # "threat list"
"8.8.8.8" in ix              # False
```

```bash
python3 netindex.py list.txt 198.51.100.7     # text lists: one entry per line, "#" and ";" comments
```

`load(path)` reads text lists, JSON lists and JSON objects `{label: [entries]}`.

## sharedcloud.py

A bad address inside a CDN or a big provider's own service is often a false alarm: thousands of unrelated sites share it. This tool downloads the official network lists the providers publish for this use and writes one JSON file:

- Cloudflare, Fastly, AWS CloudFront, Google services, GitHub (web, API, git, packages, pages), Apple 17.0.0.0/8
- left out on purpose: machines that customers rent (EC2, Google Cloud, CI runners), where a bad address really belongs to the attacker

```bash
python3 sharedcloud.py update shared-networks.json      # a provider that fails keeps its previous list
python3 sharedcloud.py lookup shared-networks.json 104.16.0.1
```

Licence: Apache-2.0
