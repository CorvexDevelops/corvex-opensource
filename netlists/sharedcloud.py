"""sharedcloud: build the list of shared provider networks (CDNs and the providers' own services).

An address of a threat list that sits inside a CDN or a big provider's own service is often a false alarm:
thousands of unrelated sites share it. This tool downloads the official lists the providers publish for
exactly this use, and writes one JSON file that netindex.py can load.

Included: Cloudflare, Fastly, AWS CloudFront, Google services (not Google Cloud customers), GitHub (web, API,
git, packages, pages) and Apple's 17.0.0.0/8. Left out on purpose: machines that customers rent (EC2, Google
Cloud, CI runners), because there a bad address really belongs to the attacker.

    python sharedcloud.py update shared-networks.json
    python sharedcloud.py lookup shared-networks.json 104.16.0.1 8.8.8.8

Standard library only. Licence: Apache-2.0
"""
import datetime
import ipaddress
import json
import os
import sys
import urllib.request

from netindex import NetIndex

SOURCES = {
    "Cloudflare": ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"),
    "Fastly": ("https://api.fastly.com/public-ip-list",),
    "AWS CloudFront": ("https://ip-ranges.amazonaws.com/ip-ranges.json",),
    "Google": ("https://www.gstatic.com/ipranges/goog.json",),
    "GitHub": ("https://api.github.com/meta",),
}
STATIC = {"Apple": ["17.0.0.0/8"]}  # assigned to Apple alone


def parse(provider, body):
    """Networks from each provider's answer (every provider has its own format)."""
    if provider == "Cloudflare":
        return [l.strip() for l in body.splitlines() if l.strip()]
    d = json.loads(body)
    if provider == "Fastly":
        return list(d.get("addresses", [])) + list(d.get("ipv6_addresses", []))
    if provider == "AWS CloudFront":
        return ([p["ip_prefix"] for p in d.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
                + [p["ipv6_prefix"] for p in d.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"])
    if provider == "Google":
        return [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in d.get("prefixes", []) if p.get("ipv4Prefix") or p.get("ipv6Prefix")]
    if provider == "GitHub":
        return [c for k in ("web", "api", "git", "packages", "pages") for c in d.get(k, [])]
    return []


def _http(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sharedcloud/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(8_000_000).decode("utf-8", "replace")


def build(fetch=_http, previous=None, log=None):
    """{"updated", "networks": {provider: [cidr]}}. A provider that fails keeps its previous list."""
    nets = dict((previous or {}).get("networks") or {})
    for provider, urls in SOURCES.items():
        try:
            got = [c for url in urls for c in parse(provider, fetch(url))]
        except (OSError, ValueError, KeyError) as e:
            if log:
                log(f"{provider}: not updated ({e.__class__.__name__}), keeping the previous list")
            continue
        valid = []
        for c in got:
            try:
                valid.append(str(ipaddress.ip_network(c, strict=False)))
            except ValueError:
                pass
        if valid:
            nets[provider] = sorted(set(valid), key=lambda c: (":" in c, c))
    nets.update(STATIC)
    return {"updated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "networks": nets}


def index(doc):
    ix = NetIndex()
    for provider, cidrs in (doc.get("networks") or {}).items():
        ix.add_many(cidrs, provider)
    return ix


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) >= 2 and argv[0] == "update":
        prev = None
        if os.path.exists(argv[1]):
            with open(argv[1], encoding="utf-8") as f:
                prev = json.load(f)
        doc = build(previous=prev, log=lambda m: print(m, file=sys.stderr))
        tmp = argv[1] + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, argv[1])
        for p, c in doc["networks"].items():
            print(f"{p:16} {len(c):6} networks")
        return 0
    if len(argv) >= 3 and argv[0] == "lookup":
        with open(argv[1], encoding="utf-8") as f:
            ix = index(json.load(f))
        for ip in argv[2:]:
            print(f"{ip}\t{ix.get(ip) or '-'}")
        return 0
    print(__doc__.split("Standard library")[0].rsplit("\n\n", 1)[-1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
