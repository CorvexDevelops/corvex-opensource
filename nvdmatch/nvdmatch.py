"""nvdmatch: which known vulnerabilities really affect an installed version, from the NVD CVE API 2.0.

Asking NVD for a product returns every CVE ever published for it, also the ones fixed long before the
installed version. nvdmatch keeps only the CVEs whose CPE match has an explicit version bound that
includes the installed version (versionEndExcluding, versionEndIncluding, start bounds, or the exact
version in the CPE). A match with no bound at all is skipped: it cannot say if this version is affected.

Standard library only. Only vendor, product and version are sent to NVD. Answers are cached on disk.
Without an API key NVD allows 5 requests every 30 seconds: the client spaces them. Set NVD_API_KEY to
raise the limit.

This product uses the NVD API but is not endorsed or certified by the NVD.

    python nvdmatch.py lookup mozilla firefox 115.0
    python nvdmatch.py check inventory.json          [{"vendor", "product", "version", "name"?}, ...]
    python nvdmatch.py match nvd-response.json mozilla firefox 115.0     offline, on a saved answer

Licence: Apache-2.0
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 500
CACHE_DAYS = 7
CPE_PART = re.compile(r"^[a-z0-9._\-~%+!]+$", re.I)


def vtuple(v):
    """'120.0.6099.62' → (120, 0, 6099, 62). Non-numeric parts count as 0, trailing zeros are dropped."""
    out = []
    for p in re.split(r"[.\-_+]", str(v or "")):
        m = re.match(r"\d+", p)
        out.append(int(m.group(0)) if m else 0)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return tuple(out)


def clean_version(v):
    """The leading dotted number of a version string: '2.4.1 (build 77)' → '2.4.1'."""
    m = re.match(r"\d+(?:\.\d+)*", str(v or "").strip())
    return m.group(0) if m else ""


def cvss(cve):
    """Base score of the newest CVSS version present, or None."""
    m = cve.get("metrics") or {}
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            try:
                return float(m[k][0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                pass
    return None


def severity(score):
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


def bound_match(m, version):
    """True or False when the cpeMatch has a version bound, None when it has none."""
    parts = str(m.get("criteria", "")).split(":")
    v = vtuple(version)
    end_ex, end_in = m.get("versionEndExcluding"), m.get("versionEndIncluding")
    st_in, st_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
    if end_ex:
        ok = v < vtuple(end_ex)
    elif end_in:
        ok = v <= vtuple(end_in)
    elif len(parts) > 5 and parts[5] not in ("*", "-", ""):
        ok = vtuple(parts[5]) == v  # one exact version
    elif st_in or st_ex:
        ok = True  # open-ended: from a version onwards
    else:
        return None
    if ok and st_in:
        ok = v >= vtuple(st_in)
    if ok and st_ex:
        ok = v > vtuple(st_ex)
    return ok


def affecting(vulnerabilities, vendor, product, version):
    """CVEs of an NVD answer that affect this version: [{id, cvss, severity, fixed_in}], worst first."""
    out = {}
    for item in vulnerabilities:
        c = item.get("cve") or {}
        for cfg in c.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    parts = str(m.get("criteria", "")).split(":")
                    if len(parts) < 6 or not m.get("vulnerable") or parts[3] != vendor or parts[4] != product:
                        continue
                    if bound_match(m, version) and c.get("id"):
                        prev = out.get(c["id"])
                        fixed = m.get("versionEndExcluding") or ""
                        if not prev or (fixed and vtuple(fixed) > vtuple(prev["fixed_in"])):
                            score = cvss(c)
                            out[c["id"]] = {"id": c["id"], "cvss": score, "severity": severity(score), "fixed_in": fixed}
    return sorted(out.values(), key=lambda x: (-(x["cvss"] or 0), x["id"]))


def min_fixed(found):
    """The lowest version that fixes every listed CVE with a known fix, or ''."""
    return max((f["fixed_in"] for f in found if f["fixed_in"]), key=vtuple, default="")


class NVDClient:
    def __init__(self, cache_path=None, key=None, fetch=None, pause=None, user_agent="nvdmatch/1"):
        self.cache_path = cache_path
        self.key = key if key is not None else os.environ.get("NVD_API_KEY", "")
        self.pause = pause if pause is not None else (0.7 if self.key else 6.5)
        self.user_agent = user_agent
        self._fetch = fetch or self._http
        self._last = 0.0

    def _http(self, url):
        headers = {"User-Agent": self.user_agent}
        if self.key:
            headers["apiKey"] = self.key
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
            return json.loads(r.read(40_000_000))

    def _get(self, url):
        wait = self.pause - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        try:
            return self._fetch(url)
        finally:
            self._last = time.time()

    def _cache(self):
        if not self.cache_path:
            return {}
        try:
            with open(self.cache_path, encoding="utf-8") as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d):
        if not self.cache_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.cache_path)), exist_ok=True)
        tmp = self.cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, self.cache_path)

    def lookup(self, vendor, product, version, all_pages=False):
        """CVEs that affect this version. By default only the newest 500 answers are read: the ones that matter
        for an installed version are the recent ones, and NVD lists them last. all_pages=True reads everything.
        Raises OSError or ValueError when NVD does not answer."""
        if not (CPE_PART.match(vendor or "") and CPE_PART.match(product or "") and CPE_PART.match(version or "")):
            raise ValueError("vendor, product and version must be plain CPE values")
        key = f"{vendor}:{product}:{version}:{'all' if all_pages else 'last'}"
        cache = self._cache()
        hit = cache.get(key)
        if hit and time.time() - hit.get("t", 0) < CACHE_DAYS * 86400:
            return hit["cve"]
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}"
        base = f"{API}?virtualMatchString={urllib.parse.quote(cpe, safe=':')}&noRejected"
        total = int(self._get(base + "&resultsPerPage=1").get("totalResults") or 0)
        items = []
        starts = range(0, total, PAGE) if all_pages else ([max(0, total - PAGE)] if total else [])
        for start in starts:
            items += self._get(base + f"&resultsPerPage={PAGE}&startIndex={start}").get("vulnerabilities") or []
        found = affecting(items, vendor, product, version)
        cache[key] = {"t": time.time(), "cve": found, "total": total}
        self._save(cache)
        return found


def check(inventory, client, budget=None, log=None):
    """[{name, vendor, product, version, cves, worst, fixed_in}] for the inventory items with known CVEs."""
    log = log or (lambda m: None)
    out, t0, failed = [], time.time(), 0
    for k, a in enumerate(inventory):
        if budget and time.time() - t0 > budget:
            log(f"time budget reached: {len(inventory) - k} items not checked")
            break
        version = clean_version(a.get("version"))
        if not version:
            continue
        try:
            found = client.lookup(a["vendor"], a["product"], version)
        except (OSError, ValueError, urllib.error.URLError) as e:
            failed += 1
            log(f"{a.get('name') or a['product']}: {e.__class__.__name__}")
            if failed >= 3:
                log("NVD not reachable: stopping")
                break
            continue
        if found:
            out.append({"name": a.get("name") or a["product"], "vendor": a["vendor"], "product": a["product"], "version": version,
                        "cves": found, "worst": found[0]["severity"], "fixed_in": min_fixed(found)})
    return out


def _print(found, label):
    if not found:
        print(f"{label}: no known vulnerability with a version bound that includes it")
        return
    fix = min_fixed(found)
    print(f"{label}: {len(found)} known vulnerabilities" + (f", fixed in {fix} or later" if fix else ""))
    for f in found[:20]:
        print(f"  {f['id']:18} {f['severity']:9} {f['cvss'] if f['cvss'] is not None else '-':>5}   fixed in {f['fixed_in'] or '?'}")
    if len(found) > 20:
        print(f"  … and {len(found) - 20} more")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Known vulnerabilities that really affect an installed version (NVD CVE API 2.0)")
    ap.add_argument("--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "nvdmatch.json"), help="cache file")
    ap.add_argument("--all-pages", action="store_true", help="read every answer, not only the newest 500")
    sub = ap.add_subparsers(dest="cmd", required=True)
    lk = sub.add_parser("lookup", help="ask NVD about one product version")
    lk.add_argument("vendor")
    lk.add_argument("product")
    lk.add_argument("version")
    ck = sub.add_parser("check", help="check a JSON inventory")
    ck.add_argument("inventory")
    ck.add_argument("--budget", type=float, help="stop after this many seconds")
    mt = sub.add_parser("match", help="match a saved NVD answer offline")
    mt.add_argument("answer")
    mt.add_argument("vendor")
    mt.add_argument("product")
    mt.add_argument("version")
    a = ap.parse_args(argv)
    if a.cmd == "match":
        with open(a.answer, encoding="utf-8") as f:
            doc = json.load(f)
        _print(affecting(doc.get("vulnerabilities") or [], a.vendor, a.product, a.version), f"{a.product} {a.version}")
        return 0
    client = NVDClient(a.cache)
    if a.cmd == "lookup":
        try:
            _print(client.lookup(a.vendor, a.product, clean_version(a.version) or a.version, a.all_pages), f"{a.product} {a.version}")
        except (OSError, ValueError) as e:
            print(f"NVD: {e}", file=sys.stderr)
            return 1
        return 0
    with open(a.inventory, encoding="utf-8") as f:
        inv = json.load(f)
    res = check(inv, client, a.budget, log=lambda m: print(m, file=sys.stderr))
    for r in res:
        _print(r["cves"], f"{r['name']} {r['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
