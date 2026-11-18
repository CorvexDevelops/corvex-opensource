"""Paired benchmark for security scanners: how many known flaws a tool finds, and how many false alarms it raises.

Every target comes in two versions: one full of known flaws and one done well, with look-alike traps.
A finding on a vulnerable target counts when it matches a flaw in expected.json. Any finding on a clean
target is a false alarm. The accepted result is kept in a baseline file, and the run fails only when
something gets worse: a flaw that used to be found is missed, or a new false alarm appears.

Works with any tool that writes SARIF 2.1.0, or a simple JSON list of findings. Standard library only.

    python bench.py list                       the expected flaws
    python bench.py serve                      start both web targets on 127.0.0.1
    python bench.py prepare work/              copy the code targets and write the captures
    python bench.py score results/             score <target>.sarif or <target>.json files
    python bench.py score results/ --baseline baseline.json [--update]

Licence: Apache-2.0
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS_DIR = os.path.join(HERE, "targets")
EXPECTED = os.path.join(HERE, "expected.json")
LEVELS = {"none": 0, "note": 1, "warning": 2, "error": 3}
CWE_RX = re.compile(r"cwe[\s_:/-]*0*(\d{1,5})", re.I)


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_expected(path=EXPECTED):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------- reading results

def cwes(*values):
    """CWE ids found in strings, numbers or lists: "CWE-89", "external/cwe/cwe-089", 89."""
    out = set()
    for v in values:
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            out |= cwes(*v)
        elif isinstance(v, int) and not isinstance(v, bool):
            out.add(v)
        elif isinstance(v, str):
            if v.strip().isdigit():
                out.add(int(v))
            out |= {int(m) for m in CWE_RX.findall(v)}
    return out


def _finding(rule="", message="", cwe=(), file="", line=None, location="", level="warning", extra=""):
    try:
        line = int(line) if line not in (None, "") else None
    except (TypeError, ValueError):
        line = None
    return {"rule": str(rule or ""), "message": str(message or ""), "cwe": sorted(cwes(cwe)), "file": str(file or ""),
            "line": line, "location": str(location or ""), "level": str(level or "warning").lower(), "text": str(extra or "")}


def _sarif_rules(run):
    rules = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    for comp in [driver] + list((run.get("tool") or {}).get("extensions") or []):
        for i, r in enumerate(comp.get("rules") or []):
            props = r.get("properties") or {}
            info = {"cwe": cwes(props.get("tags"), props.get("cwe"), r.get("relationships") and
                                [((x.get("target") or {}).get("id")) for x in r["relationships"]]),
                    "level": ((r.get("defaultConfiguration") or {}).get("level")),
                    "text": " ".join(str((r.get(k) or {}).get("text", "")) for k in ("shortDescription", "fullDescription")) + " " + str(r.get("name") or "")}
            if r.get("id"):
                rules[r["id"]] = info
            if comp is driver:
                rules[i] = info
    return rules


def read_sarif(doc):
    out = []
    for run in doc.get("runs") or []:
        rules = _sarif_rules(run)
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or ""
            info = rules.get(rid) or rules.get(res.get("ruleIndex")) or {}
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri") or ""
            line = (phys.get("region") or {}).get("startLine")
            logical = " ".join(str(l.get("fullyQualifiedName") or l.get("name") or "") for l in locs[0].get("logicalLocations") or [])
            props = res.get("properties") or {}
            is_url = uri.startswith(("http://", "https://"))
            out.append(_finding(rid, (res.get("message") or {}).get("text"), [info.get("cwe"), props.get("tags"), props.get("cwe")],
                                "" if is_url else uri, line, uri if is_url else (logical or uri),
                                res.get("level") or info.get("level") or "warning", info.get("text")))
    return out


def read_json(doc):
    items = doc.get("findings") or doc.get("results") or [] if isinstance(doc, dict) else doc
    out = []
    for x in items or []:
        if not isinstance(x, dict):
            continue
        loc = x.get("location") or x.get("url") or ""
        file = x.get("file") or x.get("path") or ""
        line = x.get("line")
        if not file and isinstance(loc, str) and not loc.startswith(("http://", "https://")):
            m = re.match(r"^(.+?):(\d+)$", loc)
            file, line = (m.group(1), m.group(2)) if m else (loc, line)
        out.append(_finding(x.get("rule") or x.get("ruleId") or x.get("id"), x.get("message") or x.get("title"),
                            [x.get("cwe"), x.get("cwes"), x.get("tags")], file, line, loc, x.get("level") or x.get("severity") or "warning",
                            x.get("description")))
    return out


def read_results(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return read_sarif(doc) if isinstance(doc, dict) and "runs" in doc else read_json(doc)


def find_results(results_dir, target):
    for ext in (".sarif", ".sarif.json", ".json"):
        p = os.path.join(results_dir, target + ext)
        if os.path.exists(p):
            return p
    return None


# --------------------------------------------------------------------------- matching

def norm_path(p):
    p = urllib.parse.unquote(str(p or ""))
    if p.startswith("file://"):
        p = p[7:]
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def resolve_line(target, file, snippet):
    """Line (1-based) of the first line of targets/<target>/<file> that contains the snippet."""
    try:
        with open(os.path.join(TARGETS_DIR, target, file), encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if snippet in line:
                    return n
    except OSError:
        pass
    raise ValueError(f"{target}/{file}: snippet not found: {snippet!r}")


def _haystack(r):
    return f"{r['rule']} {r['message']} {r['text']}".lower()


def _web_path(loc):
    s = urllib.parse.urlsplit(loc)
    return (s.path + ("?" + s.query if s.query else "")) if s.scheme in ("http", "https") else loc


def location_ok(kind, exp, r, lines):
    if kind == "code":
        f = norm_path(r["file"] or r["location"])
        want = exp["file"]
        if not (f == want or f.endswith("/" + want)):
            return False, False
        if exp["id"] in lines:
            if r["line"] is None:
                return True, False  # right file, no line: only a keyword match counts
            return abs(r["line"] - lines[exp["id"]]) <= exp.get("tolerance", 2), True
        return True, True
    if kind == "web":
        return exp.get("path", "") in _web_path(r["location"] or r["file"]), True
    where = (exp.get("where") or "").lower()
    return where in f"{r['location']} {r['message']} {r['rule']}".lower(), True


def edges(kind, exp, findings, lines):
    """Indexes of findings that match one expected flaw: keyword matches first, then CWE matches."""
    by_kw, by_cwe = [], []
    for i, r in enumerate(findings):
        ok, cwe_allowed = location_ok(kind, exp, r, lines)
        if not ok:
            continue
        if any(k.lower() in _haystack(r) for k in exp.get("keywords") or []):
            by_kw.append(i)
        elif cwe_allowed and set(exp.get("cwe") or []) & set(r["cwe"]):
            by_cwe.append(i)
    return by_kw + by_cwe


def assign(adj, n_findings):
    """Maximum matching between expected flaws and findings: each finding counts for one flaw at most."""
    owner = [-1] * n_findings

    def augment(e, seen):
        for i in adj[e]:
            if i in seen:
                continue
            seen.add(i)
            if owner[i] < 0 or augment(owner[i], seen):
                owner[i] = e
                return True
        return False
    for e in range(len(adj)):
        augment(e, set())
    return {e: i for i, e in enumerate(owner) if e >= 0}


def informational(r, info):
    return bool(set(info.get("cwe") or []) & set(r["cwe"])) or any(k in _haystack(r) for k in info.get("keywords") or [])


def finding_id(target, r):
    where = f"{norm_path(r['file'])}:{r['line']}" if r["file"] and r["line"] else (_web_path(r["location"]) or norm_path(r["file"]) or "-")
    return f"{target} · {r['rule'] or '?'} · {where}"


def score_target(name, spec, findings, info):
    rep = {"kind": spec["kind"], "found": [], "missed": [], "false_alarms": [], "uncatalogued": [], "findings": len(findings)}
    if spec.get("clean"):
        rep["false_alarms"] = sorted({finding_id(name, r) for r in findings if not informational(r, info)})
        return rep
    expected = spec["expected"]
    lines = {e["id"]: resolve_line(name, e["file"], e["contains"]) for e in expected if spec["kind"] == "code" and e.get("contains")}
    adj = [edges(spec["kind"], e, findings, lines) for e in expected]
    match = assign(adj, len(findings))
    used = set(match.values())
    for n, e in enumerate(expected):
        (rep["found"] if n in match else rep["missed"]).append(f"{name}/{e['id']}")
    rep["uncatalogued"] = sorted({finding_id(name, r) for i, r in enumerate(findings) if i not in used and not informational(r, info)})
    rep["expected"] = len(expected)
    return rep


def score(results_dir, expected=None, min_level="none"):
    expected = expected or load_expected()
    info = expected.get("informational") or {}
    report = {"targets": {}, "skipped": []}
    for name, spec in expected["targets"].items():
        path = find_results(results_dir, name)
        if not path:
            report["skipped"].append(name)
            continue
        findings = [r for r in read_results(path) if LEVELS.get(r["level"], 2) >= LEVELS[min_level]]
        report["targets"][name] = score_target(name, spec, findings, info)
    t = report["targets"].values()
    report["summary"] = {"found": sum(len(x["found"]) for x in t), "expected": sum(x.get("expected", 0) for x in t),
                         "false_alarms": sum(len(x["false_alarms"]) for x in t)}
    return report


def compare(report, baseline):
    """Differences with the baseline, limited to the targets scored in both."""
    scored = set(report["targets"])
    keep = lambda ids: {i for i in ids if i.split("/", 1)[0].split(" · ", 1)[0] in scored}
    found = {i for t in report["targets"].values() for i in t["found"]}
    false = {i for t in report["targets"].values() for i in t["false_alarms"]}
    old_f, old_fa = keep(baseline.get("found", [])), keep(baseline.get("false_alarms", []))
    return {"lost": sorted(old_f - found), "new_false_alarms": sorted(false - old_fa),
            "newly_found": sorted(found - old_f), "false_alarms_gone": sorted(old_fa - false)}


# --------------------------------------------------------------------------- output

def titles(expected):
    return {f"{n}/{e['id']}": e["title"] for n, s in expected["targets"].items() for e in s.get("expected", [])}


def print_report(report, expected):
    names = titles(expected)
    print(f"{'target':18} {'found':>9} {'false alarms':>13}")
    for name, t in report["targets"].items():
        found = f"{len(t['found'])}/{t['expected']}" if "expected" in t else "-"
        print(f"{name:18} {found:>9} {len(t['false_alarms']):>13}")
    s = report["summary"]
    pct = round(100 * s["found"] / s["expected"]) if s["expected"] else 0
    print(f"{'TOTAL':18} {str(s['found']) + '/' + str(s['expected']):>9} {s['false_alarms']:>13}   ({pct}% of the known flaws)")
    for name, t in report["targets"].items():
        for label, key in (("missed", "missed"), ("false alarms", "false_alarms"), ("not in the catalogue (worth a look)", "uncatalogued")):
            if t[key]:
                print(f"\n{name} · {label}:")
                for i in t[key]:
                    print(f"  - {i}  {names.get(i, '')}".rstrip())
    if report["skipped"]:
        print(f"\nNo results for: {', '.join(report['skipped'])}")


# --------------------------------------------------------------------------- commands

def cmd_list(a):
    exp = load_expected()
    for name, spec in exp["targets"].items():
        print(f"\n{name}  ({spec['kind']}{', clean' if spec.get('clean') else ''})  {spec.get('description', '')}")
        for e in spec.get("expected", []):
            where = e.get("file", "") + (f" «{e['contains']}»" if e.get("contains") else "") if spec["kind"] == "code" else e.get("path", e.get("where", ""))
            cwe = ",".join(f"CWE-{c}" for c in e.get("cwe", []))
            print(f"  {e['id']}  {e['title']}  [{cwe or '-'}]  {where}")


def cmd_serve(a):
    vuln = _load_module("web_vulnerable", os.path.join(TARGETS_DIR, "web-vulnerable", "server.py"))
    clean = _load_module("web_clean", os.path.join(TARGETS_DIR, "web-clean", "server.py"))
    servers = [vuln.start_background(a.vulnerable_port), clean.start_background(a.clean_port)]
    print(f"web-vulnerable  http://127.0.0.1:{a.vulnerable_port}/")
    print(f"web-clean       http://127.0.0.1:{a.clean_port}/")
    print("Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        for s in servers:
            s.shutdown()
    return 0


def cmd_prepare(a):
    os.makedirs(a.out, exist_ok=True)
    for name in ("code-vulnerable", "code-clean"):
        dst = os.path.join(a.out, name)
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(os.path.join(TARGETS_DIR, name), dst)
    pg = _load_module("pcapgen", os.path.join(HERE, os.pardir, "pcapgen", "pcapgen.py"))
    pg.write_pcap(os.path.join(a.out, "traffic-attacks.pcap"), pg.attacks())
    pg.write_pcap(os.path.join(a.out, "traffic-clean.pcap"), pg.clean())
    with open(os.path.join(a.out, "indicators.json"), "w", encoding="utf-8") as f:
        json.dump(pg.INDICATORS, f, indent=1)
    print(f"Ready in {a.out}: code-vulnerable/, code-clean/, traffic-attacks.pcap, traffic-clean.pcap, indicators.json")
    return 0


def cmd_score(a):
    exp = load_expected()
    report = score(a.results, exp, a.min_level)
    print_report(report, exp)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
    if not report["targets"]:
        print("\nNo result files found.")
        return 2
    if not a.baseline:
        return 0
    found = sorted(i for t in report["targets"].values() for i in t["found"])
    false = sorted(i for t in report["targets"].values() for i in t["false_alarms"])
    if a.update:
        with open(a.baseline, "w", encoding="utf-8") as f:
            json.dump({"summary": report["summary"], "found": found, "false_alarms": false}, f, indent=1)
            f.write("\n")
        print("\nBaseline updated.")
        return 0
    if not os.path.exists(a.baseline):
        print("\nNo baseline yet: check the result and save it with --update.")
        return 0
    with open(a.baseline, encoding="utf-8") as f:
        diff = compare(report, json.load(f))
    for label, key in (("WORSE · flaws no longer found", "lost"), ("WORSE · new false alarms", "new_false_alarms"),
                       ("better · flaws found now", "newly_found"), ("better · false alarms gone", "false_alarms_gone")):
        if diff[key]:
            print(f"\n{label}:")
            for i in diff[key]:
                print(f"  - {i}")
    if diff["lost"] or diff["new_false_alarms"]:
        print("\nFailed: worse than the baseline.")
        return 1
    print("\nBetter than the baseline: save it with --update if that is intended." if diff["newly_found"] or diff["false_alarms_gone"]
          else "\nIn line with the baseline.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Paired benchmark for security scanners")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show the expected flaws")
    s = sub.add_parser("serve", help="start both web targets on 127.0.0.1")
    s.add_argument("--vulnerable-port", type=int, default=8099)
    s.add_argument("--clean-port", type=int, default=8098)
    p = sub.add_parser("prepare", help="copy the code targets and write the captures into a folder")
    p.add_argument("out")
    sc = sub.add_parser("score", help="score result files named <target>.sarif or <target>.json")
    sc.add_argument("results")
    sc.add_argument("--baseline", help="baseline file to compare with")
    sc.add_argument("--update", action="store_true", help="save this result as the new baseline")
    sc.add_argument("--json", help="also write the full report to this file")
    sc.add_argument("--min-level", choices=list(LEVELS), default="none", help="ignore findings below this SARIF level")
    a = ap.parse_args(argv)
    return {"list": cmd_list, "serve": cmd_serve, "prepare": cmd_prepare, "score": cmd_score}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
