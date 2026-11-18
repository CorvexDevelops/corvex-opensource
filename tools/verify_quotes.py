#!/usr/bin/env python3
"""Check the code quotes in a list of security findings against the real files.

Each finding is a JSON object with "file", "line" and "sink_quote" (and optionally "entry_quote").
A quote must be copied character for character from the file: one line or a few consecutive lines,
with or without the "  17| " prefix of a numbered view. Whitespace differences are ignored.

Result for each quote:
  verified   the quote is at the given line
  moved      the quote is in the file, at another line (the nearest one is reported)
  invented   the quote is not in the file
  missing    no quote, or too short to identify code (less than 10 letters or digits)

Usage:  python3 verify_quotes.py findings.json [--root project/folder] [--json]
Exit code 1 when at least one quote is invented.

Part of corvexai open skills, Copyright 2026 Corvex, Apache License 2.0.
"""
import argparse
import json
import os
import re
import sys

MIN_SIGNIFICANT = 10


def norm(text):
    return re.sub(r"\s+", " ", text).strip()


def significant(quote):
    return isinstance(quote, str) and len(re.sub(r"\W", "", quote)) >= MIN_SIGNIFICANT


def find_quote(lines, quote, near=None):
    """Line number (from 1) where the quote really appears, the nearest to `near`, or None."""
    if not significant(quote):
        return None
    parts = [norm(re.sub(r"^\s*\d+\s*\|\s?", "", p)) for p in quote.strip().splitlines()]
    parts = [p for p in parts if p][:8]
    if not parts:
        return None
    flat = [norm(x) for x in lines]
    hits = [i + 1 for i in range(len(flat) - len(parts) + 1) if all(parts[k] in flat[i + k] for k in range(len(parts)))]
    if not hits:
        return None
    return min(hits, key=lambda x: abs(x - near)) if near else hits[0]


def check(finding, root):
    path = os.path.join(root, finding.get("file", ""))
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return {"file": finding.get("file"), "status": "unreadable", "detail": str(e)}
    out = {"file": finding.get("file"), "line": finding.get("line")}
    for key in ("sink_quote", "entry_quote"):
        q = finding.get(key)
        if key == "entry_quote" and not q:
            continue
        if not significant(q):
            out[key] = {"status": "missing"}
            continue
        try:
            near = int(finding.get("line") or 0) or None
        except (TypeError, ValueError):
            near = None
        at = find_quote(lines, q, near)
        if at is None:
            out[key] = {"status": "invented"}
        elif key == "entry_quote":
            out[key] = {"status": "verified", "line": at}  # the input may enter on another line than the sink
        elif near and at <= near <= at + q.strip().count("\n"):
            out[key] = {"status": "verified", "line": at}  # multi-line quotes: any of their lines counts
        else:
            out[key] = {"status": "moved", "line": at}
    return out


def main():
    ap = argparse.ArgumentParser(description="Check code quotes in security findings against the real files.")
    ap.add_argument("findings", help="JSON file with a list of findings (or an object with a 'findings' list)")
    ap.add_argument("--root", default=".", help="folder the file paths are relative to")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args()
    with open(args.findings, encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("findings", []) if isinstance(data, dict) else data
    results = [check(x, args.root) for x in items if isinstance(x, dict)]
    invented = sum(1 for r in results for k in ("sink_quote", "entry_quote") if (r.get(k) or {}).get("status") == "invented")
    if args.json:
        print(json.dumps({"results": results, "invented": invented}, indent=1))
    else:
        for r in results:
            if r.get("status") == "unreadable":
                print(f"{r['file']}: unreadable ({r['detail']})")
                continue
            parts = [f"{k.split('_')[0]} {v['status']}" + (f" at line {v['line']}" if v.get("line") else "")
                     for k, v in r.items() if k in ("sink_quote", "entry_quote")]
            print(f"{r['file']}:{r.get('line')}  " + ", ".join(parts))
        print(f"\n{len(results)} findings checked, {invented} invented quotes")
    sys.exit(1 if invented else 0)


if __name__ == "__main__":
    main()
