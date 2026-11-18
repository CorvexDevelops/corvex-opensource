# bench · paired benchmark for security scanners

Measures how many known flaws a tool finds and how many false alarms it raises. Every target comes in two versions: one full of known flaws and one done well, with look-alike traps. Works with any tool that writes SARIF 2.1.0 or a simple JSON list.

| Target | Kind | Expected flaws |
|---|---|---|
| `web-vulnerable` | web shop on 127.0.0.1 | 18 (headers, cookies, exposed files, CORS, XSS, SQL injection, open redirect, outdated library, brute force, API) |
| `web-clean` | the same shop done well | none: every finding is a false alarm |
| `code-vulnerable` | Python, Node.js, Dockerfile, dependencies | 32 (injections, deserialisation, crypto, TLS, JWT, secrets, debug, CORS, containers, 9 vulnerable dependencies) |
| `code-clean` | the same project done well, with traps such as `md5(usedforsecurity=False)` and comments that mention `eval()` | none |
| `traffic-attacks` | capture from `pcapgen attacks`, with `pcapgen indicators` as threat list | 21 |
| `traffic-clean` | capture from `pcapgen clean` | none |

## Commands

```bash
python3 bench.py list                                    # every expected flaw, with CWE and location
python3 bench.py serve                                   # web-vulnerable on 8099, web-clean on 8098
python3 bench.py prepare work/                           # code targets, captures and indicators
python3 bench.py score results/ --baseline baseline.json --update   # first run: save the baseline
python3 bench.py score results/ --baseline baseline.json            # later runs: exit 1 if worse
```

`score` reads `results/<target>.sarif`, `.sarif.json` or `.json`. Targets without a file are skipped, so a code scanner can be scored on the code targets only. Options: `--json report.json` writes the full report, `--min-level warning` ignores SARIF notes.

## How a finding matches an expected flaw

1. **Location.** Code: the same file, and a line within 2 of the line that contains the snippet in `expected.json` (0 for dependencies). Lines are found by the snippet, not stored as numbers, so editing a target does not break the expectations. Web: the path in the URL (`/search`, `/.env`). Network: the address, port or name in the location or message.
2. **Kind.** One of the expected keywords appears in the rule id, message or rule description, or one of the finding's CWE ids is listed. A finding with the right file but no line counts only on a keyword.
3. **Once.** Each finding counts for one expected flaw at most. The assignment is a maximum matching, so the order of findings does not change the score.

Findings on a vulnerable target that match nothing are listed as "not in the catalogue": they are not false alarms, but worth a look. Findings about licences are informational and never count as false alarms.

## JSON results

```json
[{"rule": "sql-injection", "message": "query built from input", "cwe": "CWE-89", "file": "app.py", "line": 23},
 {"rule": "xss", "message": "reflected", "location": "http://127.0.0.1:8099/search?q=x"}]
```

`file:line` in `location` also works. `cwe` can be a number, a string or a list.

Licence: Apache-2.0
