# corvexai · open skills and tools

Open skills and tools from **corvexai**, the AI behind [Corvex](https://corvex.dev), the team of security agents that tests your web platforms, code, network and computer.

corvexai runs on the customer's own machine, next to everything else. This repository shares the parts of the work that are useful to anyone building or measuring security tools: how a compact model is made reliable for security work, a paired benchmark to measure scanners honestly, and the small network and vulnerability utilities Corvex uses every day.

Everything here is Python 3.9+ with the standard library only. No dependencies, no network access unless a tool says so.

## What is inside

| Path | What it is |
|---|---|
| [`skills/corvex-verified-evidence/`](skills/corvex-verified-evidence/SKILL.md) | how to report a finding with an exact, checkable quote of the code, so invented lines and invented code are caught |
| [`skills/corvex-agent-benchmark/`](skills/corvex-agent-benchmark/SKILL.md) | how to measure a scanner or an AI auditor honestly: paired targets, expected findings, false alarms, regression baseline |
| [`tools/verify_quotes.py`](tools/verify_quotes.py) | checks the quotes in a list of findings against the real files |
| [`bench/`](bench/README.md) | the paired benchmark itself: vulnerable and clean twins (web, code, network), expected flaws by CWE, scoring of SARIF or JSON results |
| [`pcapgen/`](pcapgen/README.md) | builds deterministic network captures with one example of 21 common attacks, plus a clean baseline |
| [`pcapread/`](pcapread/README.md) | reads .pcap and .pcapng in pure Python and decodes Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ARP, DNS and TLS hellos |
| [`nvdmatch/`](nvdmatch/README.md) | tells which CVEs really affect an installed version, using only NVD matches with an explicit version bound |
| [`netlists/`](netlists/README.md) | fast lookup of addresses in huge lists of networks, and a generator of the shared CDN and provider networks |
| `tests/` | tests for all of the above, offline |

## Quick start

```bash
python3 -m unittest discover -s tests          # everything works on this machine
python3 bench/bench.py list                     # the 71 known flaws of the benchmark
python3 pcapgen/pcapgen.py attacks attacks.pcap
python3 pcapread/pcapread.py attacks.pcap --list
python3 nvdmatch/nvdmatch.py lookup mozilla firefox 115.0
```

## Measure a scanner in four steps

1. Start the web targets: `python3 bench/bench.py serve` (127.0.0.1 only).
2. Write the code targets and the captures to a folder: `python3 bench/bench.py prepare work/`.
3. Run your tool on each target and save its output as `results/<target>.sarif` (or `.json`). The targets are `web-vulnerable`, `web-clean`, `code-vulnerable`, `code-clean`, `traffic-attacks` and `traffic-clean`. Score only the ones your tool covers.
4. Score: `python3 bench/bench.py score results/ --baseline baseline.json`. The first time, add `--update` to save the baseline. From then on the run fails only when a flaw that used to be found is missed, or a new false alarm appears.

Every finding on a clean twin is a false alarm. That is the number most benchmarks forget, and the one users feel.

## Verified evidence in practice

Every finding carries `line` and `sink_quote`, copied character for character from the code:

```json
[{"file": "app.py", "line": 23, "sink_quote": "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"}]
```

Check them:

```bash
python3 tools/verify_quotes.py findings.json --root path/to/project
```

The tool prints `verified`, `moved` or `invented` for each finding:
- **verified**: the quote is at the line given.
- **moved**: the quote is in the file, but at another line. The tool gives the right one.
- **invented**: the quote is nowhere in the file.

It exits with code 1 when at least one quote is invented, so you can use it in CI. In Corvex an invented quote discards the finding, and a missing quote lowers it to "to verify".

Skills use the common `SKILL.md` format: a short YAML header and Markdown sections (`When to Use`, `Instructions`, `Checklist`, `Output`, `Example`). Give the text of a skill to your model together with the task.

## Why it matters

On the Corvex benchmark, the internal version of `bench/`:
- the rule-based agents find 78 of 78 known flaws, attack chains included, with zero false alarms on the clean twins
- with checklists and verified evidence, the compact model finds access-control and path-traversal flaws that it missed when asked to "find vulnerabilities"
- verification discards every wrong candidate on the clean project

## Data sources and notices

- `nvdmatch` uses the NVD CVE API 2.0. This product uses the NVD API but is not endorsed or certified by the NVD.
- `netlists/sharedcloud.py` downloads the network lists that Cloudflare, Fastly, AWS, Google and GitHub publish for this use. Check each provider's terms before redistributing the lists it builds.
- The benchmark targets and the captures contain only fake data, documentation addresses (RFC 5737, RFC 3849) and `.example` names. The web targets are deliberately vulnerable: never expose them to a network.

## License

Apache 2.0, see `LICENSE`. Copyright 2026 Corvex.
