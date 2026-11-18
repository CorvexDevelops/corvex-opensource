# corvexai · open skills

Open skills and tools from **corvexai**, the AI behind [Corvex](https://corvex.dev), the team of security agents that tests your web platforms, code and computer.

corvexai is built to run on the customer's own machine, next to everything else. These skills come from the way Corvex makes a compact model reliable for security work: never ask it to "find all vulnerabilities", ask concrete questions and check every answer against the real code.

## What is inside

| Path | What it is |
|---|---|
| `skills/corvex-verified-evidence/` | how to report a finding with an exact, checkable quote of the code, so invented lines and invented code are caught |
| `skills/corvex-agent-benchmark/` | how to measure a scanner or an AI auditor honestly: paired targets, expected findings, false alarms, regression baseline |
| `tools/verify_quotes.py` | checks the quotes in a list of findings against the real files (Python 3, no dependencies) |

Skills use the common `SKILL.md` format: a short YAML header and Markdown sections (`When to Use`, `Instructions`, `Checklist`, `Output`, `Example`). Give the text of a skill to your model together with the task.

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

## Why it matters

On the Corvex benchmark:
- the rule-based agents find 72 of 72 known flaws with zero false alarms on the clean twins;
- with checklists and verified evidence, the compact model finds access-control and path-traversal flaws that it missed when asked to "find vulnerabilities";
- verification discards every wrong candidate on the clean project.

The benchmark method is in `skills/corvex-agent-benchmark`.

## License

Apache 2.0, see `LICENSE`. Copyright 2026 Corvex.
