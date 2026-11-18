---
name: corvex-agent-benchmark
description: Measure a security scanner or AI auditor honestly with paired targets (same app vulnerable and fixed), a list of expected findings, a false-alarm count and a regression baseline. Written for small models such as corvexai and for the people who test them.
subdomain: vulnerability-management
tags: [benchmark, evaluation, false-positives, regression, quality, corvex]
nist_csf: [ID.IM-01]
author: Corvex
license: Apache-2.0
---

# Agent benchmark (Corvex)

## When to Use
- Before changing a detection rule, a prompt or the model, to know whether the change helps or hurts.
- When someone asks "how good is the scanner": answer with measured numbers, not impressions.

## Instructions
1. Build pairs of targets: the same app twice, once with known flaws and once written correctly. The fixed twin must keep the same shape, so a rule that fires on the shape and not on the flaw is caught.
2. Write the ground truth: for each vulnerable target, the findings it really contains (agent, rule, exact location). Write it from the code, not from what the scanner finds today.
3. Add realistic traps to the fixed twin:
   - placeholders in `.env.example`;
   - test passwords in test files;
   - MD5 marked `usedforsecurity=False`;
   - words like `eval` inside comments;
   - commands with fixed arguments.
4. Run offline, with fixed inputs, so two runs give the same result.
5. Report per agent: findings found out of expected, false alarms on the fixed twins, missed findings, and uncatalogued results to review.
6. Keep an accepted baseline. Fail only on regressions: a finding that was found and is now missed, or a new false alarm. Update the baseline only after reviewing the differences.

## Checklist
- Never tune the ground truth to the scanner's output. A missed flaw stays in the list as a miss.
- Every false alarm found is a bug to fix in the rule, not in the benchmark.
- A "clean" target can hide a real flaw: when the scanner finds one, fix the target and record it.
- For AI auditors, run the real model one at a time, with the engine stopped at the end, and report memory and time too.

## Output
```text
agent      found  false alarms
CIPHER       6/6             0
PAYLOAD    11/11             0
TOTAL      72/72             0   · 100% of known flaws found
```

## Example
In the Corvex benchmark the first run showed 71/72 and 3 false alarms:
- `Math.random()` for an invite code with an Italian variable name was missed;
- `eval` in a docstring, MD5 used as a cache key and a test password were flagged.

After fixing the four rules the benchmark showed 72/72 and 0 false alarms, and that became the new baseline.
