# Security Scan Results

**Date:** 2026-05-23
**Branch:** claude/aletheia-hardening-sprint-z51af
**Bandit version:** 1.9.4 (Python 3.11.15)
**Semgrep version:** 1.163.0

---

## Bandit

### Count by severity

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 0     |
| LOW      | 2     |

### Finding table

| # | Test ID | Severity | File | Line | Finding | Disposition |
|---|---------|----------|------|------|---------|-------------|
| 1 | B101 | LOW | `src/sentinel/agents/orchestrator.py` | 243 | Use of `assert` detected | **Accepted** — see rationale below |
| 2 | B311 | LOW | `src/sentinel/cli.py` | 292 | Standard pseudo-random generator | **Accepted** — see rationale below |

### Rationale for accepted LOW findings

**B101 (assert_used) — orchestrator.py:243**

```python
# stop_reason is guaranteed non-None by the loop's exit condition
assert stop_reason is not None
```

This assert is a type-narrowing hint for the static type checker, backed by
a code comment explaining the invariant.  `stop_reason` is set in every
branch of the orchestrator loop before it exits; the assert narrows its type
from `StopReason | None` to `StopReason` so `mypy` can verify downstream
usage.  It is not a security boundary check and does not protect any
externally controllable path.  Removing it would require a different
type-narrowing pattern (e.g., `if stop_reason is None: raise RuntimeError`)
that would be more verbose with no safety improvement.

**B311 (pseudo-random generator) — cli.py:292**

```python
rng = random.Random(seed)
```

This appears in `_run_demo()`, the scripted demonstration subcommand.  The
seed is user-supplied (`sentinel demo --seed 42`) and the RNG is used solely
to generate reproducible demo output (timestamps, finding summaries, receipt
identifiers).  No security decisions, authentication tokens, or HMAC keys
are derived from this RNG.  The audit chain's HMAC key is provided separately
via `ALETHEIA_RECEIPT_SECRET`.  Using `random.Random` here is intentional:
the demo must be deterministic given a seed so reviewers can reproduce the
exact output.

### Notes on expected findings NOT present

The task brief anticipated possible findings for B404 (subprocess import),
B603 (subprocess without shell=True), and SHA-256 usage.  None of these
appeared in the Bandit report.  Likely reasons:

- **B404**: Bandit flags B404 when subprocess is called with `subprocess.call`
  or similar at the module level; the project's `_subprocess.py` wrapper
  uses `asyncio.create_subprocess_exec` which Bandit does not associate with
  B404/B603 in its current rule set.
- **SHA-256**: Bandit's B324 (hashlib weak hash) does not flag SHA-256 —
  only MD5 and SHA-1 are flagged as insecure by default.

---

## Semgrep

### Count by severity

| Severity | Count |
|----------|-------|
| ERROR    | 0     |
| WARNING  | 0     |
| INFO     | 0     |

**0 findings across 290 rules on 23 files.**

No findings require disposition.

---

## CI Security-Scan Job

The `security-scan` job added to `.github/workflows/ci.yml` runs:

1. `bandit -r src/ --severity-level high` — fails only on HIGH findings
   (the two LOW findings above pass through without failing CI).
2. `semgrep --config=auto src/ --error` — fails on any finding at any severity.

**Confirmed:** both commands exit 0 on the current branch.

```
bandit -r src/ --severity-level high  -> exit 0  (No issues identified.)
semgrep --config=auto src/ --error    -> exit 0  (0 findings across 290 rules.)
```
