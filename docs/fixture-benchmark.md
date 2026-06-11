# Aletheia Sentinel - Fixture Benchmark (regression aid)

> **Methodology disclosure**: numbers in this report come from **mocked tool
> execution** against fixture cases, not from a running SIFT Workstation with
> real evidence files. See the Methodology section below for full details.
> Real-evidence validation results live in
> [accuracy-report.md](accuracy-report.md).

---

## Run Metadata

| Field | Value |
|-------|-------|
| Date | 2026-06-11 |
| Commit | 2b8b2ea |
| Model | N/A (mocked -- no LLM calls) |
| Total cases | 3 |
| Total sessions | 3 |

---

## Per-Case Results

| Case ID | Description | Precision | Recall | F1 | Matched | Missed | Spurious | Wall (s) |
|---------|-------------|-----------|--------|-----|---------|--------|----------|----------|
| fixture-001-credential-theft | Credential theft scenario: mimikatz.exe detected a... | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 | 0.000 |
| fixture-002-lateral-movement | Lateral movement scenario: attacker used PsExec to... | 1.00 | 0.67 | 0.80 | 2 | 1 | 0 | 0.000 |
| fixture-003-persistence-empire | Persistence mechanism scenario: PowerShell-Empire ... | 1.00 | 0.33 | 0.50 | 1 | 2 | 0 | 0.000 |

---

## Aggregate Metrics

| Metric | Value |
|--------|-------|
| Mean Precision | 1.000 |
| Mean Recall | 0.667 |
| Mean F1 | 0.767 |
| Average iterations per case | 2.0 |
| Average wall time per case (s) | 0.000 |
| Total receipts emitted | 6 |

---

## Spectral Gate Summary

| Classification | Count | Percentage |
|----------------|-------|------------|
| HEALTHY | N/A | N/A |
| CAUTION | N/A | N/A |
| STRESSED (findings rejected) | N/A | N/A |

The spectral gate is bypassed in mocked benchmark runs.
In production, STRESSED findings are rejected and re-investigated.

---

## Session Breakdown

| Case ID | Stop Reason | Iterations | Accepted | Rejected | Receipts |
|---------|-------------|------------|----------|----------|----------|
| fixture-001-credential-theft | SCOUT_DONE | 3 | 3 | 0 | 3 |
| fixture-002-lateral-movement | SCOUT_DONE | 2 | 2 | 0 | 2 |
| fixture-003-persistence-empire | SCOUT_DONE | 1 | 1 | 0 | 1 |

---

## Methodology

**IMPORTANT: these numbers come from mocked tool execution against fixture
cases, not from real SIFT evidence. This is disclosed prominently because
honest measurement is itself a differentiator for hackathon criterion #2.**

### What was measured

Each benchmark case defines a list of `ExpectedFinding` objects (ground truth).
The `_CannedOrchestrator` in `scripts/generate_accuracy_report.py` returns
pre-built `ToolResult` objects for each case without calling any real agent,
SIFT tool, or LLM. Precision/recall/F1 are computed by `compute_score()`
in `sentinel.benchmark.scoring` using substring matching on payload fields.

Canned result mix (intentional for a realistic spread):

- **Case 1** (credential theft): all 3 expected findings returned -> P=1.00, R=1.00
- **Case 2** (lateral movement): 2 of 3 expected findings returned -> R=0.67
- **Case 3** (persistence-empire): 1 of 3 expected findings returned -> R=0.33

### What real measurement requires

1. A running SANS SIFT Workstation with Volatility 3, RegRipper, Plaso,
   and EvtxECmd installed.
2. Actual memory images, disk images, and event logs for each scenario.
3. `ANTHROPIC_API_KEY` and `ALETHEIA_RECEIPT_SECRET` in the environment.
4. Running: `sentinel benchmark --cases benchmark/fixtures/cases.json`

Real measurement has been performed against three SANS SRL-2018 memory
images; see [accuracy-report.md](accuracy-report.md) for those results.
The ground-truth evidence files are not committed to git (enforced by .gitignore).

### What is architectural (structural guarantees)

- **Receipt chain integrity**: cryptographic HMAC guarantee, not a prompt.
- **Termination caps**: code-level `max_iterations`, `max_wall_seconds`,
  `max_consecutive_stressed`. No prompt can override them.
- **Spectral gate thresholds**: constants in `gate.py`, not in any prompt.
- **No shell surface**: MCP server exposes only typed Python functions.

### What is prompt-based (LLM-dependent)

- Scout tool selection quality
- Nitpicker consistency judgements
- Judge report quality
- F1 accuracy on real evidence (requires real SIFT environment)
