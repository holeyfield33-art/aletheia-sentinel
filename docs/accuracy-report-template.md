# Aletheia Sentinel - Accuracy Report

> **Template**: replace all `<PLACEHOLDER>` fields with measured values from
> a real benchmark run: `sentinel benchmark --cases benchmark/fixtures/cases.json --output report.md`

---

## Run Metadata

| Field | Value |
|-------|-------|
| Date | `<YYYY-MM-DD>` |
| Commit | `<git-sha>` |
| Model | `<claude-opus-4-X>` |
| Total cases | `<N>` |
| Total sessions | `<N>` |

---

## Per-Case Results

| Case ID | Description | Precision | Recall | F1 | Matched | Missed | Spurious | Wall (s) |
|---------|-------------|-----------|--------|-----|---------|--------|----------|----------|
| fixture-001-credential-theft | Mimikatz credential theft | `<P>` | `<R>` | `<F1>` | `<N>` | `<N>` | `<N>` | `<t>` |
| fixture-002-lateral-movement | PsExec lateral movement | `<P>` | `<R>` | `<F1>` | `<N>` | `<N>` | `<N>` | `<t>` |
| fixture-003-persistence-empire | PowerShell-Empire persistence | `<P>` | `<R>` | `<F1>` | `<N>` | `<N>` | `<N>` | `<t>` |

---

## Aggregate Metrics

| Metric | Value |
|--------|-------|
| Mean Precision | `<0.xx>` |
| Mean Recall | `<0.xx>` |
| Mean F1 | `<0.xx>` |
| Average iterations per case | `<N.N>` |
| Average wall time per case (s) | `<N.N>` |
| Total receipts emitted | `<N>` |

---

## Spectral Gate Summary

| Classification | Count | Percentage |
|----------------|-------|------------|
| HEALTHY | `<N>` | `<N>%` |
| CAUTION | `<N>` | `<N>%` |
| STRESSED (findings rejected) | `<N>` | `<N>%` |

STRESSED findings trigger re-investigation; sessions abort after
`max_consecutive_stressed` (default: 3) consecutive STRESSED results.
CAUTION is returned when the spectral gate is unreachable (network
degraded mode) -- these are excluded from the STRESSED count.

---

## Session Breakdown

| Case ID | Stop Reason | Iterations | Accepted Findings | Rejected Findings | Receipts |
|---------|-------------|------------|-------------------|-------------------|----------|
| fixture-001 | `<SCOUT_DONE\|MAX_ITERATIONS\|MAX_STRESSED\|WALL_TIMEOUT>` | `<N>` | `<N>` | `<N>` | `<N>` |
| fixture-002 | `<stop_reason>` | `<N>` | `<N>` | `<N>` | `<N>` |
| fixture-003 | `<stop_reason>` | `<N>` | `<N>` | `<N>` | `<N>` |

---

## Known Limitations

This section maps honestly to hackathon criterion #4 (transparency about
what is architectural vs. prompt-based).

### What is architectural (structural guarantees):

- **Receipt chain integrity**: Every tool call is HMAC-signed and hash-linked.
  `ReceiptChain.verify()` will raise `ChainIntegrityError` if any receipt has
  been tampered with. This is a cryptographic guarantee, not a prompt.

- **Termination caps**: The orchestrator enforces `max_iterations`,
  `max_consecutive_stressed`, and `max_wall_seconds` as hard code-level caps.
  No prompt can override them; the loop physically cannot run past these limits.

- **Spectral gate thresholds**: HEALTHY >= 0.55, CAUTION >= 0.40, STRESSED < 0.40.
  These are constants in `gate.py`, not in any prompt. The gate makes the
  decision; the LLM does not vote on it.

- **No shell surface**: The MCP server exposes only typed Python functions.
  There is no `exec_shell` tool. Destructive commands do not exist in the
  tool surface. This is enforced by the server implementation.

- **Typed tool inputs**: All tool arguments pass through Pydantic validation
  before any subprocess runs. Invalid inputs are rejected at the boundary.

### What is prompt-based (LLM-dependent, less guaranteed):

- **Scout tool selection quality**: Which tool to call next, and with what
  arguments, depends entirely on the Scout LLM's reasoning. A Scout that
  hallucinates a tool name or nonsensical arguments will waste iterations.
  The iteration cap is the backstop.

- **Nitpicker consistency judgements**: Whether a finding is "consistent with
  existing evidence" is a semantic judgement made by the Nitpicker LLM. The
  spectral gate adds a second opinion on the *quality* of the reasoning, but
  cannot guarantee the Nitpicker will catch every real inconsistency.

- **Judge report quality**: The final report is a free-form LLM synthesis.
  Section headings are required by the system prompt, but their content is
  not validated for accuracy. Caveats about rejected findings are mentioned
  by prompt instruction, not enforced by code.

- **F1 accuracy on real cases**: The precision/recall numbers above depend on
  the LLM's ability to extract the expected key_fields from actual evidence.
  Without real SIFT Workstation evidence and running SIFT tools, the fixture
  cases cannot produce real F1 scores. The architecture is correct; the
  measurement requires real evidence.

### What requires real evidence to validate:

The fixture cases point to hypothetical paths (`/evidence/fixture-xxx/`).
Real accuracy measurement requires:
1. A running SANS SIFT Workstation with Volatility 3, RegRipper, Plaso,
   and EvtxECmd installed.
2. Actual memory images / disk images / event logs for each scenario.
3. An `ANTHROPIC_API_KEY` and `ALETHEIA_RECEIPT_SECRET` in the environment.

The benchmark harness infrastructure is complete and ready to measure; the
ground truth evidence files are not committed to git (enforced by .gitignore).
