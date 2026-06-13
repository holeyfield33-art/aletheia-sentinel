# Aletheia Sentinel — Accuracy Report

| Field | Value |
|-------|-------|
| Date | 2026-06-11 |
| Dataset | SANS SRL-2018 (real memory images, three hosts) |
| Tools | Volatility 3 via typed MCP wrappers |

This report covers (1) **real-evidence validation** of the full pipeline against three
hosts from the SANS SRL-2018 dataset, with independent findings verification and a
documented self-correction; (2) the **fixture benchmark** used for regression; and
(3) an honest **spectral-gate calibration study**. Real-evidence results are primary.

---

## 1. Real-Evidence Validation (SANS SRL-2018, three hosts)

The full Scout -> Nitpicker -> Judge pipeline was run end-to-end against three real
memory images. All runs completed cleanly (`stop_reason=scout_done`) and wrote verified
receipt chains.

| | wkstn-01 | rd01 | wkstn-05 |
|---|---|---|---|
| Host IP | 172.16.7.11 | 172.16.6.11 | 172.16.7.15 |
| OS | Windows 10 x64 | Windows 10 x64 | Windows 10 x64 |
| Role | Initial alert host | Lateral pivot | DLL-beacon host |
| Receipts | 2, chain valid | 2, chain valid | 2, chain valid |
| Tools | pslist (psscan fallback), netscan | pslist, netscan | pslist, netscan |

### The three-host campaign

The hosts are linked by shared attacker infrastructure and directional lateral
movement, establishing a coordinated campaign rather than isolated compromises:

- **Shared C2 across all three hosts:** every host maintains sessions to
  `172.16.4.10:8080` -- a single HTTP C2 beacon endpoint spanning the campaign.
- **Proven directional lateral movement:** wkstn-05 shows an inbound SMB session on
  port 445 from `172.16.6.11` -- **that is rd01's IP.** rd01 reached wkstn-05 directly;
  the movement edge is evidence-backed (netscan), not inferred.
- **Shared infrastructure:** rd01 and wkstn-05 both transit `172.16.5.x`
  (WinRM to 172.16.5.21; subject_srv sessions to 172.16.5.50).
- **Multiple attack techniques observed:** rd01 ran a `p.exe` implant via
  WMI->PowerShell; wkstn-05 ran a WMI->PowerShell->`rundll32` chain (Cobalt
  Strike/Empire-style DLL payload loading). The pipeline surfaced both -- evidence the
  typed tools and the agent loop handle more than one technique, validated per host.

### Findings verification -- independent spot-check (wkstn-01)

Every specific claim in the autonomously generated wkstn-01 report was independently
re-derived from raw Volatility 3 output. **All traced to real evidence.**

| Report claim | Verification against raw output |
|--------------|----------------------------------|
| `subject_srv.exe` (PID 12528), services.exe parent, WoW64 | Confirmed: pslist PID 12528, PPID 740, wow64=true |
| TCP 3262 listener | Confirmed: netscan LISTENING, owner subject_srv.ex |
| ESTABLISHED session 172.16.5.50:56722 | Confirmed: netscan, state ESTABLISHED |
| WinRM (5985) to 172.16.5.21 | Confirmed: netscan, multiple sessions |
| Persistence chain cmd.exe (5024) -> sc.exe (3068) | Confirmed: pslist, 17:15:26 -> 17:15:31 |
| Recon tooling sd.exe (5588), Autorunsc.exe (9048) | Confirmed: pslist, stated PIDs/times |

The rd01 and wkstn-05 findings (WMI->PowerShell chains, shared C2, lateral SMB) were
likewise confirmed against raw cmdline/pslist/netscan output.

### Real-world parsing failures found and fixed

Validation surfaced two parser failures invisible to fixture tests; both fixed and
regression-tested:

- **pslist returned zero processes** on wkstn-01. The tool now falls back to
  `windows.psscan` (also surfaces hidden processes), recording the source in the audit
  trail (`src/sentinel/tools/volatility_pslist.py`).
- **Volatility 3 `-r json` emits `Offset(V)` as an integer**, not a string. Typed
  models now normalize int offsets to hex. Before the fix, all processes were silently
  rejected by validation.

The third host (wkstn-05) ran cleanly with **no new parser failures** -- pslist and
netscan both parsed and produced a verified 2-receipt chain on a previously-unseen
image, evidence the typed tools generalize. (An earlier field-alias gap between the
documented Volatility 3 JSON schema and the typed models is recorded in
[real-evidence-validation.md](real-evidence-validation.md).)

---

## 2. Self-Correction: subject_srv.exe False Positive

The clearest demonstration of evidence-grounded discipline in this submission.

**The flag.** On wkstn-01, `subject_srv.exe` (PID 12528) was flagged as a suspected
backdoor -- name, `services.exe` parent, TCP 3262 listener, and external session all
read as suspicious. On wkstn-01's capture, `windows.cmdline`, `windows.dlllist`, and
`windows.handles` returned empty for this PID (internals paged out), so it could not be
classified from that host alone.

**The correction.** On rd01 -- where the same binary ran (PID 1096) and internals were
recoverable -- command-line analysis resolved it:

```
subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"
```

`subject_srv.exe` is **F-Response**, a legitimate commercial remote-forensics tool
deployed by the IR team. The finding was **corrected from suspected-backdoor to
informational.**

**Resolves where the evidence is present; cautious where it is not.** On rd01, where
`subject_srv.exe`'s own network activity reveals F-Response infrastructure
(`base-hunt.shieldbase.lan:5682`, the F-Response hunt server) and the command line is
recoverable, the agent identifies it as legitimate tooling. On wkstn-01 and wkstn-05 --
where that 5682 connection is absent from the image and the command-line memory is paged
out -- the identifying evidence is simply not present, so the agent holds `subject_srv`
as "suspicious pending verification" rather than asserting either malice or innocence.
The recurrence across three hosts shows the trap is systematic -- a legitimately-deployed
forensic tool that pattern-matches as malicious -- and that the verdict must track the
evidence available on each host: command-line or network correlation resolves it where
present, honest caution covers it where absent. This is evidence-bounded classification,
not a claim that the correction generalizes unconditionally across hosts.

**Why this matters.** A real false positive caught by deeper evidence: classification
must be evidence-bounded, multi-host correlation resolves what a single paged-out
capture cannot, and the analyst's job is to distinguish the IR team's own tooling from
the actual implant.

**Real malicious findings preserved (not softened):**

- `p.exe` at `c:\windows\temp\perfmon\p.exe` (rd01) -- implant/dispatcher spawning rundll32 children
- WMI->PowerShell->rundll32 beacon chains on rd01 and wkstn-05 (Cobalt Strike/Empire-style)
- Shared C2 `172.16.4.10:8080` across all three hosts; lateral SMB/RDP/WinRM

Hosts remain compromised -- by the implants and the C2, **not** by subject_srv.

---

## 3. Evidence Integrity (Spoliation)

The pipeline is read-only. Source image MD5s were identical before and after analysis,
matching the original dc3dd acquisition logs shipped with the dataset. Evidence paths
are pinned server-side, so the agent cannot redirect a tool at an arbitrary file --
confirmed on all three runs (`Evidence image: ... (pinned)` in the run logs;
pinning is wired in `src/sentinel/agents/wiring.py`).

---

## 4. Receipt Chain Integrity -- current and roadmap

**Current:** every tool execution writes an HMAC-signed, hash-linked receipt (SHA-256
of input and output, chained via `prev_digest`). Tamper-evident -- altering any receipt
breaks verification. All three runs verified valid (genesis -> pslist -> netscan, each
linked and signed). This is a cryptographic guarantee enforced in code
(`src/sentinel/audit/receipts.py`), not a prompt.

**Known limitation:** HMAC is a shared-secret scheme -- verification requires the
signing secret, so a third party cannot independently verify without it.

**Roadmap -- Ed25519 public-key receipts:** asymmetric signing would let anyone verify
the chain against a published public key with no shared secret, strengthening
chain-of-custody for adversarial/legal contexts. The Ed25519 primitive already exists in
the companion `aletheia-cyber-core` package.

**Roadmap -- deterministic canonical hashing:** routing receipt content through a
canonical serializer before hashing would make digests reproducible across machines.

---

## 5. Spectral Confidence Calibration Study

The spectral gate was evaluated as a potential coherence/hallucination signal across
four models (gpt2-large, pythia-1.4b, pythia-2.8b, and smaller).

| Statistic | Result |
|-----------|--------|
| Spacing ratio (r) | Does not separate classes (AUROC ~0.5-0.7, no scale trend) |
| Effective rank | Weak separation (AUROC ~0.7, high overlap) |
| Participation ratio | Weak separation (AUROC ~0.7) |

**Conclusion:** no spectral statistic reliably separated coherent from degenerate
generation at the tested scales. The spectral gate is therefore treated as an
**advisory confidence signal**: it annotates findings with a confidence reading
rather than serving as a hallucination detector. The orchestrator retains a
deterministic STRESSED -> reject-and-reinvestigate guard
(`src/sentinel/agents/orchestrator.py`) as defense-in-depth, but in practice live
gate calls return CAUTION -- text-proxy r-ratios cluster at 0.41-0.43 for English
prose regardless of content, and service errors degrade gracefully to CAUTION -- so
the gate does not decide acceptance on real runs. The reliable self-correction path
is the Scout's evidence-based identity-verification rule together with the Judge's
evidence-bounded synthesis (Sections 1-2); the Nitpicker is a consistency reviewer, not
an evidence-grounding gate. This negative result is reported deliberately rather than
overclaiming a detector the data does not support.

> Note: the gate calls the companion Geometric Brain service, which returns a 307
> redirect (`/mcp` -> `/mcp/`). The gate handles this gracefully (returns CAUTION and
> continues) -- visible as a benign WARNING in run logs. It does not affect findings.

---

## 6. Fixture Benchmark (regression aid)

Mocked tool execution against 3 fixture cases with known ground truth. For regression of
the matching logic; not a substitute for the real-evidence results. Full breakdown and
methodology disclosure: [fixture-benchmark.md](fixture-benchmark.md), regenerated by
`scripts/generate_accuracy_report.py`.

| Metric | Value |
|--------|-------|
| Mean Precision | 1.000 |
| Mean Recall | 0.667 |
| Mean F1 | 0.767 |

---

## Reproducibility

- Quality bar at time of writing: `ruff check src tests` clean, `mypy` clean
  (strict mode, 39 source files), `pytest` green (133 tests).
- Real-evidence runs: install Volatility 3 (`pip install volatility3`), set
  `ALETHEIA_RECEIPT_SECRET` and `ANTHROPIC_API_KEY`, then
  `sentinel run <case> --image <image>.img` and
  `sentinel verify audit-logs/<chain>.jsonl`.
- Dataset provenance and per-host findings:
  [dataset-documentation.md](dataset-documentation.md).
