# Aletheia Sentinel — Accuracy Report

| Field | Value |
|-------|-------|
| Date | 2026-06-14 |
| Dataset | SANS SRL-2018 (real memory images) |
| Tools | Volatility 3 (`pslist`, `netscan`, `cmdline`) via typed MCP wrappers |

This report covers (1) **real-evidence validation** of the full pipeline against two
hosts from the SANS SRL-2018 dataset, with a documented evidence-bounded
classification; (2) the **fixture benchmark** used for regression; and (3) an honest
**spectral-gate calibration study**. Real-evidence results are primary.

---

## 1. Real-Evidence Validation (SANS SRL-2018)

The full Scout -> Nitpicker -> Judge pipeline was run end-to-end against real memory
images. Both runs completed cleanly (`stop_reason=scout_done`) and wrote HMAC
hash-linked receipt chains that verify.

| | rd01 | wkstn-05 |
|---|---|---|
| Host IP | 172.16.6.11 | 172.16.7.15 |
| OS | Windows 10 x64 | Windows 10 x64 |
| Role | Compromised host / lateral source | Lateral target / beacon host |
| Receipts | 3, chain valid | 4, chain valid |
| Tools run | pslist, cmdline, netscan | pslist, netscan, cmdline (x2) |
| Verdict | Compromised (HIGH) | Compromised (HIGH) |

### The campaign

The two hosts are linked by shared attacker infrastructure and a directional lateral
movement edge, establishing a coordinated campaign rather than isolated compromises:

- **Shared C2:** both hosts maintain sessions to `172.16.4.10:8080` -- a single
  internal HTTP C2/staging endpoint (ESTABLISHED and CLOSE_WAIT sockets on each host).
- **Directional lateral movement (evidence-backed):** wkstn-05 holds an ESTABLISHED
  inbound SMB session `172.16.6.11:59352 -> 172.16.7.15:445` -- and `172.16.6.11` is
  **rd01's IP**. rd01 reached wkstn-05 directly over SMB; the movement edge is netscan
  evidence, not inference.
- **Multiple techniques surfaced:** rd01 ran a staged `p.exe` implant launched through a
  WMI -> PowerShell -> `cmd.exe` chain; wkstn-05 ran a WMI -> PowerShell -> `rundll32`
  chain (Cobalt Strike / Empire-style DLL payload loading). The typed tools and the
  agent loop handled both, validated per host.

### rd01 -- evidenced compromise

The verdict is driven by evidence, stated by the Judge as "driven by evidenced
findings ... not by any unverified flag":

- Staged payload `c:\windows\temp\perfmon\p.exe` (PID 8260) executed via
  `cmd.exe /C` on 2018-08-30 22:15:18, resident through 2018-09-06, spawning multiple
  `rundll32.exe` children (PIDs 5768, 1424, 7552) -- payload-loading tradecraft.
- Launcher chain `WmiPrvSE.exe` (2876) -> `powershell.exe` (8712) -> 32-bit
  `powershell.exe` (5848, `-s -NoLogo -NoProfile`) -- WMI-triggered PowerShell staging.
- Sustained C2 to `172.16.4.10:8080`; RDP probes to `172.16.4.5:3389`; SMB to
  `172.16.7.15:445`.

### wkstn-05 -- evidenced compromise

Verdict "not dependent on the unverified subject_srv.ex listener":

- `WmiPrvSE.exe` (2676) -> multiple `powershell.exe` (3920, 4064, 4328) -> short-lived
  `rundll32.exe` burst (PIDs 5300, 5056, 4240, 1972, 3720) on 2018-08-31 -- staged
  payload loading.
- Long-lived orphaned `rundll32.exe` (PID 7100, parent gone, 337 handles) still
  resident at acquisition.
- Repeated `172.16.4.10:8080` callbacks; ESTABLISHED WinRM to `172.16.5.21:5985`.

---

## 2. Evidence-Bounded Classification: subject_srv.exe

The clearest demonstration of evidence discipline in this submission -- the agent's
verdict tracks the evidence available on each host rather than the process name.

**The trap.** `subject_srv.exe` appears on both hosts: a non-standard binary name, a
`services.exe` parent, a TCP/3262 listener, and an external session. Name-and-port
heuristics read it as a backdoor -- but it is **F-Response**, a legitimate commercial
remote-forensics tool deployed by the IR team, which the SANS SRL-2018 dataset is built
around.

**Resolved on rd01 (evidence present).** The Scout calls `volatility.cmdline` before the
Judge concludes, and on rd01 the command line is resident and recovered:

```
subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"
```

The `-v "F-Response Subject"` argument identifies it directly, and the network evidence
agrees (the process's session to `base-hunt.shieldbase.lan:5682`, the F-Response
hunt-server endpoint). The Judge classifies it as defender activity -- explicitly "not
attacker infrastructure" -- and does not let it drive the compromise verdict.

**Held pending verification on wkstn-05 (evidence absent).** The same binary runs on
wkstn-05, but `volatility.cmdline` returns empty (the process's command-line memory is
paged out) and no F-Response endpoint is in that host's network capture. With the
identifying evidence absent from the image, the Judge holds `subject_srv.ex` as
**"suspicious pending verification"** -- asserting neither malice nor innocence -- and
records the residual uncertainty in Confidence Caveats. The compromise verdict stands on
the WMI->PowerShell->rundll32 chain and the C2 callbacks instead.

**Why this matters.** Evidence-bounded classification means the verdict tracks the
evidence on each host: a recovered command line or a network correlation resolves the
process where present; honest caution covers it where absent. The discipline is split
across two agents -- the Scout must verify a flagged process's identity from evidence
before concluding, and the Judge must not report a process as malicious, or let it drive
the verdict, unless that identity is established in the findings. The Nitpicker is a
consistency reviewer, not an evidence gate.

**Real malicious findings preserved (not softened):**

- `p.exe` at `c:\windows\temp\perfmon\p.exe` (rd01) -- implant/dispatcher spawning rundll32 children
- WMI->PowerShell->rundll32 chains on both hosts (Cobalt Strike/Empire-style)
- Shared C2 `172.16.4.10:8080`; lateral SMB `172.16.6.11 -> 172.16.7.15:445`; WinRM

Both hosts remain compromised -- by the implants and the C2, **not** by subject_srv.

**Reproducibility note.** The agent's report prose varies between runs, as expected for
an LLM-driven pipeline. What does not vary is the receipt chain: the signed, ordered
record of which tools executed against which evidence. Every claim traces to a receipted
tool execution, and the chain -- not the prose -- is the verifiable artifact
(`sentinel verify <chain>`).

---

## 3. Evidence Integrity (Spoliation)

The pipeline is read-only. Source image MD5s were identical before and after analysis,
matching the original dc3dd acquisition logs shipped with the dataset. Evidence paths
are pinned server-side, so the agent cannot redirect a tool at an arbitrary file --
confirmed on both runs (`Evidence image: ... (pinned)` in the logs; pinning is wired in
`src/sentinel/agents/wiring.py`).

---

## 4. Receipt Chain Integrity -- current and roadmap

**Current:** every tool execution writes an HMAC-signed, hash-linked receipt (SHA-256 of
input and output, chained via `prev_digest`). Tamper-evident -- altering any receipt
breaks verification. Both runs verified valid. Enforced in code
(`src/sentinel/audit/receipts.py`), not a prompt.

**Known limitation:** HMAC is a shared-secret scheme -- verification requires the signing
secret, so a third party cannot independently verify without it.

**Roadmap -- Ed25519 public-key receipts:** asymmetric signing would let anyone verify
against a published public key with no shared secret. The Ed25519 primitive already
exists in the companion `aletheia-cyber-core` package.

---

## 5. Spectral Confidence Calibration Study

The spectral gate is **experimental and off by default** (enable with `--spectral`). It
was evaluated as a potential coherence signal across four models.

| Statistic | Result |
|-----------|--------|
| Spacing ratio (r) | Does not separate classes (AUROC ~0.5-0.7) |
| Effective rank | Weak separation (AUROC ~0.7) |
| Participation ratio | Weak separation (AUROC ~0.7) |

**Conclusion:** no spectral statistic reliably separated coherent from degenerate
generation at the tested scales, so the gate is treated as advisory. When enabled, live
gate calls return CAUTION in practice -- text-proxy r-ratios cluster at 0.41-0.43 for
English prose regardless of content, and service errors degrade gracefully to CAUTION --
so the gate does not decide acceptance. The reliable evidence-discipline path is the
Scout's identity-verification rule plus the Judge's evidence-bounded synthesis
(Sections 1-2). This negative result is reported deliberately rather than overclaiming a
detector the data does not support.

---

## 6. Fixture Benchmark (regression aid)

Three fixture cases with known ground truth, for regression of the matching logic; not a
substitute for the real-evidence results above. Full methodology:
[fixture-benchmark.md](fixture-benchmark.md), regenerated by
`scripts/generate_accuracy_report.py`.

| Metric | Value |
|--------|-------|
| Mean Precision | 1.000 |
| Mean Recall | 0.667 |
| Mean F1 | 0.767 |

> Note: the fixture scorer was corrected to traverse nested tool-result payloads
> (`_deep_record_matches`); regenerate this table from the corrected scorer before
> relying on the numbers.

---

## Reproducibility

- Quality bar: `ruff check src tests` clean, `mypy` clean (strict, 43 source files),
  `pytest` green (153 tests).
- Real-evidence runs: install Volatility 3, set `ALETHEIA_RECEIPT_SECRET` and
  `ANTHROPIC_API_KEY`, then `sentinel run <case> --image <image>.img` and
  `sentinel verify audit-logs/<chain>.jsonl`. Spectral gate is off by default.
- Dataset provenance: [dataset-documentation.md](dataset-documentation.md).

### Verify the demo run

The exact run shown in the demo video is committed as a verifiable receipt chain.
Anyone can confirm it was not altered:

    export ALETHEIA_RECEIPT_SECRET=2f95697099e2b698b591a5557012e81f273722cad98c8cfd9a3fed0cbe8ae92c
    sentinel verify submission-logs/srl2018-rd01-live-1781580663.jsonl

Expected output: `Chain valid: 3 receipts`. Tampering with any byte, or using the
wrong secret, yields `Chain INVALID: HMAC signature invalid`. The chain covers the
volatility.pslist -> netscan -> cmdline sequence that produced the rd01 verdict
(p.exe implant via WMI->PowerShell->cmd.exe, C2 to 172.16.4.10:8080, subject_srv.exe
cleared as F-Response tooling).
