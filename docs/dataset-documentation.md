# Dataset Documentation

## Source

**SANS SRL-2018 dataset** -- a multi-host enterprise breach scenario published by SANS
for digital-forensics training, used here as real case data for the Find Evil!
hackathon. Evidence was obtained from the official hackathon starter resources.

## Obtaining the evidence

Images are distributed via the SANS Find Evil! hackathon starter resources (registration
required). The two validated images are `base-rd01-memory` and `base-wkstn-05-memory`.
Download the starter archive, extract the `.7z`/`.zip`, then pass the image to the agent:

```
sentinel run <case> --image <path>/base-rd01-memory.img
sentinel run <case> --image <path>/base-wkstn-05-memory.img
```

Evidence images are gitignored and not committed to this repository; only the HMAC-verified
receipt chains in `submission-logs/` are committed.

The full SRL-2018 dataset contains additional images (e.g. `base-wkstn-01-memory`, DC,
file server) that are available as inventory but were not validated in this submission.

## Hosts validated

| Field | rd01 | wkstn-05 |
|-------|------|----------|
| Host IP | 172.16.6.11 | 172.16.7.15 |
| OS | Windows 10 x64 | Windows 10 x64 |
| Evidence | Physical memory capture | Physical memory capture |
| Image file | `base-rd01-memory.img` | `base-wkstn-05-memory.img` |
| Role | Lateral-movement pivot | DLL-beacon host |
| Receipts | 3 receipts (pslist, cmdline, netscan) | 4 receipts (pslist, netscan, cmdline x2) |

Evidence images are **not** committed to this repository (enforced by `.gitignore`).

## Acquisition / chain of custody

Images ship with their original dc3dd acquisition logs. rd01 example:

```
dc3dd 7.2.641 started at 2018-09-06 19:42:33 +0000
command line: dc3dd if=/mnt/mhill/base-rd01/pmem/pmem
              of=./base-rd01-memory.img hash=md5 hlog=./base-rd01-memory.md5
input MD5: a3f2e1d94c8b7065fa1293847e5c0d22
dc3dd completed at 2018-09-06 19:43:30 +0000
```

For each image, the MD5 after Sentinel's analysis was identical to the acquisition
hash, confirming the read-only pipeline did not alter the evidence.

## What the agent found

### rd01 (lateral pivot)

- WMI-spawned PowerShell chain: WmiPrvSE -> powershell -> 32-bit powershell -> cmd ->
  `p.exe`.
- **The implant: `p.exe` at `c:\windows\temp\perfmon\p.exe`** -- dispatcher spawning
  rundll32 children over a multi-day window.
- ESTABLISHED beaconing to the shared C2 172.16.4.10:8080.
- Active lateral SMB to 172.16.4.5 and 172.16.7.15; RDP attempts; inbound SMB.

### wkstn-05 (DLL-beacon host)

- WMI-spawned PowerShell chain (WmiPrvSE PID 2676 -> powershell -> PID 1332)
  repeatedly launching short-lived `rundll32.exe` children -- Cobalt Strike/Empire-style
  DLL payload loading.
- Multiple sessions to the shared C2 172.16.4.10:8080 (HTTP beacon).
- **Inbound SMB on port 445 from 172.16.6.11 (rd01)** -- proves rd01 -> wkstn-05 lateral
  movement.
- Outbound WinRM to 172.16.5.21.
- `subject_srv.ex` (PID 3548) present on TCP 3262 -> 172.16.5.50 -- F-Response forensic
  tooling, confirmed false positive, consistent with accuracy report Section 2.

### Campaign linkage

Both validated hosts share the C2 (172.16.4.10:8080) and transit 172.16.5.x. The inbound
SMB from rd01's IP to wkstn-05 gives a directional lateral-movement edge -- one coordinated
intrusion across multiple systems and multiple attack techniques.

All findings were independently verified against raw Volatility 3 output (see
[accuracy report](accuracy-report.md)).

## Reproducibility

Tools executed: `volatility.pslist` (with psscan fallback), `volatility.netscan`, and
`volatility.cmdline` via Volatility 3. rd01 produced a 3-receipt HMAC-verified audit chain
(pslist, cmdline, netscan); wkstn-05 produced a 4-receipt chain (pslist, netscan, cmdline,
cmdline). Verifiable chains are committed to `submission-logs/`. Images are available
through the SANS SRL-2018 hackathon starter resources; install Volatility 3
(`pip install volatility3`) and run `sentinel run <case> --image <image>.img`.

The live demo-video run is committed as `submission-logs/srl2018-rd01-live-1781580663.jsonl`
and can be independently verified (see "Verify the demo run" in
[accuracy-report.md](accuracy-report.md)).
