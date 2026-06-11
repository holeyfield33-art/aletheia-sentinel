# Dataset Documentation

## Source

**SANS SRL-2018 dataset** -- a multi-host enterprise breach scenario published by SANS
for digital-forensics training, used here as real case data for the Find Evil!
hackathon. Evidence was obtained from the official hackathon starter resources.

## Hosts analyzed

Three memory images from the same intrusion were analyzed, establishing a multi-host
campaign linked by a shared C2 and directional lateral movement.

| Field | wkstn-01 | rd01 | wkstn-05 |
|-------|----------|------|----------|
| Host IP | 172.16.7.11 | 172.16.6.11 | 172.16.7.15 |
| OS | Windows 10 x64 | Windows 10 x64 | Windows 10 x64 |
| Evidence | Physical memory capture | Physical memory capture | Physical memory capture |
| Image file | `base-wkstn-01-memory.img` | `base-rd01-memory.img` | `base-wkstn-05-memory.img` |
| Role | Initial alert host | Lateral-movement pivot | DLL-beacon host |

Evidence images are **not** committed to this repository (enforced by `.gitignore`).

## Acquisition / chain of custody

Images ship with their original dc3dd acquisition logs. wkstn-01 example:

```
dc3dd 7.2.641 started at 2018-09-06 19:42:33 +0000
command line: dc3dd if=/mnt/mhill/base-wkstn-01/pmem/pmem
              of=./base-wkstn-01-memory.img hash=md5 hlog=./base-wkstn-01-memory.md5
input MD5: 7586e0cd75e9c6a5ea97c3c74ebf391b
dc3dd completed at 2018-09-06 19:43:30 +0000
```

For each image, the MD5 after Sentinel's analysis was identical to the acquisition
hash, confirming the read-only pipeline did not alter the evidence.

## What the agent found

### wkstn-01 (initial alert host)

- Service binary `subject_srv.exe` (PID 12528) under `services.exe`, listening on
  TCP 3262 with an ESTABLISHED session to 172.16.5.50. Initially flagged suspicious;
  **later identified as F-Response forensic tooling** via rd01 cmdline analysis (see
  [accuracy report](accuracy-report.md), Section 2).
- Persistence chain: cmd.exe -> sc.exe (17:15:26 -> 17:15:31).
- Outbound to C2 172.16.4.10:8080; WinRM lateral movement to 172.16.5.21.

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
- `subject_srv.ex` (PID 3548) again present on TCP 3262 -> 172.16.5.50 -- the same
  F-Response false-positive trap, reinforcing the self-correction
  ([accuracy report](accuracy-report.md), Section 2).

### Campaign linkage

All three hosts share the C2 (172.16.4.10:8080) and transit 172.16.5.x. The inbound SMB
from rd01's IP to wkstn-05 gives a directional lateral-movement edge -- one coordinated
intrusion across multiple systems and multiple attack techniques.

All findings were independently verified against raw Volatility 3 output (see
[accuracy report](accuracy-report.md)).

## Reproducibility

Tools executed: `volatility.pslist` (with psscan fallback) and `volatility.netscan` via
Volatility 3. Each run produced a 2-receipt, HMAC-verified audit chain. Images are
available through the SANS SRL-2018 starter resources; install Volatility 3
(`pip install volatility3`) and run `sentinel run <case> --image <image>.img`.
