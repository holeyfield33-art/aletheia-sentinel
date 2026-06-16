# Submission Evidence Logs

Receipt chains from real SANS SRL-2018 memory-image runs. Each chain is an
HMAC-SHA256, hash-linked record of the tool executions behind the agent's report:
every finding traces to a signed receipt, and altering any receipt breaks verification.

## Verify

    export ALETHEIA_RECEIPT_SECRET=160664d44230c35db3e3f723520fa0bcdb1783439781aab99714776ede42b2f5
    sentinel verify submission-logs/srl2018-rd01-1781477951.jsonl
    sentinel verify submission-logs/srl2018-wkstn05-1781478098.jsonl

Expected:

    Chain valid: 3 receipts spanning 30.649s
    Chain valid: 4 receipts spanning 54.625s

Verifying with any other secret returns `HMAC signature invalid` (tamper-evidence).

## Chains

| Chain | Host | Receipts | Tools |
|-------|------|----------|-------|
| srl2018-rd01-1781477951.jsonl | rd01 (172.16.6.11) | 3 | pslist -> cmdline -> netscan |
| srl2018-wkstn05-1781478098.jsonl | wkstn-05 (172.16.7.15) | 4 | pslist -> netscan -> cmdline x2 |

- rd01 -- evidenced compromise (p.exe implant, WMI->PowerShell->cmd.exe launch chain, C2 172.16.4.10:8080); subject_srv.exe identified as F-Response and excluded from the verdict.
- wkstn-05 -- same campaign; subject_srv held "suspicious pending verification" where its command line was paged out.

See [../docs/accuracy-report.md](../docs/accuracy-report.md) for the full write-up.

## rd01-live (live agent run, June 15 2026)

Full autonomous `sentinel run` against the real SRL-2018 rd01 memory image
(`base-rd01-memory.img`). Three receipts: volatility.pslist, volatility.cmdline,
volatility.netscan. This is the run shown in the demo video.

Verify:

    export ALETHEIA_RECEIPT_SECRET=2f95697099e2b698b591a5557012e81f273722cad98c8cfd9a3fed0cbe8ae92c
    sentinel verify submission-logs/srl2018-rd01-live-1781580663.jsonl

Expected: `Chain valid: 3 receipts`. Findings: p.exe implant staged in
c:\windows\temp\perfmon via WMI->PowerShell->cmd.exe; C2 to 172.16.4.10:8080;
subject_srv.exe correctly identified as F-Response DFIR tooling and excluded
from the verdict.
