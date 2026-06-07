"""Command-line interface for Aletheia Sentinel.

Five subcommands:
    sentinel server                   Start the FastMCP server over stdio.
    sentinel run CASE_ID              Run a full autonomous investigation session.
    sentinel benchmark --cases PATH   Run the accuracy benchmark harness.
    sentinel verify CHAIN_PATH        Verify a JSONL receipt chain on disk.
    sentinel demo [--seed N]          Run a scripted end-to-end demo investigation.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import json
import logging
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.agents.llm import ClaudeJudge, ClaudeNitpicker, ClaudeScout, make_client
from sentinel.agents.orchestrator import Orchestrator, OrchestratorConfig
from sentinel.agents.wiring import build_executor
from sentinel.audit.receipts import ChainIntegrityError, ReceiptChain, secret_from_env
from sentinel.benchmark.cases import Case, ExpectedFinding
from sentinel.benchmark.runner import OrchestratorProtocol, run_benchmark
from sentinel.benchmark.scoring import BenchmarkResult
from sentinel.spectral.gate import RemoteSpectralGate
from sentinel.tools.base import ToolResult, ToolStatus

log = logging.getLogger(__name__)

_TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "name": "volatility.pslist",
        "description": "List running processes from a memory image (Volatility 3).",
        "input_schema": {
            "type": "object",
            "properties": {
                "memory_image": {"type": "string", "description": "Path to memory image file."},
                "profile_hint": {"type": "string", "description": "Optional OS profile hint."},
            },
            "required": ["memory_image"],
        },
    },
    {
        "name": "volatility.netscan",
        "description": "Scan network connections from a memory image (Volatility 3).",
        "input_schema": {
            "type": "object",
            "properties": {
                "memory_image": {"type": "string", "description": "Path to memory image file."},
            },
            "required": ["memory_image"],
        },
    },
    {
        "name": "regripper.amcache",
        "description": "Parse Amcache.hve with RegRipper to enumerate executed programs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hive_file": {"type": "string", "description": "Path to Amcache.hve."},
            },
            "required": ["hive_file"],
        },
    },
    {
        "name": "plaso.log2timeline",
        "description": "Build a super-timeline from a disk image (slow; use last).",
        "input_schema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to disk image."},
                "output_dir": {"type": "string", "description": "Directory for output files."},
            },
            "required": ["image_path", "output_dir"],
        },
    },
    {
        "name": "evtxecmd.parse_security",
        "description": "Parse Security.evtx for authentication and privilege events.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evtx_path": {"type": "string", "description": "Path to Security.evtx file."},
                "include_event_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Event IDs to include (defaults to auth-relevant set).",
                },
            },
            "required": ["evtx_path"],
        },
    },
]


# ---------------------------------------------------------------------------
# Demo subcommand data and helpers
# ---------------------------------------------------------------------------

@dataclass
class _DemoStep:
    tool: str
    reason: str
    health: str
    r_base: float
    findings: list[dict[str, str | int]]
    is_reinvestigation: bool = False


_DEMO_STEPS: list[_DemoStep] = [
    _DemoStep(
        tool="volatility.pslist",
        reason="Enumerate active processes to identify suspicious executables in memory",
        health="HEALTHY",
        r_base=0.62,
        findings=[
            {"pid": 1234, "name": "mimikatz.exe", "ppid": 4, "state": "ACTIVE"},
            {"pid": 736, "name": "lsass.exe", "ppid": 4, "anomaly": "unexpected_child"},
            {"pid": 1056, "name": "cmd.exe", "ppid": 1234, "state": "ACTIVE"},
        ],
    ),
    _DemoStep(
        tool="volatility.netscan",
        reason="Scan network state for active C2 connections",
        health="HEALTHY",
        r_base=0.58,
        findings=[
            {
                "local_ip": "10.0.0.5",
                "local_port": 49200,
                "remote_ip": "192.168.100.5",
                "remote_port": 4444,
                "state": "ESTABLISHED",
            },
            {
                "local_ip": "10.0.0.5",
                "local_port": 49201,
                "remote_ip": "192.168.100.5",
                "remote_port": 4445,
                "state": "CLOSE_WAIT",
            },
        ],
    ),
    _DemoStep(
        tool="evtxecmd.parse_security",
        reason="Review Security.evtx for authentication and lateral movement events",
        health="STRESSED",
        r_base=0.31,
        findings=[
            {"event_id": 4624, "logon_type": 3, "username": "Administrator"},
            {"event_id": 7045, "service_name": "PSEXESVC", "path": "C:\\Windows\\PSEXESVC.exe"},
            {"event_id": 4776, "source_workstation": "COMPROMISED-WS01"},
            {"event_id": 4648, "username": "Administrator", "target": "FILE-SERVER-02"},
            {"event_id": 4624, "logon_type": 3, "username": "SYSTEM"},
        ],
    ),
    _DemoStep(
        tool="evtxecmd.parse_security",
        reason="Re-examine security events after spectral gate rejection",
        health="HEALTHY",
        r_base=0.71,
        is_reinvestigation=True,
        findings=[
            {"event_id": 4624, "logon_type": 3, "source_workstation": "COMPROMISED-WS01"},
            {"event_id": 7045, "service_name": "PSEXESVC", "path": "C:\\Windows\\PSEXESVC.exe"},
            {"event_id": 4776, "source_workstation": "COMPROMISED-WS01"},
        ],
    ),
    _DemoStep(
        tool="regripper.amcache",
        reason="Check Amcache for attacker toolkit execution artifacts",
        health="HEALTHY",
        r_base=0.65,
        findings=[
            {"name": "mimikatz.exe", "sha256": "4b3a2c1d0e9f8a7b",
             "last_run": "2026-05-15T03:41:22Z"},
            {"name": "PsExec64.exe", "path": "C:\\Temp\\PsExec64.exe",
             "last_run": "2026-05-15T03:55:00Z"},
        ],
    ),
]

_DEMO_DIVIDER = "-" * 63
_DEMO_BANNER = "=" * 63


def _demo_print_banner(label: str) -> None:
    print(_DEMO_BANNER)
    print(f" {label}")
    print(_DEMO_BANNER)


def _demo_print_divider() -> None:
    print(_DEMO_DIVIDER)


def _demo_format_finding(f: dict[str, str | int], prefix: str = "  ") -> str:
    parts = [f"{k}={v}" for k, v in f.items()]
    return prefix + "  ".join(parts)


def _demo_print_step(
    step: _DemoStep,
    iteration: int,
    r_ratio: float,
    receipt_seq: int,
    accepted: bool,
) -> None:
    reinv_tag = "  [RE-INVESTIGATION]" if step.is_reinvestigation else ""
    print(f"[SCOUT]   iteration {iteration}: plans {step.tool}{reinv_tag}")
    print(f"          reason: {step.reason}")
    print()

    n = len(step.findings)
    print(f"[TOOL]    {step.tool} -> OK  ({n} result(s), receipt #{receipt_seq})")
    show = step.findings[:2]
    for f in show:
        print(_demo_format_finding(f))
    if n > 2:
        print(f"          ({n - 2} more entries omitted)")
    print()

    if step.health == "STRESSED":
        print(f"[GATE]    spectral health: STRESSED  (r={r_ratio:.2f})")
        print("          ** Coherence below threshold 0.40 -- FINDING REJECTED **")
        print("          ** Re-investigation queued for next iteration           **")
    elif step.health == "CAUTION":
        print(f"[GATE]    spectral health: CAUTION   (r={r_ratio:.2f})")
    else:
        print(f"[GATE]    spectral health: HEALTHY   (r={r_ratio:.2f})")

    print()
    _demo_print_divider()
    print()


def _demo_generate_report(accepted: int, rejected: int, chain_len: int) -> str:
    lines = [
        "CASE: demo-case-001",
        f"STOP: SCOUT_DONE  |  ITERATIONS: {len(_DEMO_STEPS)}  "
        f"|  ACCEPTED: {accepted}  |  REJECTED: {rejected}",
        "",
        "EXECUTIVE SUMMARY",
        "-----------------",
        "A credential theft attack was detected on the monitored workstation.",
        "Mimikatz.exe (PID 1234) was found active in memory with a live C2",
        "channel to 192.168.100.5:4444 (ESTABLISHED, remote port 4444).",
        "The attacker subsequently used PsExec to pivot to FILE-SERVER-02,",
        "as evidenced by PSEXESVC service install (Event 7045) in Security.evtx.",
        "",
        "The spectral gate flagged one evtxecmd iteration as incoherent (r=0.31).",
        "That result was rejected and re-investigated; the follow-up run (r=0.71)",
        "confirmed lateral movement indicators.",
        "",
        "ATTACK TIMELINE",
        "---------------",
        "2026-05-15T03:41:22Z  mimikatz.exe executed (Amcache artifact)",
        "2026-05-15T03:41:35Z  LSASS anomalous child process observed",
        "2026-05-15T03:42:10Z  C2 connection: 10.0.0.5 -> 192.168.100.5:4444",
        "2026-05-15T03:55:00Z  PsExec lateral movement to FILE-SERVER-02",
        "2026-05-15T03:55:03Z  PSEXESVC installed on target (Event 7045)",
        "",
        f"ACCEPTED FINDINGS ({accepted})",
        "---------------------------",
        "[#0] volatility.pslist   mimikatz.exe (PID 1234) active in memory    CRITICAL",
        "[#1] volatility.netscan  C2 channel to 192.168.100.5:4444 ESTABLISHED CRITICAL",
        "[#3] evtxecmd.security   PSEXESVC service install (Event 7045)        HIGH",
        "[#3] evtxecmd.security   Type-3 logon from COMPROMISED-WS01           HIGH",
        "[#4] regripper.amcache   mimikatz.exe and PsExec64.exe in Amcache     HIGH",
        "",
        f"REJECTED FINDINGS ({rejected} -- spectral gate)",
        "----------------------------------------------",
        "[#2] evtxecmd.security   r=0.31 < threshold 0.40; re-investigated at iter 4",
        "",
        f"RECEIPT CHAIN ({chain_len} receipts)",
        "------------------------------",
        "All findings are HMAC-signed and hash-linked in an append-only chain.",
        "Run: sentinel verify <chain.jsonl>",
    ]
    return "\n".join(lines)


def _run_demo(seed: int) -> int:
    rng = random.Random(seed)

    _demo_print_banner(f"ALETHEIA SENTINEL - DEMO INVESTIGATION  (seed={seed})")
    print(" Case ID : demo-case-001")
    print(" Scenario: Credential theft + lateral movement")
    print()

    # Hex string matches what secret_from_env() returns when the user exports
    # ALETHEIA_RECEIPT_SECRET=<this value>, making sentinel verify work out of the box.
    demo_secret_hex = hashlib.sha256(f"aletheia-demo-seed-{seed}".encode()).hexdigest()
    demo_secret = demo_secret_hex.encode("ascii")
    chain = ReceiptChain(secret=demo_secret, session_id="demo-case-001")

    accepted: list[ToolResult] = []
    rejected: list[ToolResult] = []
    receipt_seq = 0

    for iteration, step in enumerate(_DEMO_STEPS, start=1):
        payload: dict[str, Any] = {"entries": step.findings}
        result = ToolResult(
            tool_name=step.tool,
            status=ToolStatus.OK,
            payload=payload,
        )

        receipt = chain.append(
            tool_name=step.tool,
            tool_input=json.dumps({"tool": step.tool}).encode("ascii"),
            tool_output=result.to_canonical_bytes(),
        )
        result_with_seq = result.with_receipt(receipt.sequence)
        receipt_seq = receipt.sequence

        r_ratio = step.r_base + rng.uniform(-0.02, 0.02)
        is_accepted = step.health != "STRESSED"

        _demo_print_step(
            step=step,
            iteration=iteration,
            r_ratio=r_ratio,
            receipt_seq=receipt_seq,
            accepted=is_accepted,
        )

        if is_accepted:
            accepted.append(result_with_seq)
        else:
            rejected.append(result_with_seq)

    print("[SCOUT]   Investigation complete: all high-priority evidence sources examined.")
    print()

    _demo_print_banner("[JUDGE]   Final Report  (first 30 lines)")
    print()

    report = _demo_generate_report(
        accepted=len(accepted),
        rejected=len(rejected),
        chain_len=chain.length,
    )
    report_lines = report.splitlines()
    for line in report_lines[:30]:
        print(line)
    if len(report_lines) > 30:
        print(f"... ({len(report_lines) - 30} more lines omitted)")
    print()

    _demo_print_banner("[CHAIN]   Receipt Chain Summary")
    chain.verify()
    receipts = chain.receipts()
    n = chain.length
    if n > 0:
        first_ts = receipts[0].timestamp_ns
        last_ts = receipts[-1].timestamp_ns
        span_s = (last_ts - first_ts) / 1_000_000_000
        first_dt = datetime.datetime.fromtimestamp(first_ts / 1_000_000_000, tz=datetime.UTC)
        last_dt = datetime.datetime.fromtimestamp(last_ts / 1_000_000_000, tz=datetime.UTC)
        print(f" {n} receipts emitted, integrity verified.")
        print(f" Timespan : {span_s:.3f}s")
        print(f" First    : {first_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        print(f" Last     : {last_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    else:
        print(f" {n} receipts emitted (empty chain).")
    print()

    audit_dir = Path("audit-logs")
    audit_dir.mkdir(exist_ok=True)
    ts = int(time.time())
    chain_path = audit_dir / f"demo-seed{seed}-{ts}.jsonl"
    chain_path.write_text(chain.to_jsonl(), encoding="ascii")

    print(f" Chain saved: {chain_path}")
    print()
    print(" To verify this chain offline:")
    print(f"   export ALETHEIA_RECEIPT_SECRET={demo_secret_hex}")
    print(f"   sentinel verify {chain_path}")
    print(_DEMO_BANNER)

    return 0


# ---------------------------------------------------------------------------
# run subcommand helpers
# ---------------------------------------------------------------------------

async def _run_investigation(
    case_id: str,
    image_path: Path | None,
    max_iterations: int,
) -> int:
    if image_path is not None:
        log.info("Evidence image: %s (pinned; executor overrides Scout-invented paths)", image_path)

    secret = secret_from_env()
    chain = ReceiptChain(secret=secret, session_id=case_id)

    client = make_client()
    scout = ClaudeScout(client=client, tool_catalog=_TOOL_CATALOG)
    nitpicker = ClaudeNitpicker(client=client)
    judge = ClaudeJudge(client=client)
    gate = RemoteSpectralGate()

    from sentinel.server import server  # local import avoids circular at module level

    executor = build_executor(server, evidence_image=image_path)

    config = OrchestratorConfig(max_iterations=max_iterations)
    orch = Orchestrator(
        config=config,
        scout=scout,
        nitpicker=nitpicker,
        judge=judge,
        gate=gate,
        execute_tool=executor,
        chain=chain,
    )

    result = await orch.run(case_id)

    print(result.report)

    audit_dir = Path("audit-logs")
    audit_dir.mkdir(exist_ok=True)
    timestamp = int(time.time())
    jsonl_path = audit_dir / f"{case_id}-{timestamp}.jsonl"
    jsonl_path.write_text(chain.to_jsonl(), encoding="ascii")
    log.info(
        "Session complete: stop_reason=%s iterations=%d chain=%d receipts -> %s",
        result.stop_reason,
        result.iterations,
        result.chain_length,
        jsonl_path,
    )
    return 0


# ---------------------------------------------------------------------------
# benchmark subcommand helpers
# ---------------------------------------------------------------------------

async def _run_benchmark_cmd(cases_path: Path, output_path: Path | None) -> int:
    cases = _load_cases(cases_path)
    if not cases:
        print("No cases found in input file.", file=sys.stderr)
        return 1

    secret = secret_from_env()
    client = make_client()

    from sentinel.server import server as mcp_server

    executor = build_executor(mcp_server)

    def _make_orchestrator() -> OrchestratorProtocol:
        chain = ReceiptChain(secret=secret, session_id=f"bench-{time.time_ns()}")
        return Orchestrator(
            config=OrchestratorConfig(max_iterations=10),
            scout=ClaudeScout(client=client, tool_catalog=_TOOL_CATALOG),
            nitpicker=ClaudeNitpicker(client=client),
            judge=ClaudeJudge(client=client),
            gate=RemoteSpectralGate(),
            execute_tool=executor,
            chain=chain,
        )

    log.info("Running benchmark: %d case(s) from %s", len(cases), cases_path)
    results = await run_benchmark(cases, _make_orchestrator)

    report = _format_benchmark_report(cases, results)

    if output_path is not None:
        output_path.write_text(report, encoding="ascii")
        log.info("Benchmark report written to %s", output_path)
    else:
        print(report)

    return 0


def _load_cases(path: Path) -> list[Case]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"cases file must contain a JSON array: {path}")
    result: list[Case] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each case entry must be a JSON object")
        result.append(_parse_case(item))
    return result


def _parse_case(data: dict[str, object]) -> Case:
    case_id_raw = data.get("case_id", "")
    description_raw = data.get("description", "")
    findings_raw = data.get("expected_findings", [])
    paths_raw = data.get("evidence_paths", {})

    expected_findings: list[ExpectedFinding] = []
    if isinstance(findings_raw, list):
        for f in findings_raw:
            if isinstance(f, dict):
                ftype = str(f.get("type", ""))
                kf_raw = f.get("key_fields", {})
                kf = {str(k): str(v) for k, v in kf_raw.items()} if isinstance(kf_raw, dict) else {}
                expected_findings.append(ExpectedFinding(type=ftype, key_fields=kf))

    evidence_paths: dict[str, Path] = {}
    if isinstance(paths_raw, dict):
        evidence_paths = {str(k): Path(str(v)) for k, v in paths_raw.items()}

    return Case(
        case_id=str(case_id_raw),
        description=str(description_raw),
        expected_findings=expected_findings,
        evidence_paths=evidence_paths,
    )


def _format_benchmark_report(cases: list[Case], results: list[BenchmarkResult]) -> str:
    lines: list[str] = [
        "# Aletheia Sentinel Accuracy Benchmark Report",
        "",
        f"Cases run: {len(cases)}",
        "",
        "## Per-Case Results",
        "",
        "| Case ID | P | R | F1 | Matched | Missed | Spurious | Wall (s) | Error |",
        "|---------|---|---|----|---------|--------|----------|----------|-------|",
    ]

    total_p = total_r = total_f1 = 0.0
    for case, res in zip(cases, results):
        err = res.error_message or ""
        lines.append(
            f"| {case.case_id} "
            f"| {res.precision:.2f} "
            f"| {res.recall:.2f} "
            f"| {res.f1:.2f} "
            f"| {len(res.matched)} "
            f"| {len(res.missed)} "
            f"| {len(res.spurious)} "
            f"| {res.wall_seconds:.1f} "
            f"| {err} |"
        )
        total_p += res.precision
        total_r += res.recall
        total_f1 += res.f1

    n = len(cases)
    if n > 0:
        lines += [
            "",
            "## Overall",
            "",
            f"- Mean Precision: {total_p / n:.3f}",
            f"- Mean Recall:    {total_r / n:.3f}",
            f"- Mean F1:        {total_f1 / n:.3f}",
            f"- Total Cases:    {n}",
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# verify subcommand
# ---------------------------------------------------------------------------

def _cmd_verify(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain_path)

    if not chain_path.exists():
        print(f"Chain INVALID: file not found: {chain_path}", file=sys.stderr)
        return 1

    try:
        secret = secret_from_env()
    except RuntimeError as exc:
        print(f"Chain INVALID: {exc}", file=sys.stderr)
        return 1

    try:
        data = chain_path.read_text(encoding="ascii")
        chain = ReceiptChain.from_jsonl(data, secret=secret)
    except (ValueError, OSError) as exc:
        print(f"Chain INVALID: parse error: {exc}", file=sys.stderr)
        return 1

    try:
        chain.verify()
    except ChainIntegrityError as exc:
        print(f"Chain INVALID: {exc}", file=sys.stderr)
        return 1

    n = chain.length
    if n == 0:
        print("Chain valid: 0 receipts (empty chain)")
        return 0

    receipts = chain.receipts()
    first_ns = receipts[0].timestamp_ns
    last_ns = receipts[-1].timestamp_ns
    span_s = (last_ns - first_ns) / 1_000_000_000
    print(f"Chain valid: {n} receipts spanning {span_s:.3f}s")
    return 0


# ---------------------------------------------------------------------------
# Subcommand dispatch
# ---------------------------------------------------------------------------

def _cmd_server(_args: argparse.Namespace) -> int:
    from sentinel.server import main as server_main

    server_main()
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    image_path = Path(args.image) if args.image else None
    try:
        return asyncio.run(
            _run_investigation(
                case_id=args.case_id,
                image_path=image_path,
                max_iterations=args.max_iterations,
            )
        )
    except RuntimeError as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        return 1


def _cmd_benchmark(args: argparse.Namespace) -> int:
    cases_path = Path(args.cases)
    output_path = Path(args.output) if args.output else None
    try:
        return asyncio.run(_run_benchmark_cmd(cases_path, output_path))
    except (RuntimeError, ValueError) as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        return 1


def _cmd_demo(args: argparse.Namespace) -> int:
    try:
        return _run_demo(seed=args.seed)
    except (RuntimeError, OSError) as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Aletheia Sentinel autonomous incident response.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("server", help="Run the FastMCP server over stdio.")

    run_p = sub.add_parser("run", help="Run a full investigation session.")
    run_p.add_argument("case_id", help="Unique identifier for this investigation.")
    run_p.add_argument("--image", metavar="PATH", help="Path to evidence image (disk or memory).")
    run_p.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        metavar="N",
        help="Hard cap on Scout decisions (default: 50).",
    )

    bench_p = sub.add_parser("benchmark", help="Run the accuracy benchmark harness.")
    bench_p.add_argument(
        "--cases",
        required=True,
        metavar="PATH",
        help="JSON file containing an array of benchmark cases.",
    )
    bench_p.add_argument(
        "--output",
        metavar="PATH",
        help="Write markdown report to PATH instead of stdout.",
    )

    verify_p = sub.add_parser("verify", help="Verify a JSONL receipt chain on disk.")
    verify_p.add_argument("chain_path", metavar="CHAIN_PATH", help="Path to the .jsonl chain file.")

    demo_p = sub.add_parser(
        "demo",
        help="Run a scripted end-to-end demo investigation (no API key or SIFT tools required).",
    )
    demo_p.add_argument(
        "--seed",
        type=int,
        default=42,
        metavar="N",
        help="RNG seed for deterministic fake-tool output (default: 42).",
    )

    args = parser.parse_args()

    if args.command == "server":
        sys.exit(_cmd_server(args))
    elif args.command == "run":
        sys.exit(_cmd_run(args))
    elif args.command == "benchmark":
        sys.exit(_cmd_benchmark(args))
    elif args.command == "verify":
        sys.exit(_cmd_verify(args))
    else:
        sys.exit(_cmd_demo(args))


if __name__ == "__main__":
    main()
