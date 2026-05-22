"""Command-line interface for Aletheia Sentinel.

Three subcommands:
    sentinel server                   Start the FastMCP server over stdio.
    sentinel run CASE_ID              Run a full autonomous investigation session.
    sentinel benchmark --cases PATH   Run the accuracy benchmark harness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from sentinel.agents.llm import ClaudeJudge, ClaudeNitpicker, ClaudeScout, make_client
from sentinel.agents.orchestrator import Orchestrator, OrchestratorConfig
from sentinel.agents.wiring import build_executor
from sentinel.audit.receipts import ReceiptChain, secret_from_env
from sentinel.benchmark.cases import Case, ExpectedFinding
from sentinel.benchmark.runner import OrchestratorProtocol, run_benchmark
from sentinel.benchmark.scoring import BenchmarkResult
from sentinel.spectral.gate import RemoteSpectralGate

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


async def _run_investigation(
    case_id: str,
    image_path: Path | None,
    max_iterations: int,
) -> int:
    if image_path is not None:
        log.info("Evidence image: %s (captured; tool wiring uses this via Scout args)", image_path)

    secret = secret_from_env()
    chain = ReceiptChain(secret=secret, session_id=case_id)

    client = make_client()
    scout = ClaudeScout(client=client, tool_catalog=_TOOL_CATALOG)
    nitpicker = ClaudeNitpicker(client=client)
    judge = ClaudeJudge(client=client)
    gate = RemoteSpectralGate()

    from sentinel.server import server  # local import avoids circular at module level

    executor = build_executor(server)

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

    args = parser.parse_args()

    if args.command == "server":
        sys.exit(_cmd_server(args))
    elif args.command == "run":
        sys.exit(_cmd_run(args))
    else:
        sys.exit(_cmd_benchmark(args))
