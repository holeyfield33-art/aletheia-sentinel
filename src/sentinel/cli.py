"""Command-line interface for Aletheia Sentinel.

Two subcommands:
    sentinel server          Start the FastMCP server over stdio.
    sentinel run CASE_ID     Run a full autonomous investigation session.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path
from typing import Any

from sentinel.agents.llm import ClaudeJudge, ClaudeNitpicker, ClaudeScout, make_client
from sentinel.agents.orchestrator import Orchestrator, OrchestratorConfig
from sentinel.agents.wiring import build_executor
from sentinel.audit.receipts import ReceiptChain, secret_from_env
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

    args = parser.parse_args()

    if args.command == "server":
        sys.exit(_cmd_server(args))
    else:
        sys.exit(_cmd_run(args))
