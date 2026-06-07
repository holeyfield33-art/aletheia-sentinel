"""Dispatch table wiring orchestrator tool calls to wrapper functions.

For single-host investigations the CLI calls wrapper functions directly
rather than going through a separate MCP subprocess. The MCP server
(server.py) handles external client connections (Claude Desktop etc.).

The dispatch table uses an explicit dict, not getattr-by-string, so the
mapping is statically auditable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel.agents.orchestrator import ToolExecutor
from sentinel.tools.base import ToolResult, ToolStatus
from sentinel.tools.evtxecmd_security import EvtxSecurityInput, evtxecmd_security
from sentinel.tools.plaso_log2timeline import Log2TimelineInput, plaso_log2timeline
from sentinel.tools.regripper_amcache import AmcacheInput, regripper_amcache
from sentinel.tools.volatility_netscan import NetscanInput, volatility_netscan
from sentinel.tools.volatility_pslist import PslistInput, volatility_pslist

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


async def _exec_pslist(args: dict[str, object]) -> ToolResult:
    return await volatility_pslist(PslistInput.model_validate(args))


async def _exec_netscan(args: dict[str, object]) -> ToolResult:
    return await volatility_netscan(NetscanInput.model_validate(args))


async def _exec_amcache(args: dict[str, object]) -> ToolResult:
    return await regripper_amcache(AmcacheInput.model_validate(args))


async def _exec_log2timeline(args: dict[str, object]) -> ToolResult:
    return await plaso_log2timeline(Log2TimelineInput.model_validate(args))


async def _exec_parse_security(args: dict[str, object]) -> ToolResult:
    return await evtxecmd_security(EvtxSecurityInput.model_validate(args))


_DISPATCH: dict[str, Callable[[dict[str, object]], Awaitable[ToolResult]]] = {
    "volatility.pslist": _exec_pslist,
    "volatility.netscan": _exec_netscan,
    "regripper.amcache": _exec_amcache,
    "plaso.log2timeline": _exec_log2timeline,
    "evtxecmd.parse_security": _exec_parse_security,
}


def build_executor(
    server: FastMCP,  # noqa: ARG001
    *,
    evidence_image: Path | None = None,
    evidence_disk: Path | None = None,
    evidence_hive: Path | None = None,
    evidence_evtx: Path | None = None,
) -> ToolExecutor:
    """Return a ToolExecutor that dispatches directly to wrapper functions.

    The ``server`` parameter is accepted for API consistency with callers
    that pass the FastMCP instance; it is not used in the direct-dispatch path.

    Evidence path parameters pin the real paths from CLI flags so Scout cannot
    redirect tools at invented or arbitrary files -- a server-side guardrail
    consistent with the no-shell-execution invariant.

    If a tool is called but its required evidence path was not provided, the
    executor returns ToolStatus.ERROR immediately rather than letting an
    invented path reach the Pydantic validator.
    """

    async def _execute(tool_name: str, args: dict[str, object]) -> ToolResult:
        fn = _DISPATCH.get(tool_name)
        if fn is None:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Unknown tool: {tool_name!r}. "
                f"Available: {sorted(_DISPATCH)}",
            )

        # Fast-fail if the required evidence was not supplied for this tool.
        if tool_name in ("volatility.pslist", "volatility.netscan") and evidence_image is None:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"{tool_name} requires a memory image (--image) but none was provided.",
            )
        if tool_name == "plaso.log2timeline" and evidence_disk is None:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error="plaso.log2timeline requires a disk image (--disk) but none was provided.",
            )
        if tool_name == "regripper.amcache" and evidence_hive is None:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error="regripper.amcache requires a registry hive (--hive) but none was provided.",
            )
        if tool_name == "evtxecmd.parse_security" and evidence_evtx is None:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=(
                    "evtxecmd.parse_security requires an evtx directory"
                    " (--evtx) but none was provided."
                ),
            )

        # Pin evidence paths: override whatever path Scout invented with the
        # real path captured from the CLI flags.
        if tool_name in ("volatility.pslist", "volatility.netscan") and evidence_image:
            args = {**args, "memory_image": str(evidence_image)}
        if tool_name == "plaso.log2timeline" and evidence_disk:
            args = {**args, "image_path": str(evidence_disk)}
        if tool_name == "regripper.amcache" and evidence_hive:
            args = {**args, "hive_file": str(evidence_hive)}
        if tool_name == "evtxecmd.parse_security" and evidence_evtx:
            args = {**args, "evtx_path": str(evidence_evtx)}

        return await fn(args)

    return _execute
