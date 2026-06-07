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
) -> ToolExecutor:
    """Return a ToolExecutor that dispatches directly to wrapper functions.

    The ``server`` parameter is accepted for API consistency with callers
    that pass the FastMCP instance; it is not used in the direct-dispatch path.

    ``evidence_image`` and ``evidence_disk`` pin the real evidence paths from
    the CLI flags. Scout selects which tool to run and any non-path parameters;
    it must not determine the evidence file path. Overriding here means the
    agent cannot redirect a tool at an invented or arbitrary file -- a
    server-side guardrail consistent with the no-shell-execution invariant.
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
        # Pin evidence paths: override whatever path Scout invented with the
        # real path captured from --image / --disk on the CLI.
        if tool_name in ("volatility.pslist", "volatility.netscan") and evidence_image:
            args = {**args, "memory_image": str(evidence_image)}
        if tool_name == "plaso.log2timeline" and evidence_disk:
            args = {**args, "image_path": str(evidence_disk)}
        return await fn(args)

    return _execute
