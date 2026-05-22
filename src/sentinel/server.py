"""FastMCP server exposing typed forensic SIFT tools.

All five tools declare readOnlyHint=True and destructiveHint=False.
This is the architectural invariant the hackathon brief evaluates:
the MCP tool surface contains zero destructive operations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from sentinel.tools.evtxecmd_security import EvtxSecurityInput, evtxecmd_security
from sentinel.tools.plaso_log2timeline import Log2TimelineInput, plaso_log2timeline
from sentinel.tools.regripper_amcache import AmcacheInput, regripper_amcache
from sentinel.tools.volatility_netscan import NetscanInput, volatility_netscan
from sentinel.tools.volatility_pslist import PslistInput, volatility_pslist

server: FastMCP = FastMCP("aletheia-sentinel")

_RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False)


@server.tool(
    name="volatility.pslist",
    description="List processes from a memory image using Volatility 3 windows.pslist.",
    annotations=_RO,
    structured_output=False,
)
async def _volatility_pslist(
    memory_image: Path,
    profile_hint: str | None = None,
) -> dict[str, Any]:
    inp = PslistInput(memory_image=memory_image, profile_hint=profile_hint)
    result = await volatility_pslist(inp)
    return result.model_dump(mode="json")


@server.tool(
    name="volatility.netscan",
    description="Scan network connections from a memory image using Volatility 3 windows.netscan.",
    annotations=_RO,
    structured_output=False,
)
async def _volatility_netscan(memory_image: Path) -> dict[str, Any]:
    inp = NetscanInput(memory_image=memory_image)
    result = await volatility_netscan(inp)
    return result.model_dump(mode="json")


@server.tool(
    name="regripper.amcache",
    description="Parse an Amcache registry hive with the RegRipper amcache plugin.",
    annotations=_RO,
    structured_output=False,
)
async def _regripper_amcache(hive_file: Path) -> dict[str, Any]:
    inp = AmcacheInput(hive_file=hive_file)
    result = await regripper_amcache(inp)
    return result.model_dump(mode="json")


@server.tool(
    name="plaso.log2timeline",
    description="Generate a full filesystem timeline using Plaso log2timeline + psort.",
    annotations=_RO,
    structured_output=False,
)
async def _plaso_log2timeline(image_path: Path, output_dir: Path) -> dict[str, Any]:
    inp = Log2TimelineInput(image_path=image_path, output_dir=output_dir)
    result = await plaso_log2timeline(inp)
    return result.model_dump(mode="json")


@server.tool(
    name="evtxecmd.parse_security",
    description="Parse Security.evtx events using EvtxECmd with optional event-ID filter.",
    annotations=_RO,
    structured_output=False,
)
async def _evtxecmd_parse_security(
    evtx_path: Path,
    include_event_ids: list[int] | None = None,
) -> dict[str, Any]:
    inp = EvtxSecurityInput(evtx_path=evtx_path, include_event_ids=include_event_ids)
    result = await evtxecmd_security(inp)
    return result.model_dump(mode="json")


def main() -> None:
    server.run(transport="stdio")
