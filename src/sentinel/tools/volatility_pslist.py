from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

if TYPE_CHECKING:
    pass

# Fields vol3 adds to every TreeGrid row that are not part of the process model.
# "Offset(P)" and "Disassembly" appear in some psscan builds; strip them too.
_VOL3_PSLIST_STRIP: frozenset[str] = frozenset(
    {"__children", "File output", "Offset(P)", "Disassembly"}
)


class Process(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    pid: int = Field(alias="PID")
    ppid: int = Field(alias="PPID")
    name: str = Field(alias="ImageFileName")
    offset: str = Field(alias="Offset(V)")
    threads: int = Field(alias="Threads")
    handles: int | None = Field(default=None, alias="Handles")
    session_id: int | None = Field(default=None, alias="SessionId")
    wow64: bool = Field(alias="Wow64")
    create_time: str | None = Field(default=None, alias="CreateTime")
    exit_time: str | None = Field(default=None, alias="ExitTime")


class PslistInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    memory_image: Path
    profile_hint: str | None = None

    @field_validator("memory_image")
    @classmethod
    def validate_memory_image(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("memory_image must exist and be a readable file")
        return v


class PslistPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    processes: list[Process]


def _parse_vol_output(
    stdout: bytes,
) -> tuple[list[Process], list[str]] | ToolResult:
    """Parse vol JSON stdout into (processes, skip_notes) or a ToolResult on error."""
    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.ERROR,
            error=f"Failed to parse JSON: {e}",
        )

    processes: list[Process] = []
    skip_notes: list[str] = []
    for item in data:
        clean = {k: v for k, v in item.items() if k not in _VOL3_PSLIST_STRIP}
        try:
            processes.append(Process.model_validate(clean))
        except ValidationError as e:
            skip_notes.append(f"Skipped process entry: {e}")

    return processes, skip_notes


async def volatility_pslist(input_data: PslistInput) -> ToolResult:
    """Typed wrapper for Volatility 3 windows.pslist.PsList with psscan fallback."""
    args = ["-f", str(input_data.memory_image), "-r", "json", "windows.pslist.PsList"]

    try:
        returncode, stdout, stderr = await _subprocess.run_tool("vol", args, timeout_seconds=180.0)
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(tool_name="volatility.pslist", status=ToolStatus.ERROR, error=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(tool_name="volatility.pslist", status=ToolStatus.ERROR, error=str(e))

    if returncode != 0:
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.ERROR,
            error=f"Volatility exited with code {returncode}: {stderr.decode()[:500]}",
        )

    parsed = _parse_vol_output(stdout)
    if isinstance(parsed, ToolResult):
        return parsed
    processes, skip_notes = parsed

    if processes:
        skip_notes.append("source=pslist")
        status = ToolStatus.PARTIAL if skip_notes[:-1] else ToolStatus.OK
        payload = PslistPayload(processes=processes)
        return ToolResult(
            tool_name="volatility.pslist",
            status=status,
            payload=payload.model_dump(mode="json"),
            notes=skip_notes,
        )

    # pslist returned 0 processes — run psscan fallback.
    args_scan = ["-f", str(input_data.memory_image), "-r", "json", "windows.psscan.PsScan"]

    try:
        rc2, stdout2, stderr2 = await _subprocess.run_tool("vol", args_scan, timeout_seconds=180.0)
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.ERROR,
            error=f"psscan fallback failed (pslist returned 0 processes): {e}",
        )
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.ERROR,
            error=f"psscan fallback timed out (pslist returned 0 processes): {e}",
        )

    if rc2 != 0:
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.ERROR,
            error=(
                f"psscan fallback exited with code {rc2} "
                f"(pslist returned 0 processes): {stderr2.decode()[:500]}"
            ),
        )

    parsed2 = _parse_vol_output(stdout2)
    if isinstance(parsed2, ToolResult):
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.ERROR,
            error=(
                "psscan fallback JSON parse error "
                f"(pslist returned 0 processes): {parsed2.error}"
            ),
        )
    processes2, skip_notes2 = parsed2

    if not processes2:
        notes_both = skip_notes2 + ["both pslist and psscan returned 0 processes"]
        payload2 = PslistPayload(processes=[])
        return ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.PARTIAL,
            payload=payload2.model_dump(mode="json"),
            notes=notes_both,
        )

    skip_notes2.append("source=psscan-fallback (pslist returned 0 processes)")
    status2 = ToolStatus.PARTIAL if skip_notes2[:-1] else ToolStatus.OK
    payload2 = PslistPayload(processes=processes2)
    return ToolResult(
        tool_name="volatility.pslist",
        status=status2,
        payload=payload2.model_dump(mode="json"),
        notes=skip_notes2,
    )
