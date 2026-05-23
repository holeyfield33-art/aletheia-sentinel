from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

# Fields vol3 adds to every TreeGrid row that are not part of the process model.
_VOL3_PSLIST_STRIP: frozenset[str] = frozenset({"__children", "File output"})


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


async def volatility_pslist(input_data: PslistInput) -> ToolResult:
    """Typed wrapper for Volatility 3 windows.pslist.PsList."""
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

    status = ToolStatus.PARTIAL if (skip_notes or not processes) else ToolStatus.OK
    payload = PslistPayload(processes=processes)
    return ToolResult(
        tool_name="volatility.pslist",
        status=status,
        payload=payload.model_dump(mode="json"),
        notes=skip_notes,
    )
