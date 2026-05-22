from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess


class Process(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pid: int
    ppid: int
    name: str
    offset: str
    threads: int
    handles: int | None = None
    session_id: int | None = None
    wow64: bool
    create_time: str | None = None
    exit_time: str | None = None


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
        try:
            processes.append(Process.model_validate(item))
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
