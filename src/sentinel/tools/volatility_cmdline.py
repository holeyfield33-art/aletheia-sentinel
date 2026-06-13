"""Typed wrapper for Volatility 3 windows.cmdline.CmdLine.

Recovers full process command lines from a memory image. This is the
evidence path that resolves identity traps like subject_srv.exe (F-Response):
process name and listening port alone read as a backdoor; the command line
(`-v "F-Response Subject" ...`) is what classifies it as legitimate tooling.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

# Fields vol3 adds to every TreeGrid row that are not part of the model.
_VOL3_CMDLINE_STRIP: frozenset[str] = frozenset({"__children", "File output"})


class CommandLine(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    pid: int = Field(alias="PID")
    process: str = Field(alias="Process")
    args: str | None = Field(default=None, alias="Args")
    """Full command line. None or an error string when the process's
    command-line memory is paged out or the process has exited."""


class CmdlineInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    memory_image: Path

    @field_validator("memory_image")
    @classmethod
    def validate_memory_image(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("memory_image must exist and be a readable file")
        return v


class CmdlinePayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    command_lines: list[CommandLine]


async def volatility_cmdline(input_data: CmdlineInput) -> ToolResult:
    """Recover process command lines via Volatility 3 windows.cmdline.CmdLine."""
    args = ["-f", str(input_data.memory_image), "-r", "json", "windows.cmdline.CmdLine"]

    try:
        returncode, stdout, stderr = await _subprocess.run_tool("vol", args, timeout_seconds=180.0)
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(tool_name="volatility.cmdline", status=ToolStatus.ERROR, error=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(tool_name="volatility.cmdline", status=ToolStatus.ERROR, error=str(e))

    if returncode != 0:
        return ToolResult(
            tool_name="volatility.cmdline",
            status=ToolStatus.ERROR,
            error=f"Volatility exited with code {returncode}: {stderr.decode()[:500]}",
        )

    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        return ToolResult(
            tool_name="volatility.cmdline",
            status=ToolStatus.ERROR,
            error=f"Failed to parse JSON: {e}",
        )

    command_lines: list[CommandLine] = []
    skip_notes: list[str] = []
    for item in data:
        clean = {k: v for k, v in item.items() if k not in _VOL3_CMDLINE_STRIP}
        try:
            command_lines.append(CommandLine.model_validate(clean))
        except ValidationError as e:
            skip_notes.append(f"Skipped cmdline entry: {e}")

    status = ToolStatus.PARTIAL if skip_notes else ToolStatus.OK
    payload = CmdlinePayload(command_lines=command_lines)
    return ToolResult(
        tool_name="volatility.cmdline",
        status=status,
        payload=payload.model_dump(mode="json"),
        notes=skip_notes,
    )
