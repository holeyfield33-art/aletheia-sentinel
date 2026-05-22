from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from . import _subprocess
from sentinel.tools.base import ToolResult, ToolStatus


class Connection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    offset: str
    protocol: str
    local_address: str
    local_port: int | None = None
    foreign_address: str | None = None
    foreign_port: int | None = None
    state: str | None = None
    pid: int | None = None
    owner: str | None = None
    created: str | None = None


class NetscanInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    memory_image: Path

    @field_validator("memory_image")
    @classmethod
    def validate_memory_image(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("memory_image must exist and be a readable file")
        return v


class NetscanPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    connections: list[Connection]


async def volatility_netscan(input_data: NetscanInput) -> ToolResult:
    """Typed wrapper for Volatility 3 windows.netscan.NetScan."""
    args = ["-f", str(input_data.memory_image), "-r", "json", "windows.netscan.NetScan"]

    try:
        returncode, stdout, stderr = await _subprocess.run_tool("vol", args, timeout_seconds=180.0)
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(tool_name="volatility.netscan", status=ToolStatus.ERROR, error=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(tool_name="volatility.netscan", status=ToolStatus.ERROR, error=str(e))

    if returncode != 0:
        return ToolResult(
            tool_name="volatility.netscan",
            status=ToolStatus.ERROR,
            error=f"Volatility exited with code {returncode}: {stderr.decode()[:500]}",
        )

    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        return ToolResult(
            tool_name="volatility.netscan",
            status=ToolStatus.ERROR,
            error=f"Failed to parse JSON: {e}",
        )

    connections: list[Connection] = []
    skip_notes: list[str] = []
    for item in data:
        try:
            connections.append(Connection.model_validate(item))
        except ValidationError as e:
            skip_notes.append(f"Skipped connection entry: {e}")

    status = ToolStatus.PARTIAL if (skip_notes or not connections) else ToolStatus.OK
    payload = NetscanPayload(connections=connections)
    return ToolResult(
        tool_name="volatility.netscan",
        status=status,
        payload=payload.model_dump(mode="json"),
        notes=skip_notes,
    )
