from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

# Fields vol3 adds to every TreeGrid row that are not part of the connection model.
_VOL3_NETSCAN_STRIP: frozenset[str] = frozenset({"__children"})


class Connection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    offset: str = Field(alias="Offset")
    protocol: str = Field(alias="Proto")
    local_address: str = Field(alias="LocalAddr")
    local_port: int | None = Field(default=None, alias="LocalPort")
    foreign_address: str | None = Field(default=None, alias="ForeignAddr")
    foreign_port: int | None = Field(default=None, alias="ForeignPort")
    state: str | None = Field(default=None, alias="State")
    pid: int | None = Field(default=None, alias="PID")
    owner: str | None = Field(default=None, alias="Owner")
    created: str | None = Field(default=None, alias="Created")

    @field_validator("offset", mode="before")
    @classmethod
    def _normalize_offset(cls, v: object) -> str:
        # Volatility 3 -r json emits Offset as an int; older/other outputs as a hex string.
        if isinstance(v, int):
            return hex(v)
        return str(v)


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
        clean = {k: v for k, v in item.items() if k not in _VOL3_NETSCAN_STRIP}
        try:
            connections.append(Connection.model_validate(clean))
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
