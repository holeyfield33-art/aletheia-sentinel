from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

# Maps lowercase RegRipper output keys to AmcacheEntry field names.
# "path"/"full_path" are the terminal fields of an entry and trigger creation.
# Both "last modified" (space) and "last_modified" (underscore) variants are
# present depending on the RegRipper version / plugin output style.
_KEY_MAP: dict[str, str] = {
    "path": "program_path",
    "full_path": "program_path",
    "sha1": "sha1",
    "first run": "first_run",
    "last modified": "last_modified",
    "last_modified": "last_modified",
    "publisher": "publisher",
    "product name": "product_name",
    "product version": "product_version",
}


class AmcacheEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    program_path: str
    sha1: str | None = None
    first_run: str | None = None
    last_modified: str | None = None
    publisher: str | None = None
    product_name: str | None = None
    product_version: str | None = None

    @field_validator("program_path")
    @classmethod
    def program_path_not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("program_path cannot be empty")
        return v


class AmcacheInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hive_file: Path

    @field_validator("hive_file")
    @classmethod
    def validate_hive(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("hive_file must exist")
        return v


class AmcachePayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entries: list[AmcacheEntry]


async def regripper_amcache(input_data: AmcacheInput) -> ToolResult:
    """Typed wrapper for RegRipper amcache plugin."""
    args = ["-p", "amcache", "-r", str(input_data.hive_file)]

    try:
        returncode, stdout, stderr = await _subprocess.run_tool(
            "rip.pl", args, timeout_seconds=120.0
        )
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(tool_name="regripper.amcache", status=ToolStatus.ERROR, error=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(tool_name="regripper.amcache", status=ToolStatus.ERROR, error=str(e))

    if returncode != 0:
        return ToolResult(
            tool_name="regripper.amcache",
            status=ToolStatus.ERROR,
            error=f"RegRipper failed: {stderr.decode()[:300]}",
        )

    entries: list[AmcacheEntry] = []
    skip_notes: list[str] = []
    current: dict[str, str] = {}

    for line in stdout.decode().splitlines():
        if ":" not in line:
            continue
        raw_key, _, val = line.partition(":")
        key_lower = raw_key.strip().lower()
        mapped = _KEY_MAP.get(key_lower)
        if mapped is not None:
            current[mapped] = val.strip()
        # "path" or "full_path" is the terminal field; trigger entry creation
        if key_lower in {"path", "full_path"}:
            try:
                entries.append(AmcacheEntry(**current))
            except ValidationError as e:
                skip_notes.append(f"Skipped amcache entry: {e}")
            current = {}

    status = ToolStatus.PARTIAL if (skip_notes or not entries) else ToolStatus.OK
    payload = AmcachePayload(entries=entries)
    return ToolResult(
        tool_name="regripper.amcache",
        status=status,
        payload=payload.model_dump(mode="json"),
        notes=skip_notes,
    )
