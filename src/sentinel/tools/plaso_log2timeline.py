from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

# All keys (field names and aliases) accepted by TimelineEvent.
# Used to strip unrecognised psort JSON fields before model_validate so that
# extra="forbid" does not reject rows that contain parser-specific extras.
_TIMELINE_KNOWN_KEYS: frozenset[str] = frozenset({
    "timestamp", "source", "source_type", "event_type",
    "user", "host", "short_description", "description",
    "datetime", "source_short", "source_long", "timestamp_desc",
    "username", "hostname", "message_short", "message",
})


class TimelineEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    timestamp: str = Field(alias="datetime")
    source: str = Field(alias="source_short")
    source_type: str = Field(alias="source_long")
    event_type: str = Field(alias="timestamp_desc")
    user: str | None = Field(default=None, alias="username")
    host: str | None = Field(default=None, alias="hostname")
    short_description: str = Field(alias="message_short")
    description: str = Field(alias="message")

    @model_validator(mode="before")
    @classmethod
    def _derive_short_description(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        has_short = data.get("short_description") or data.get("message_short")
        if not has_short:
            base = str(data.get("message") or data.get("description") or "")
            data = dict(data)
            data["message_short"] = base[:100]
        return data


class Log2TimelineInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    image_path: Path
    output_dir: Path

    @field_validator("image_path")
    @classmethod
    def validate_image(cls, v: Path) -> Path:
        if not v.exists():
            raise ValueError("image_path must exist")
        return v

    @field_validator("output_dir")
    @classmethod
    def validate_output_dir(cls, v: Path) -> Path:
        v.mkdir(parents=True, exist_ok=True)
        if not v.is_dir():
            raise ValueError("output_dir must be writable directory")
        return v


class TimelinePayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    plaso_file: str
    event_count: int
    events_sample: list[TimelineEvent]


async def plaso_log2timeline(input_data: Log2TimelineInput) -> ToolResult:
    """Long-running typed wrapper for Plaso log2timeline + psort. Slow tool."""
    plaso_file = input_data.output_dir / "case.plaso"
    json_out = input_data.output_dir / "timeline.json"

    # Stage 1: build the .plaso store
    args1 = [str(plaso_file), str(input_data.image_path)]
    try:
        rc1, _, _ = await _subprocess.run_tool(
            "log2timeline.py", args1, timeout_seconds=3600.0
        )
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(tool_name="plaso.log2timeline", status=ToolStatus.ERROR, error=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(tool_name="plaso.log2timeline", status=ToolStatus.ERROR, error=str(e))

    if rc1 != 0:
        return ToolResult(
            tool_name="plaso.log2timeline",
            status=ToolStatus.ERROR,
            error="log2timeline failed",
        )

    # Stage 2: export first 50 events to JSON via psort
    args2 = ["-o", "json", str(plaso_file), "--output-file", str(json_out)]
    try:
        rc2, _, _ = await _subprocess.run_tool(
            "psort.py", args2, timeout_seconds=600.0
        )
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(tool_name="plaso.log2timeline", status=ToolStatus.ERROR, error=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(tool_name="plaso.log2timeline", status=ToolStatus.ERROR, error=str(e))

    if rc2 != 0:
        return ToolResult(
            tool_name="plaso.log2timeline",
            status=ToolStatus.ERROR,
            error="psort failed",
        )

    try:
        with json_out.open() as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        return ToolResult(
            tool_name="plaso.log2timeline",
            status=ToolStatus.ERROR,
            error=f"Failed to read psort output: {e}",
        )

    events: list[TimelineEvent] = []
    skip_notes: list[str] = []
    for item in raw[:50]:
        clean = {k: v for k, v in item.items() if k in _TIMELINE_KNOWN_KEYS}
        try:
            events.append(TimelineEvent.model_validate(clean))
        except ValidationError as e:
            skip_notes.append(f"Skipped timeline event: {e}")

    status = ToolStatus.PARTIAL if skip_notes else ToolStatus.OK
    payload = TimelinePayload(
        plaso_file=str(plaso_file),
        event_count=len(events),
        events_sample=events,
    )
    return ToolResult(
        tool_name="plaso.log2timeline",
        status=status,
        payload=payload.model_dump(mode="json"),
        notes=skip_notes,
    )
