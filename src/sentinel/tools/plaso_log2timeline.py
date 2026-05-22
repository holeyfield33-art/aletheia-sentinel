from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess


class TimelineEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: str
    source: str
    source_type: str
    event_type: str
    user: str | None = None
    host: str | None = None
    short_description: str
    description: str


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
        try:
            events.append(TimelineEvent.model_validate(item))
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
