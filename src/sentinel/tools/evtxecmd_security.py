from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

_DEFAULT_EVENT_IDS: list[int] = [
    4624, 4625, 4634, 4648, 4672, 4688, 4720, 4732, 4738, 4768, 4769, 4776, 7045, 4697
]


class SecurityEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: int
    level: str
    channel: str
    computer: str
    time_created: str
    record_id: int
    provider_name: str
    payload_summary: str


class EvtxSecurityInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evtx_path: Path
    include_event_ids: list[int] | None = None

    @field_validator("evtx_path")
    @classmethod
    def validate_evtx(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("evtx_path must exist")
        return v


class SecurityEventPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    events: list[SecurityEvent]


async def evtxecmd_security(input_data: EvtxSecurityInput) -> ToolResult:
    """Typed wrapper for EvtxECmd on Security.evtx."""
    filter_ids = input_data.include_event_ids or _DEFAULT_EVENT_IDS

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as ntf:
        tmp_path = Path(ntf.name)

    args = ["-f", str(input_data.evtx_path), "--json", str(tmp_path)]

    try:
        try:
            returncode, _, stderr = await _subprocess.run_tool(
                "EvtxECmd", args, timeout_seconds=300.0
            )
        except _subprocess.ToolBinaryNotFoundError as e:
            return ToolResult(
                tool_name="evtxecmd.security", status=ToolStatus.ERROR, error=str(e)
            )
        except _subprocess.ToolTimeoutError as e:
            return ToolResult(
                tool_name="evtxecmd.security", status=ToolStatus.ERROR, error=str(e)
            )

        if returncode != 0:
            return ToolResult(
                tool_name="evtxecmd.security",
                status=ToolStatus.ERROR,
                error=f"EvtxECmd failed: {stderr.decode()[:300]}",
            )

        try:
            with tmp_path.open() as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            return ToolResult(
                tool_name="evtxecmd.security",
                status=ToolStatus.ERROR,
                error=f"Failed to read EvtxECmd output: {e}",
            )

        events: list[SecurityEvent] = []
        skip_notes: list[str] = []
        for item in data:
            if item.get("EventID") not in filter_ids:
                continue
            try:
                evt = SecurityEvent(
                    event_id=item["EventID"],
                    level=item.get("Level", ""),
                    channel=item.get("Channel", ""),
                    computer=item.get("Computer", ""),
                    time_created=item.get("TimeCreated", ""),
                    record_id=item.get("RecordID", 0),
                    provider_name=item.get("ProviderName", ""),
                    payload_summary=str(item.get("Payload", ""))[:200],
                )
                events.append(evt)
            except ValidationError as e:
                skip_notes.append(f"Skipped event: {e}")

        status = ToolStatus.PARTIAL if skip_notes else ToolStatus.OK
        payload = SecurityEventPayload(events=events)
        return ToolResult(
            tool_name="evtxecmd.security",
            status=status,
            payload=payload.model_dump(mode="json"),
            notes=skip_notes,
        )
    finally:
        tmp_path.unlink(missing_ok=True)
