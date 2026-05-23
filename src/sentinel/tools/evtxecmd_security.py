from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from sentinel.tools.base import ToolResult, ToolStatus

from . import _subprocess

_DEFAULT_EVENT_IDS: list[int] = [
    4624, 4625, 4634, 4648, 4672, 4688, 4720, 4732, 4738, 4768, 4769, 4776, 7045, 4697
]

_PAYLOAD_FIELDS: tuple[str, ...] = (
    "PayloadData1", "PayloadData2", "PayloadData3",
    "PayloadData4", "PayloadData5", "PayloadData6",
)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    event_id: int = Field(alias="EventId")
    level: str = Field(alias="Level")
    channel: str = Field(alias="Channel")
    computer: str = Field(alias="Computer")
    time_created: str = Field(alias="TimeCreated")
    record_id: int = Field(alias="RecordNumber")
    provider_name: str = Field(alias="Provider")
    payload_summary: str

    @model_validator(mode="before")
    @classmethod
    def _normalize_evtx_fields(cls, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            return data
        # Build payload_summary from PayloadData1..6 (real format) or Payload (legacy mock)
        parts = [str(data[k]) for k in _PAYLOAD_FIELDS if data.get(k)]
        payload_summary = " | ".join(parts) if parts else str(data.get("Payload", ""))[:200]
        # Normalize field names: support both real EvtxECmd output and legacy mock keys
        return {
            "EventId": data.get("EventId") or data.get("EventID"),
            "Level": data.get("Level", ""),
            "Channel": data.get("Channel", ""),
            "Computer": data.get("Computer", ""),
            "TimeCreated": data.get("TimeCreated", ""),
            "RecordNumber": data.get("RecordNumber") or data.get("RecordID", 0),
            "Provider": data.get("Provider") or data.get("ProviderName", ""),
            "payload_summary": payload_summary,
        }


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
            # Support both real EvtxECmd key ("EventId") and legacy mock key ("EventID")
            event_id_raw = item.get("EventId") or item.get("EventID")
            if event_id_raw not in filter_ids:
                continue
            try:
                events.append(SecurityEvent.model_validate(item))
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
