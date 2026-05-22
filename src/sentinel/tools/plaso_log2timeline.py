from pathlib import Path
from pydantic import BaseModel, field_validator
from typing import List, Optional
from . import _subprocess
from ..models import ToolResult, ToolStatus

class TimelineEvent(BaseModel):
    timestamp: str
    source: str
    source_type: str
    event_type: str
    user: Optional[str] = None
    host: Optional[str] = None
    short_description: str
    description: str

class Log2TimelineInput(BaseModel):
    image_path: Path
    output_dir: Path

    @field_validator('image_path')
    @classmethod
    def validate_image(cls, v: Path) -> Path:
        if not v.exists():
            raise ValueError("image_path must exist")
        return v

    @field_validator('output_dir')
    @classmethod
    def validate_output_dir(cls, v: Path) -> Path:
        v.mkdir(parents=True, exist_ok=True)
        if not v.is_dir():
            raise ValueError("output_dir must be writable directory")
        return v

class TimelinePayload(BaseModel):
    plaso_file: Path
    event_count: int
    events_sample: List[TimelineEvent]

async def plaso_log2timeline(input_data: Log2TimelineInput) -> ToolResult:
    """Long-running typed wrapper for Plaso log2timeline + psort. Slow tool."""
    plaso_file = input_data.output_dir / "case.plaso"
    
    # Stage 1: log2timeline
    args1 = [str(plaso_file), str(input_data.image_path)]
    try:
        rc1, _, _ = await _subprocess.run_tool("log2timeline.py", args1, timeout_seconds=3600.0)
        if rc1 != 0:
            return ToolResult(status=ToolStatus.ERROR, payload=None, notes="log2timeline failed")
    except Exception as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    
    # Stage 2: psort to JSON
    json_out = input_data.output_dir / "timeline.json"
    args2 = ["-o", "json", str(plaso_file), "--output-file", str(json_out)]
    try:
        rc2, stdout, _ = await _subprocess.run_tool("psort.py", args2, timeout_seconds=600.0)
        
        # Sample first 50 events
        events = []
        try:
            import json
            data = json.loads(stdout.decode()[:500000])  # safety
            events = [TimelineEvent.model_validate(e) for e in data[:50]]
        except Exception:
            pass
        
        payload = TimelinePayload(
            plaso_file=plaso_file,
            event_count=len(events),
            events_sample=events
        )
        return ToolResult(
            status=ToolStatus.SUCCESS,
            payload=payload,
            notes="Timeline generated"
        )
        
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except Exception as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))