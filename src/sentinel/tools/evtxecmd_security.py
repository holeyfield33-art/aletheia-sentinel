from pathlib import Path
from pydantic import BaseModel, field_validator
from typing import List, Optional
from . import _subprocess
from ..models import ToolResult, ToolStatus
import tempfile

class SecurityEvent(BaseModel):
    event_id: int
    level: str
    channel: str
    computer: str
    time_created: str
    record_id: int
    provider_name: str
    payload_summary: str

class EvtxSecurityInput(BaseModel):
    evtx_path: Path
    include_event_ids: Optional[List[int]] = None

    @field_validator('evtx_path')
    @classmethod
    def validate_evtx(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("evtx_path must exist")
        return v

class SecurityEventPayload(BaseModel):
    events: List[SecurityEvent]

async def evtxecmd_security(input_data: EvtxSecurityInput) -> ToolResult:
    """Typed wrapper for EvtxECmd on Security.evtx"""
    default_ids = [4624, 4625, 4634, 4648, 4672, 4688, 4720, 4732, 4738, 4768, 4769, 4776, 7045, 4697]
    filter_ids = input_data.include_event_ids or default_ids
    
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
        tmp_path = Path(tmp.name)
    
    args = ["-f", str(input_data.evtx_path), "--json", str(tmp_path)]
    
    try:
        returncode, stdout, stderr = await _subprocess.run_tool("EvtxECmd", args, timeout_seconds=300.0)
        
        if returncode != 0:
            return ToolResult(status=ToolStatus.ERROR, payload=None, notes="EvtxECmd failed")
        
        try:
            import json
            with open(tmp_path) as f:
                data = json.load(f)
            
            events = []
            for item in data:
                if item.get('EventID') in filter_ids:
                    try:
                        evt = SecurityEvent(
                            event_id=item.get('EventID'),
                            level=item.get('Level', ''),
                            channel=item.get('Channel', ''),
                            computer=item.get('Computer', ''),
                            time_created=item.get('TimeCreated', ''),
                            record_id=item.get('RecordID', 0),
                            provider_name=item.get('ProviderName', ''),
                            payload_summary=str(item.get('Payload', ''))[:200]
                        )
                        events.append(evt)
                    except Exception:
                        pass
            
            payload = SecurityEventPayload(events=events)
            return ToolResult(
                status=ToolStatus.SUCCESS,
                payload=payload,
                notes=f"Extracted {len(events)} security events"
            )
            
        finally:
            tmp_path.unlink(missing_ok=True)
            
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except Exception as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))