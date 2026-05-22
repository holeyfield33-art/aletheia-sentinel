from pathlib import Path
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from . import _subprocess
from ..models import ToolResult, ToolStatus

class Process(BaseModel):
    pid: int
    ppid: int
    name: str
    offset: str
    threads: int
    handles: Optional[int] = None
    session_id: Optional[int] = None
    wow64: bool
    create_time: Optional[str] = None
    exit_time: Optional[str] = None

class PslistInput(BaseModel):
    memory_image: Path
    profile_hint: Optional[str] = None

    @field_validator('memory_image')
    @classmethod
    def validate_memory_image(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("memory_image must exist and be a readable file")
        return v

class PslistPayload(BaseModel):
    processes: List[Process]

async def volatility_pslist(input_data: PslistInput) -> ToolResult:
    """Typed wrapper for Volatility 3 windows.pslist.PsList"""
    args = ["-f", str(input_data.memory_image), "-r", "json", "windows.pslist.PsList"]
    
    try:
        returncode, stdout, stderr = await _subprocess.run_tool("vol", args, timeout_seconds=180.0)
        
        if returncode != 0:
            return ToolResult(
                status=ToolStatus.ERROR,
                payload=None,
                notes=f"Volatility exited with code {returncode}: {stderr.decode()[:500]}"
            )
        
        try:
            import json
            data = json.loads(stdout.decode())
            processes = []
            for item in data:
                try:
                    proc = Process.model_validate(item)
                    processes.append(proc)
                except Exception as e:
                    # Partial handling
                    pass
            
            payload = PslistPayload(processes=processes)
            return ToolResult(
                status=ToolStatus.SUCCESS if processes else ToolStatus.PARTIAL,
                payload=payload,
                notes="Parsed successfully"
            )
            
        except json.JSONDecodeError as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                payload=None,
                notes=f"Failed to parse JSON: {e}"
            )
            
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except Exception as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))