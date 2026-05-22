from pathlib import Path
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from . import _subprocess
from ..models import ToolResult, ToolStatus

class Connection(BaseModel):
    offset: str
    protocol: str
    local_address: str
    local_port: Optional[int] = None
    foreign_address: Optional[str] = None
    foreign_port: Optional[int] = None
    state: Optional[str] = None
    pid: Optional[int] = None
    owner: Optional[str] = None
    created: Optional[str] = None

class NetscanInput(BaseModel):
    memory_image: Path

    @field_validator('memory_image')
    @classmethod
    def validate_memory_image(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("memory_image must exist and be a readable file")
        return v

class NetscanPayload(BaseModel):
    connections: List[Connection]

async def volatility_netscan(input_data: NetscanInput) -> ToolResult:
    """Typed wrapper for Volatility 3 windows.netscan.NetScan"""
    args = ["-f", str(input_data.memory_image), "-r", "json", "windows.netscan.NetScan"]
    
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
            connections = []
            for item in data:
                try:
                    conn = Connection.model_validate(item)
                    connections.append(conn)
                except Exception:
                    pass  # partial
            
            payload = NetscanPayload(connections=connections)
            return ToolResult(
                status=ToolStatus.SUCCESS if connections else ToolStatus.PARTIAL,
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