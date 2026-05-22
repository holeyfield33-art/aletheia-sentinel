from pathlib import Path
from pydantic import BaseModel, field_validator
from typing import List, Optional
from . import _subprocess
from ..models import ToolResult, ToolStatus

class AmcacheEntry(BaseModel):
    program_path: str
    sha1: Optional[str] = None
    first_run: Optional[str] = None
    last_modified: Optional[str] = None
    publisher: Optional[str] = None
    product_name: Optional[str] = None
    product_version: Optional[str] = None

class AmcacheInput(BaseModel):
    hive_file: Path

    @field_validator('hive_file')
    @classmethod
    def validate_hive(cls, v: Path) -> Path:
        if not v.exists() or not v.is_file():
            raise ValueError("hive_file must exist")
        return v

class AmcachePayload(BaseModel):
    entries: List[AmcacheEntry]

async def regripper_amcache(input_data: AmcacheInput) -> ToolResult:
    """Typed wrapper for RegRipper amcache plugin"""
    args = ["-p", "amcache", "-r", str(input_data.hive_file)]
    
    try:
        returncode, stdout, stderr = await _subprocess.run_tool("rip.pl", args, timeout_seconds=120.0)
        
        if returncode != 0:
            return ToolResult(
                status=ToolStatus.ERROR,
                payload=None,
                notes=f"RegRipper failed: {stderr.decode()[:300]}"
            )
        
        # Simple line-by-line parser (defensive)
        entries = []
        lines = stdout.decode().splitlines()
        current = {}
        for line in lines:
            if ':' in line:
                key, val = line.split(':', 1)
                current[key.strip()] = val.strip()
                if 'Path' in key:
                    entries.append(AmcacheEntry(**{k.lower().replace(' ', '_'): v for k, v in current.items() if v}))
                    current = {}
        
        payload = AmcachePayload(entries=entries)
        return ToolResult(
            status=ToolStatus.SUCCESS if entries else ToolStatus.PARTIAL,
            payload=payload,
            notes=f"Parsed {len(entries)} entries"
        )
        
    except _subprocess.ToolBinaryNotFoundError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except _subprocess.ToolTimeoutError as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))
    except Exception as e:
        return ToolResult(status=ToolStatus.ERROR, payload=None, notes=str(e))