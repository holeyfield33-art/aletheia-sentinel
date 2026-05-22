import asyncio
from pathlib import Path
from typing import Tuple

class ToolExecutionError(Exception):
    """Base exception for tool execution errors."""
    pass

class ToolBinaryNotFoundError(ToolExecutionError):
    """Raised when the binary is not found."""
    pass

class ToolTimeoutError(ToolExecutionError):
    """Raised when the tool times out."""
    pass


async def run_tool(
    binary: str, 
    args: list[str], 
    *, 
    timeout_seconds: float = 300.0
) -> Tuple[int, bytes, bytes]:
    """
    Run a tool binary asynchronously with no shell.
    Caller is responsible for path validation.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
            returncode = await process.wait()
            return returncode, stdout, stderr
        except asyncio.TimeoutError:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise ToolTimeoutError(f"Tool {binary} timed out after {timeout_seconds}s")
            
    except FileNotFoundError:
        raise ToolBinaryNotFoundError(f"Binary not found: {binary}") from None
    except Exception as e:
        # Limited broad except as per spec; real code should be tighter
        raise ToolExecutionError(f"Failed to run {binary}: {e}") from e