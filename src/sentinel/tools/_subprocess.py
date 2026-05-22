from __future__ import annotations

import asyncio


class ToolExecutionError(Exception):
    """Base exception for tool execution errors."""


class ToolBinaryNotFoundError(ToolExecutionError):
    """Raised when the binary is not found."""


class ToolTimeoutError(ToolExecutionError):
    """Raised when the tool times out."""


async def run_tool(
    binary: str,
    args: list[str],
    *,
    timeout_seconds: float = 300.0,
) -> tuple[int, bytes, bytes]:
    """Run a tool binary asynchronously with no shell.

    Raises ToolBinaryNotFoundError if the binary does not exist.
    Raises ToolTimeoutError if execution exceeds timeout_seconds.
    Any other OS-level error propagates unchanged.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise ToolBinaryNotFoundError(f"Binary not found: {binary}") from None

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except TimeoutError:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise ToolTimeoutError(f"Tool {binary} timed out after {timeout_seconds}s")

    returncode = process.returncode if process.returncode is not None else 1
    return returncode, stdout, stderr
