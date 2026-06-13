from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.tools._subprocess import ToolBinaryNotFoundError, ToolTimeoutError
from sentinel.tools.base import ToolStatus
from sentinel.tools.volatility_cmdline import CmdlineInput, volatility_cmdline

_PROC1 = {
    "PID": 4,
    "Process": "System",
    "Args": None,
}

_PROC2 = {
    "PID": 1234,
    "Process": "mimikatz.exe",
    "Args": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
}


@pytest.fixture()
def dummy_image(tmp_path: Path) -> Path:
    p = tmp_path / "memory.raw"
    p.write_bytes(b"dummy")
    return p


async def test_happy_path(dummy_image: Path) -> None:
    stdout = json.dumps([_PROC1, _PROC2]).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    assert len(result.payload["command_lines"]) == 2
    assert result.payload["command_lines"][0]["process"] == "System"
    assert result.payload["command_lines"][1]["args"] is not None
    assert result.error is None


async def test_strips_vol3_extra_fields(dummy_image: Path) -> None:
    rows = [
        {
            "__children": [],
            "File output": "stdout",
            "PID": 99,
            "Process": "svchost.exe",
            "Args": "svchost.exe -k NetworkService",
        }
    ]
    stdout = json.dumps(rows).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    assert len(result.payload["command_lines"]) == 1
    assert result.payload["command_lines"][0]["pid"] == 99


async def test_partial_mixed_rows(dummy_image: Path) -> None:
    bad_item = {"unexpected_field": "whoops"}
    stdout = json.dumps([_PROC1, bad_item]).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.PARTIAL
    assert len(result.notes) == 1
    assert "Skipped cmdline entry" in result.notes[0]
    assert result.payload is not None
    assert len(result.payload["command_lines"]) == 1


async def test_bad_json(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, b"<html>not json</html>", b"")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "JSON" in result.error


async def test_nonzero_exit_code(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(2, b"", b"profile mismatch")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "code 2" in result.error


async def test_binary_not_found(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolBinaryNotFoundError("Binary not found: vol")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None


async def test_timeout(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolTimeoutError("Tool vol timed out after 180.0s")),
    ):
        result = await volatility_cmdline(CmdlineInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "timed out" in result.error
