from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.tools._subprocess import ToolBinaryNotFoundError, ToolTimeoutError
from sentinel.tools.base import ToolStatus
from sentinel.tools.volatility_pslist import PslistInput, volatility_pslist

_PROC1 = {
    "pid": 4,
    "ppid": 0,
    "name": "System",
    "offset": "0xfa8000c95040",
    "threads": 147,
    "handles": 2343,
    "session_id": None,
    "wow64": False,
    "create_time": "2023-01-01 00:00:00.000000",
    "exit_time": None,
}

_PROC2 = {
    "pid": 388,
    "ppid": 4,
    "name": "smss.exe",
    "offset": "0xfa8001234567",
    "threads": 2,
    "handles": 35,
    "session_id": 0,
    "wow64": False,
    "create_time": "2023-01-01 00:00:01.000000",
    "exit_time": None,
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
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    assert len(result.payload["processes"]) == 2
    assert result.payload["processes"][0]["pid"] == 4
    assert result.payload["processes"][1]["name"] == "smss.exe"
    assert result.error is None


async def test_parser_error_bad_json(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, b"not valid json {{{{", b"")),
    ):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "JSON" in result.error


async def test_partial_mixed_rows(dummy_image: Path) -> None:
    # _PROC1 is valid; the second dict is missing required fields
    bad_item = {"foo": "bar", "invalid": True}
    stdout = json.dumps([_PROC1, bad_item]).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.PARTIAL
    assert len(result.notes) == 1
    assert "Skipped process entry" in result.notes[0]
    assert result.payload is not None
    assert len(result.payload["processes"]) == 1


async def test_binary_not_found(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolBinaryNotFoundError("Binary not found: vol")),
    ):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "vol" in result.error


async def test_timeout(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolTimeoutError("Tool vol timed out after 180.0s")),
    ):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "timed out" in result.error


async def test_nonzero_exit_code(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(1, b"", b"volatility: error loading profile")),
    ):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "code 1" in result.error
