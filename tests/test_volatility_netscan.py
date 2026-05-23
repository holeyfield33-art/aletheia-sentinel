from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.tools._subprocess import ToolBinaryNotFoundError, ToolTimeoutError
from sentinel.tools.base import ToolStatus
from sentinel.tools.volatility_netscan import NetscanInput, volatility_netscan

_CONN1 = {
    "offset": "0xfa8001a2b3c4",
    "protocol": "TCPv4",
    "local_address": "192.168.1.10",
    "local_port": 445,
    "foreign_address": "10.0.0.5",
    "foreign_port": 49200,
    "state": "ESTABLISHED",
    "pid": 4,
    "owner": "System",
    "created": "2023-01-01 00:01:00.000000",
}

_CONN2 = {
    "offset": "0xfa8001a2b3d0",
    "protocol": "UDPv4",
    "local_address": "0.0.0.0",
    "local_port": 5355,
    "foreign_address": None,
    "foreign_port": None,
    "state": None,
    "pid": 1088,
    "owner": "svchost.exe",
    "created": None,
}


@pytest.fixture()
def dummy_image(tmp_path: Path) -> Path:
    p = tmp_path / "memory.raw"
    p.write_bytes(b"dummy")
    return p


async def test_happy_path(dummy_image: Path) -> None:
    stdout = json.dumps([_CONN1, _CONN2]).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    assert len(result.payload["connections"]) == 2
    assert result.payload["connections"][0]["protocol"] == "TCPv4"
    assert result.payload["connections"][1]["local_port"] == 5355
    assert result.error is None


async def test_parser_error_bad_json(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, b"<html>not json</html>", b"")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "JSON" in result.error


async def test_partial_mixed_rows(dummy_image: Path) -> None:
    # Second item missing required fields (offset, protocol, local_address)
    bad_item = {"pid": 999, "unexpected_field": "whoops"}
    stdout = json.dumps([_CONN1, bad_item]).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.PARTIAL
    assert len(result.notes) == 1
    assert "Skipped connection entry" in result.notes[0]
    assert result.payload is not None
    assert len(result.payload["connections"]) == 1


async def test_binary_not_found(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolBinaryNotFoundError("Binary not found: vol")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None


async def test_timeout(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolTimeoutError("Tool vol timed out after 180.0s")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "timed out" in result.error


async def test_nonzero_exit_code(dummy_image: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(2, b"", b"profile mismatch")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "code 2" in result.error


async def test_parses_real_tool_output(dummy_image: Path) -> None:
    # Real vol3 windows.netscan.NetScan -r json format: aliased column names
    # plus __children extra added by the TreeGrid renderer.
    real_rows = [
        {
            "__children": [],
            "Offset": "0xfa8001a2b3c4",
            "Proto": "TCPv4",
            "LocalAddr": "192.168.1.10",
            "LocalPort": 445,
            "ForeignAddr": "10.0.0.5",
            "ForeignPort": 49200,
            "State": "ESTABLISHED",
            "PID": 4,
            "Owner": "System",
            "Created": "2023-01-01 00:01:00.000000",
        },
        {
            "__children": [],
            "Offset": "0xfa8001a2b3d0",
            "Proto": "UDPv4",
            "LocalAddr": "0.0.0.0",
            "LocalPort": 5355,
            "ForeignAddr": None,
            "ForeignPort": None,
            "State": None,
            "PID": 1088,
            "Owner": "svchost.exe",
            "Created": None,
        },
    ]
    stdout = json.dumps(real_rows).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_netscan(NetscanInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.error is None
    assert result.payload is not None
    conns = result.payload["connections"]
    assert len(conns) == 2
    assert conns[0]["protocol"] == "TCPv4"
    assert conns[0]["local_address"] == "192.168.1.10"
    assert conns[0]["local_port"] == 445
    assert conns[0]["state"] == "ESTABLISHED"
    assert conns[1]["protocol"] == "UDPv4"
    assert conns[1]["foreign_address"] is None
