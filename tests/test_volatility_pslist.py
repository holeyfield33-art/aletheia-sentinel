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
    assert any("Skipped process entry" in n for n in result.notes)
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


# ---------------------------------------------------------------------------
# psscan fallback tests
# ---------------------------------------------------------------------------

_PSSCAN_ROWS = [
    {
        "__children": [],
        "PID": 4,
        "PPID": 0,
        "ImageFileName": "System",
        "Offset(V)": "0xfa8000c95040",
        "Threads": 147,
        "Handles": 2343,
        "SessionId": None,
        "Wow64": False,
        "CreateTime": "2018-09-12 08:00:00.000000 UTC+0000",
        "ExitTime": None,
        "File output": "-",
    },
    {
        "__children": [],
        "PID": 12528,
        "PPID": 740,
        "ImageFileName": "subject_srv.ex",
        "Offset(V)": "0xfa8009abc000",
        "Threads": 5,
        "Handles": 120,
        "SessionId": 1,
        "Wow64": True,
        "CreateTime": "2018-09-12 09:15:33.000000 UTC+0000",
        "ExitTime": None,
        "File output": "-",
    },
]


async def test_pslist_populated_no_fallback(dummy_image: Path) -> None:
    pslist_rows = [
        {
            "__children": [],
            "PID": 4,
            "PPID": 0,
            "ImageFileName": "System",
            "Offset(V)": "0xfa8000c95040",
            "Threads": 147,
            "Handles": 2343,
            "SessionId": None,
            "Wow64": False,
            "CreateTime": "2023-01-01 00:00:00.000000 UTC+0000",
            "ExitTime": None,
            "File output": "-",
        },
        {
            "__children": [],
            "PID": 388,
            "PPID": 4,
            "ImageFileName": "smss.exe",
            "Offset(V)": "0xfa8001234000",
            "Threads": 2,
            "Handles": 35,
            "SessionId": 0,
            "Wow64": False,
            "CreateTime": "2023-01-01 00:00:01.000000 UTC+0000",
            "ExitTime": None,
            "File output": "-",
        },
    ]
    mock = AsyncMock(return_value=(0, json.dumps(pslist_rows).encode(), b""))
    with patch("sentinel.tools._subprocess.run_tool", new=mock):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert mock.call_count == 1
    assert result.status == ToolStatus.OK
    assert result.payload is not None
    assert len(result.payload["processes"]) == 2
    assert any("source=pslist" in n for n in result.notes)


async def test_pslist_empty_triggers_psscan_fallback(dummy_image: Path) -> None:
    pslist_stdout = json.dumps([]).encode()
    psscan_stdout = json.dumps(_PSSCAN_ROWS).encode()
    mock = AsyncMock(
        side_effect=[
            (0, pslist_stdout, b""),
            (0, psscan_stdout, b""),
        ]
    )
    with patch("sentinel.tools._subprocess.run_tool", new=mock):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert mock.call_count == 2
    assert result.status == ToolStatus.OK
    assert result.payload is not None
    procs = result.payload["processes"]
    pids = [p["pid"] for p in procs]
    assert 12528 in pids
    subject = next(p for p in procs if p["pid"] == 12528)
    assert subject["name"] == "subject_srv.ex"
    assert subject["ppid"] == 740
    assert subject["wow64"] is True
    assert any("psscan-fallback" in n for n in result.notes)


async def test_both_empty_partial(dummy_image: Path) -> None:
    empty = json.dumps([]).encode()
    mock = AsyncMock(side_effect=[(0, empty, b""), (0, empty, b"")])
    with patch("sentinel.tools._subprocess.run_tool", new=mock):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert mock.call_count == 2
    assert result.status == ToolStatus.PARTIAL
    assert any("both pslist and psscan returned 0 processes" in n for n in result.notes)


async def test_psscan_error_surfaced(dummy_image: Path) -> None:
    empty = json.dumps([]).encode()
    mock = AsyncMock(
        side_effect=[
            (0, empty, b""),
            (1, b"", b"psscan: fatal profile error"),
        ]
    )
    with patch("sentinel.tools._subprocess.run_tool", new=mock):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert mock.call_count == 2
    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "psscan" in result.error.lower()
    assert "pslist returned 0" in result.error


async def test_existing_behavior_unchanged(dummy_image: Path) -> None:
    """Populated-pslist path must produce identical output to pre-fallback behaviour."""
    rows = [
        {
            "__children": [],
            "PID": 4,
            "PPID": 0,
            "ImageFileName": "System",
            "Offset(V)": "0xfa8000c95040",
            "Threads": 147,
            "Handles": 2343,
            "SessionId": None,
            "Wow64": False,
            "CreateTime": "2023-01-01 00:00:00.000000 UTC+0000",
            "ExitTime": None,
            "File output": "-",
        }
    ]
    mock = AsyncMock(return_value=(0, json.dumps(rows).encode(), b""))
    with patch("sentinel.tools._subprocess.run_tool", new=mock):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.error is None
    assert result.payload is not None
    procs = result.payload["processes"]
    assert len(procs) == 1
    assert procs[0]["pid"] == 4
    assert procs[0]["name"] == "System"
    # psscan must NOT have been called
    assert mock.call_count == 1


async def test_parses_real_tool_output(dummy_image: Path) -> None:
    # Real vol3 windows.pslist.PsList -r json format: uppercase column names
    # plus __children and "File output" extras added by the TreeGrid renderer.
    real_rows = [
        {
            "__children": [],
            "PID": 4,
            "PPID": 0,
            "ImageFileName": "System",
            "Offset(V)": "0xfa8000c95040",
            "Threads": 147,
            "Handles": 2343,
            "SessionId": None,
            "Wow64": False,
            "CreateTime": "2023-11-15 08:00:00.000000 UTC+0000",
            "ExitTime": None,
            "File output": "-",
        },
        {
            "__children": [],
            "PID": 388,
            "PPID": 4,
            "ImageFileName": "smss.exe",
            "Offset(V)": "0xfa8001234000",
            "Threads": 2,
            "Handles": 35,
            "SessionId": 0,
            "Wow64": False,
            "CreateTime": "2023-11-15 08:00:00.543210 UTC+0000",
            "ExitTime": None,
            "File output": "-",
        },
        {
            "__children": [],
            "PID": 3980,
            "PPID": 2172,
            "ImageFileName": "mimikatz.exe",
            "Offset(V)": "0xfa8003456000",
            "Threads": 3,
            "Handles": None,
            "SessionId": 1,
            "Wow64": True,
            "CreateTime": "2023-11-15 08:02:45.000000 UTC+0000",
            "ExitTime": None,
            "File output": "-",
        },
    ]
    stdout = json.dumps(real_rows).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        result = await volatility_pslist(PslistInput(memory_image=dummy_image))

    assert result.status == ToolStatus.OK
    assert result.error is None
    assert result.payload is not None
    procs = result.payload["processes"]
    assert len(procs) == 3
    assert procs[0]["pid"] == 4
    assert procs[0]["name"] == "System"
    assert procs[0]["offset"] == "0xfa8000c95040"
    assert procs[1]["pid"] == 388
    assert procs[1]["name"] == "smss.exe"
    assert procs[2]["pid"] == 3980
    assert procs[2]["wow64"] is True
    assert procs[2]["handles"] is None
