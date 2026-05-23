from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.tools._subprocess import ToolBinaryNotFoundError, ToolTimeoutError
from sentinel.tools.base import ToolStatus
from sentinel.tools.plaso_log2timeline import Log2TimelineInput, plaso_log2timeline

_EVENT1 = {
    "timestamp": "2023-01-01T00:00:00Z",
    "source": "FILE",
    "source_type": "file entry",
    "event_type": "modification",
    "user": None,
    "host": "DESKTOP-1",
    "short_description": "C:/Windows/System32/calc.exe",
    "description": "OS file entry: C:/Windows/System32/calc.exe",
}

_EVENT2 = {
    "timestamp": "2023-01-01T00:01:00Z",
    "source": "REG",
    "source_type": "registry key",
    "event_type": "creation",
    "user": "Administrator",
    "host": "DESKTOP-1",
    "short_description": "HKLM\\Software\\Microsoft",
    "description": "Registry key created: HKLM\\Software\\Microsoft",
}


def _make_psort_writer(output_dir: Path, events: list[dict[str, Any]]) -> Any:
    """Return an AsyncMock side_effect that writes psort JSON on the second call."""
    call_count = 0

    async def _mock(
        binary: str, args: list[str], *, timeout_seconds: float = 300.0
    ) -> tuple[int, bytes, bytes]:
        nonlocal call_count
        call_count += 1
        if binary == "psort.py":
            # Find --output-file path in args and write the events there
            idx = args.index("--output-file")
            Path(args[idx + 1]).write_text(json.dumps(events))
        return (0, b"", b"")

    return _mock


@pytest.fixture()
def image_file(tmp_path: Path) -> Path:
    p = tmp_path / "case.dd"
    p.write_bytes(b"dummy image")
    return p


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plaso_out"
    d.mkdir()
    return d


async def test_happy_path(image_file: Path, output_dir: Path) -> None:
    side_effect = _make_psort_writer(output_dir, [_EVENT1, _EVENT2])
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=side_effect),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    assert result.payload["event_count"] == 2
    assert len(result.payload["events_sample"]) == 2
    assert result.payload["events_sample"][0]["source"] == "FILE"
    assert result.error is None


async def test_parser_error_bad_json(image_file: Path, output_dir: Path) -> None:
    async def _mock(
        binary: str, args: list[str], *, timeout_seconds: float = 300.0
    ) -> tuple[int, bytes, bytes]:
        if binary == "psort.py":
            idx = args.index("--output-file")
            Path(args[idx + 1]).write_text("not json {{{{")
        return (0, b"", b"")

    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=_mock),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "psort output" in result.error


async def test_partial_mixed_events(image_file: Path, output_dir: Path) -> None:
    # Second event is missing required fields (no timestamp)
    bad_event = {"source": "REG", "source_type": "key", "event_type": "mod",
                 "short_description": "x", "description": "y"}
    side_effect = _make_psort_writer(output_dir, [_EVENT1, bad_event])
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=side_effect),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.PARTIAL
    assert result.payload is not None
    assert result.payload["event_count"] == 1
    assert len(result.notes) == 1
    assert "Skipped timeline event" in result.notes[0]


async def test_binary_not_found_log2timeline(image_file: Path, output_dir: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolBinaryNotFoundError("Binary not found: log2timeline.py")),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "log2timeline.py" in result.error


async def test_timeout_psort(image_file: Path, output_dir: Path) -> None:
    call_count = 0

    async def _mock(
        binary: str, args: list[str], *, timeout_seconds: float = 300.0
    ) -> tuple[int, bytes, bytes]:
        nonlocal call_count
        call_count += 1
        if binary == "psort.py":
            raise ToolTimeoutError("Tool psort.py timed out after 600.0s")
        return (0, b"", b"")

    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=_mock),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "timed out" in result.error


async def test_log2timeline_nonzero_exit(image_file: Path, output_dir: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(1, b"", b"image format not recognised")),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "log2timeline" in result.error


async def test_parses_real_tool_output(image_file: Path, output_dir: Path) -> None:
    # Real psort -o json field names; also includes parser-specific extras
    # (display_name, parser, tag) that the wrapper must silently strip.
    real_events: list[dict[str, Any]] = [
        {
            "datetime": "2023-01-01T00:00:00Z",
            "timestamp_desc": "File Modified",
            "source_short": "FILE",
            "source_long": "OS file entry",
            "message": "OS file entry: C:/Windows/System32/calc.exe",
            "message_short": "C:/Windows/System32/calc.exe",
            "username": None,
            "hostname": "DESKTOP-1",
            # parser-specific extras -- should be stripped, not cause forbid error
            "display_name": "OS:/Windows/System32/calc.exe",
            "parser": "filestat",
            "tag": [],
        },
        {
            "datetime": "2023-01-01T00:01:00Z",
            "timestamp_desc": "Registry Key Written",
            "source_short": "REG",
            "source_long": "Registry Key",
            "message": "Registry key: HKLM\\Software\\Microsoft",
            # no message_short -- wrapper must derive from message[:100]
            "username": "Administrator",
            "hostname": "DESKTOP-1",
            "display_name": "NTUSER.DAT",
            "parser": "winreg",
        },
    ]
    side_effect = _make_psort_writer(output_dir, real_events)
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=side_effect),
    ):
        result = await plaso_log2timeline(
            Log2TimelineInput(image_path=image_file, output_dir=output_dir)
        )

    assert result.status == ToolStatus.OK
    assert result.error is None
    assert result.payload is not None
    assert result.payload["event_count"] == 2
    events = result.payload["events_sample"]
    assert len(events) == 2
    assert events[0]["source"] == "FILE"
    assert events[0]["event_type"] == "File Modified"
    assert events[0]["timestamp"] == "2023-01-01T00:00:00Z"
    assert events[0]["short_description"] == "C:/Windows/System32/calc.exe"
    assert events[1]["source"] == "REG"
    # short_description derived from message when message_short absent
    assert events[1]["short_description"] == "Registry key: HKLM\\Software\\Microsoft"[:100]
