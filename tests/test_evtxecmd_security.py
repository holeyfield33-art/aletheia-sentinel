from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.tools._subprocess import ToolBinaryNotFoundError, ToolTimeoutError
from sentinel.tools.base import ToolStatus
from sentinel.tools.evtxecmd_security import EvtxSecurityInput, evtxecmd_security

_LOGON_EVENT: dict[str, Any] = {
    "EventID": 4624,
    "Level": "Information",
    "Channel": "Security",
    "Computer": "DESKTOP-VICTIM",
    "TimeCreated": "2023-06-15T08:00:00.000Z",
    "RecordID": 12345,
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Payload": "An account was successfully logged on.",
}

_PROCESS_CREATE_EVENT: dict[str, Any] = {
    "EventID": 4688,
    "Level": "Information",
    "Channel": "Security",
    "Computer": "DESKTOP-VICTIM",
    "TimeCreated": "2023-06-15T08:01:00.000Z",
    "RecordID": 12346,
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Payload": "A new process has been created. Process: cmd.exe",
}

# An event with an ID not in the default filter list - should be ignored
_IGNORED_EVENT: dict[str, Any] = {
    "EventID": 9999,
    "Level": "Information",
    "Channel": "Security",
    "Computer": "DESKTOP-VICTIM",
    "TimeCreated": "2023-06-15T08:02:00.000Z",
    "RecordID": 12347,
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Payload": "Some other event.",
}


def _make_evtx_writer(events: list[dict[str, Any]]) -> Any:
    """Return a side_effect that writes the JSON events to the --json output path."""

    async def _mock(binary: str, args: list[str], *, timeout_seconds: float = 300.0) -> tuple[int, bytes, bytes]:
        idx = args.index("--json")
        Path(args[idx + 1]).write_text(json.dumps(events))
        return (0, b"", b"")

    return _mock


@pytest.fixture()
def dummy_evtx(tmp_path: Path) -> Path:
    p = tmp_path / "Security.evtx"
    p.write_bytes(b"dummy evtx")
    return p


async def test_happy_path(dummy_evtx: Path) -> None:
    side_effect = _make_evtx_writer([_LOGON_EVENT, _PROCESS_CREATE_EVENT, _IGNORED_EVENT])
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=side_effect),
    ):
        result = await evtxecmd_security(EvtxSecurityInput(evtx_path=dummy_evtx))

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    events = result.payload["events"]
    # _IGNORED_EVENT (9999) is filtered out
    assert len(events) == 2
    assert events[0]["event_id"] == 4624
    assert events[1]["event_id"] == 4688
    assert result.error is None


async def test_parser_error_bad_json(dummy_evtx: Path) -> None:
    async def _bad_mock(binary: str, args: list[str], *, timeout_seconds: float = 300.0) -> tuple[int, bytes, bytes]:
        idx = args.index("--json")
        Path(args[idx + 1]).write_text("this is not json ][")
        return (0, b"", b"")

    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=_bad_mock),
    ):
        result = await evtxecmd_security(EvtxSecurityInput(evtx_path=dummy_evtx))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "EvtxECmd output" in result.error


async def test_partial_mixed_events(dummy_evtx: Path) -> None:
    # A valid event plus an event missing EventID (gets through filter? No - None not in list)
    # Use a matching EventID but EventID value that causes int coercion failure
    bad_event: dict[str, Any] = {
        "EventID": 4624,        # matches filter
        "Level": "Information",
        "Channel": "Security",
        "Computer": "VICTIM",
        "TimeCreated": "2023-06-15T08:00:00Z",
        "RecordID": "not-an-int",   # invalid: must be int
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Payload": "logon",
    }
    side_effect = _make_evtx_writer([_LOGON_EVENT, bad_event])
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=side_effect),
    ):
        result = await evtxecmd_security(EvtxSecurityInput(evtx_path=dummy_evtx))

    assert result.status == ToolStatus.PARTIAL
    assert result.payload is not None
    assert len(result.payload["events"]) == 1
    assert len(result.notes) == 1
    assert "Skipped event" in result.notes[0]


async def test_binary_not_found(dummy_evtx: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolBinaryNotFoundError("Binary not found: EvtxECmd")),
    ):
        result = await evtxecmd_security(EvtxSecurityInput(evtx_path=dummy_evtx))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "EvtxECmd" in result.error


async def test_timeout(dummy_evtx: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolTimeoutError("Tool EvtxECmd timed out after 300.0s")),
    ):
        result = await evtxecmd_security(EvtxSecurityInput(evtx_path=dummy_evtx))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "timed out" in result.error


async def test_custom_event_id_filter(dummy_evtx: Path) -> None:
    side_effect = _make_evtx_writer([_LOGON_EVENT, _PROCESS_CREATE_EVENT])
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=side_effect),
    ):
        # Only request 4624 (logon) events
        result = await evtxecmd_security(
            EvtxSecurityInput(evtx_path=dummy_evtx, include_event_ids=[4624])
        )

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    events = result.payload["events"]
    assert len(events) == 1
    assert events[0]["event_id"] == 4624
