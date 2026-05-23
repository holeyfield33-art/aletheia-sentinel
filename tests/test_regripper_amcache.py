from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.tools._subprocess import ToolBinaryNotFoundError, ToolTimeoutError
from sentinel.tools.base import ToolStatus
from sentinel.tools.regripper_amcache import AmcacheInput, regripper_amcache

# Simulated RegRipper amcache output: other fields first, "Path" triggers creation
_GOOD_OUTPUT = b"""\
SHA1: aabbccddeeff00112233445566778899aabbccdd
First Run: 2023-01-15 08:30:00
Publisher: Microsoft Corporation
Product Name: Windows Calculator
Path: C:\\Windows\\System32\\calc.exe
SHA1: 1122334455667788990011223344556677889900
Path: C:\\Windows\\System32\\notepad.exe
"""

# One valid entry, then a "Path" line with no value (empty program_path -> ValidationError)
_PARTIAL_OUTPUT = b"""\
SHA1: aabbccddeeff00112233445566778899aabbccdd
Path: C:\\Windows\\System32\\calc.exe
SHA1: deadbeef
Path: \x20
"""


@pytest.fixture()
def dummy_hive(tmp_path: Path) -> Path:
    p = tmp_path / "Amcache.hve"
    p.write_bytes(b"dummy hive")
    return p


async def test_happy_path(dummy_hive: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, _GOOD_OUTPUT, b"")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.OK
    assert result.payload is not None
    entries = result.payload["entries"]
    assert len(entries) == 2
    assert entries[0]["program_path"] == "C:\\Windows\\System32\\calc.exe"
    assert entries[0]["sha1"] == "aabbccddeeff00112233445566778899aabbccdd"
    assert entries[0]["product_name"] == "Windows Calculator"
    assert entries[1]["program_path"] == "C:\\Windows\\System32\\notepad.exe"
    assert result.error is None


async def test_parser_error_garbled_output(dummy_hive: Path) -> None:
    # All lines lack colons; no entries parsed; empty result is PARTIAL
    garbled = b"this is not structured output\nno colons anywhere\n"
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, garbled, b"")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.PARTIAL
    assert result.payload is not None
    assert result.payload["entries"] == []


async def test_partial_mixed_entries(dummy_hive: Path) -> None:
    # _PARTIAL_OUTPUT has one valid entry and one with empty program_path
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, _PARTIAL_OUTPUT, b"")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.PARTIAL
    assert result.payload is not None
    assert len(result.payload["entries"]) == 1
    assert len(result.notes) == 1
    assert "Skipped amcache entry" in result.notes[0]


async def test_binary_not_found(dummy_hive: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolBinaryNotFoundError("Binary not found: rip.pl")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "rip.pl" in result.error


async def test_timeout(dummy_hive: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(side_effect=ToolTimeoutError("Tool rip.pl timed out after 120.0s")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "timed out" in result.error


async def test_nonzero_exit_code(dummy_hive: Path) -> None:
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(1, b"", b"Cannot open hive file")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.ERROR
    assert result.error is not None
    assert "RegRipper failed" in result.error


async def test_parses_real_amcache_plugin_output(dummy_hive: Path) -> None:
    # Realistic rip.pl -p amcache -r Amcache.hve output.
    # The amcache plugin emits a header block (amcache v.YYYYMMDD), then per-entry
    # blocks with: Key: ..., LastWrite: ..., file_id: ..., sha1: ...,
    # file_size: ..., full_path: ..., last_modified: ... (underscore variant).
    # file_id and file_size are not mapped to AmcacheEntry fields and are silently
    # ignored by the parser.  full_path triggers entry creation (real format).
    real_output = (
        b"amcache v.20200220\n"
        b"(HKLM\\ROOT\\InventoryApplicationFile)\n"
        b"\n"
        b"Key: {7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}\n"
        b"LastWrite: Wed Nov 18 10:23:44 2020 (UTC)\n"
        b"\n"
        b"file_id: 0000abc123def456\n"
        b"sha1: aabbccddeeff00112233445566778899aabbccdd\n"
        b"file_size: 12345\n"
        b"last_modified: Wed Nov 18 10:00:00 2020 (UTC)\n"
        b"full_path: c:\\windows\\system32\\calc.exe\n"
        b"\n"
        b"Key: {8d9e4a6b-c1d2-e3f4-a5b6-c7d8e9f0a1b2}\n"
        b"LastWrite: Thu Nov 19 09:10:00 2020 (UTC)\n"
        b"\n"
        b"file_id: 0000def456abc789\n"
        b"sha1: 1122334455667788990011223344556677889900\n"
        b"file_size: 98765\n"
        b"last_modified: Thu Nov 19 08:00:00 2020 (UTC)\n"
        b"full_path: c:\\windows\\system32\\notepad.exe\n"
    )
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, real_output, b"")),
    ):
        result = await regripper_amcache(AmcacheInput(hive_file=dummy_hive))

    assert result.status == ToolStatus.OK
    assert result.error is None
    assert result.payload is not None
    entries = result.payload["entries"]
    assert len(entries) == 2
    assert entries[0]["program_path"] == "c:\\windows\\system32\\calc.exe"
    assert entries[0]["sha1"] == "aabbccddeeff00112233445566778899aabbccdd"
    assert entries[0]["last_modified"] == "Wed Nov 18 10:00:00 2020 (UTC)"
    assert entries[1]["program_path"] == "c:\\windows\\system32\\notepad.exe"
    assert entries[1]["sha1"] == "1122334455667788990011223344556677889900"
