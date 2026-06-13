"""Tests for evidence-gated tool catalog and complete path-pinning.

Part A: _build_tool_catalog only advertises tools whose evidence was supplied.
Part B: build_executor pins paths for every path-typed tool and fast-fails
        cleanly when the required evidence was not provided.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.agents.wiring import build_executor
from sentinel.cli import _build_tool_catalog
from sentinel.tools.base import ToolResult, ToolStatus

# ---------------------------------------------------------------------------
# Part A: catalog gating
# ---------------------------------------------------------------------------


def test_catalog_memory_only_has_volatility_tools() -> None:
    """pslist, netscan, and cmdline when only a memory image is provided."""
    catalog = _build_tool_catalog(
        evidence_image=Path("/mem.img"),
        evidence_disk=None,
        evidence_hive=None,
        evidence_evtx=None,
    )
    names = {t["name"] for t in catalog}
    assert names == {"volatility.pslist", "volatility.netscan", "volatility.cmdline"}


def test_catalog_hive_only_has_amcache() -> None:
    """Only regripper when only a hive file is provided."""
    catalog = _build_tool_catalog(
        evidence_image=None,
        evidence_disk=None,
        evidence_hive=Path("/Amcache.hve"),
        evidence_evtx=None,
    )
    names = {t["name"] for t in catalog}
    assert names == {"regripper.amcache"}


def test_catalog_evtx_only_has_parse_security() -> None:
    """Only evtxecmd when only an evtx path is provided."""
    catalog = _build_tool_catalog(
        evidence_image=None,
        evidence_disk=None,
        evidence_hive=None,
        evidence_evtx=Path("/Security.evtx"),
    )
    names = {t["name"] for t in catalog}
    assert names == {"evtxecmd.parse_security"}


def test_catalog_disk_only_has_log2timeline() -> None:
    """Only plaso when only a disk image is provided."""
    catalog = _build_tool_catalog(
        evidence_image=None,
        evidence_disk=Path("/disk.E01"),
        evidence_hive=None,
        evidence_evtx=None,
    )
    names = {t["name"] for t in catalog}
    assert names == {"plaso.log2timeline"}


def test_catalog_no_evidence_is_empty() -> None:
    """No evidence -> no tools advertised."""
    catalog = _build_tool_catalog(
        evidence_image=None,
        evidence_disk=None,
        evidence_hive=None,
        evidence_evtx=None,
    )
    assert catalog == []


def test_catalog_all_evidence_has_all_tools() -> None:
    """All five tools appear when every evidence type is provided."""
    catalog = _build_tool_catalog(
        evidence_image=Path("/mem.img"),
        evidence_disk=Path("/disk.E01"),
        evidence_hive=Path("/Amcache.hve"),
        evidence_evtx=Path("/Security.evtx"),
    )
    names = {t["name"] for t in catalog}
    assert names == {
        "volatility.pslist",
        "volatility.netscan",
        "volatility.cmdline",
        "regripper.amcache",
        "plaso.log2timeline",
        "evtxecmd.parse_security",
    }


def test_catalog_memory_only_excludes_regripper_and_evtxecmd() -> None:
    """Memory-only run must not advertise regripper or evtxecmd."""
    catalog = _build_tool_catalog(
        evidence_image=Path("/mem.img"),
        evidence_disk=None,
        evidence_hive=None,
        evidence_evtx=None,
    )
    names = {t["name"] for t in catalog}
    assert "regripper.amcache" not in names
    assert "evtxecmd.parse_security" not in names
    assert "plaso.log2timeline" not in names


# ---------------------------------------------------------------------------
# Part B: executor fast-fail when evidence not provided
# ---------------------------------------------------------------------------


async def test_executor_regripper_without_hive_fast_fails() -> None:
    """Calling regripper on an executor built without a hive must return ERROR."""
    executor = build_executor(MagicMock(), evidence_image=Path("/mem.img"))

    result = await executor("regripper.amcache", {"hive_file": "/invented/Amcache.hve"})

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert "hive" in result.error.lower() or "--hive" in result.error


async def test_executor_evtxecmd_without_evtx_fast_fails() -> None:
    """Calling evtxecmd on an executor built without evtx must return ERROR."""
    executor = build_executor(MagicMock(), evidence_image=Path("/mem.img"))

    result = await executor("evtxecmd.parse_security", {"evtx_path": "/invented/Security.evtx"})

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert "evtx" in result.error.lower() or "--evtx" in result.error


async def test_executor_pslist_without_image_fast_fails() -> None:
    """Calling pslist on an executor built without a memory image must return ERROR."""
    executor = build_executor(MagicMock())

    result = await executor("volatility.pslist", {"memory_image": "/invented/memory.raw"})

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert "image" in result.error.lower() or "--image" in result.error


async def test_executor_log2timeline_without_disk_fast_fails() -> None:
    """Calling log2timeline on an executor built without a disk image must return ERROR."""
    executor = build_executor(MagicMock(), evidence_image=Path("/mem.img"))

    result = await executor(
        "plaso.log2timeline",
        {"image_path": "/invented/disk.E01", "output_dir": "/tmp/out"},
    )

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert "disk" in result.error.lower() or "--disk" in result.error


# ---------------------------------------------------------------------------
# Part B: path pinning for regripper and evtxecmd
# ---------------------------------------------------------------------------


async def test_wiring_hive_path_pinned_for_regripper(tmp_path: Path) -> None:
    """regripper.amcache must receive the real hive_file path, not Scout's invented one."""
    from sentinel.tools.regripper_amcache import AmcacheInput

    real_hive = tmp_path / "Amcache.hve"
    real_hive.write_bytes(b"")

    executor = build_executor(MagicMock(), evidence_hive=real_hive)

    captured: list[AmcacheInput] = []

    async def _fake_amcache(payload: AmcacheInput) -> ToolResult:
        captured.append(payload)
        return ToolResult(tool_name="regripper.amcache", status=ToolStatus.OK)

    with patch("sentinel.agents.wiring.regripper_amcache", new=_fake_amcache):
        result = await executor(
            "regripper.amcache",
            {"hive_file": "/evidence/invented/Amcache.hve"},
        )

    assert result.status is ToolStatus.OK
    assert len(captured) == 1
    assert captured[0].hive_file == real_hive


async def test_wiring_evtx_path_pinned_for_evtxecmd(tmp_path: Path) -> None:
    """evtxecmd.parse_security must receive the real evtx_path, not Scout's invented one."""
    from sentinel.tools.evtxecmd_security import EvtxSecurityInput

    real_evtx = tmp_path / "Security.evtx"
    real_evtx.write_bytes(b"")

    executor = build_executor(MagicMock(), evidence_evtx=real_evtx)

    captured: list[EvtxSecurityInput] = []

    async def _fake_evtxecmd(payload: EvtxSecurityInput) -> ToolResult:
        captured.append(payload)
        return ToolResult(tool_name="evtxecmd.parse_security", status=ToolStatus.OK)

    with patch("sentinel.agents.wiring.evtxecmd_security", new=_fake_evtxecmd):
        result = await executor(
            "evtxecmd.parse_security",
            {"evtx_path": "/evidence/invented/Security.evtx"},
        )

    assert result.status is ToolStatus.OK
    assert len(captured) == 1
    assert captured[0].evtx_path == real_evtx


async def test_wiring_memory_only_run_completes_without_path_validation_error(
    tmp_path: Path,
) -> None:
    """With only a memory image, Scout calling regripper or evtxecmd returns ERROR cleanly.

    This covers the regression: a run with --image only must not crash with a
    Pydantic ValidationError when the invented path does not exist on disk.
    """
    real_image = tmp_path / "memory.img"
    real_image.write_bytes(b"")

    executor = build_executor(MagicMock(), evidence_image=real_image)

    reg_result = await executor("regripper.amcache", {"hive_file": "/evidence/Amcache.hve"})
    evtx_result = await executor(
        "evtxecmd.parse_security", {"evtx_path": "/evidence/Security.evtx"}
    )

    assert reg_result.status is ToolStatus.ERROR
    assert evtx_result.status is ToolStatus.ERROR
    assert reg_result.error is not None
    assert evtx_result.error is not None


@pytest.mark.parametrize("bogus_path", ["/made/up/Amcache.hve", "/nonexistent.hve"])
async def test_wiring_pinned_path_overrides_any_bogus_input(
    tmp_path: Path, bogus_path: str
) -> None:
    """The real evidence path is substituted regardless of what Scout supplies."""
    from sentinel.tools.regripper_amcache import AmcacheInput

    real_hive = tmp_path / "real_Amcache.hve"
    real_hive.write_bytes(b"")

    executor = build_executor(MagicMock(), evidence_hive=real_hive)

    captured: list[AmcacheInput] = []

    async def _fake_amcache(payload: AmcacheInput) -> ToolResult:
        captured.append(payload)
        return ToolResult(tool_name="regripper.amcache", status=ToolStatus.OK)

    with patch("sentinel.agents.wiring.regripper_amcache", new=_fake_amcache):
        await executor("regripper.amcache", {"hive_file": bogus_path})

    assert captured[0].hive_file == real_hive
