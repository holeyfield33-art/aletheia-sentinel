"""Validation script: test the volatility_pslist wrapper against realistic JSON inputs.

This script exercises the wrapper's parsing logic without subprocess calls or a real
memory image.  It serves two purposes:

1. Confirm the wrapper correctly processes JSON that matches the schema it expects.
2. Document the field-name gap between real Volatility 3 JSON output (which uses
   column headers such as "PID", "ImageFileName", "Offset(V)") and the Pydantic
   model's field names ("pid", "name", "offset", ...).

Run with:  python scripts/validate_real_pslist.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

# Ensure the src tree is importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinel.tools.base import ToolStatus
from sentinel.tools.volatility_pslist import Process, PslistInput, volatility_pslist
# ---------------------------------------------------------------------------
# Sample A: REAL Volatility 3 JSON format
# Keys match the column names defined in windows.pslist.PsList.run():
#   PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64,
#   CreateTime, ExitTime, File output, __children
# This is what `vol -r json windows.pslist.PsList` actually outputs.
# ---------------------------------------------------------------------------
REAL_VOL3_JSON: list[dict[str, object]] = [
    {
        "__children": [],
        "CreateTime": "2023-11-15 08:00:00.000000 UTC+0000",
        "ExitTime": None,
        "File output": "-",
        "Handles": 2343,
        "ImageFileName": "System",
        "Offset(V)": "0xfa8000c95040",
        "PID": 4,
        "PPID": 0,
        "SessionId": None,
        "Threads": 147,
        "Wow64": False,
    },
    {
        "__children": [],
        "CreateTime": "2023-11-15 08:00:00.543210 UTC+0000",
        "ExitTime": None,
        "File output": "-",
        "Handles": 35,
        "ImageFileName": "smss.exe",
        "Offset(V)": "0xfa8001234000",
        "PID": 388,
        "PPID": 4,
        "SessionId": 0,
        "Threads": 2,
        "Wow64": False,
    },
    {
        "__children": [],
        "CreateTime": "2023-11-15 08:01:12.100000 UTC+0000",
        "ExitTime": None,
        "File output": "-",
        "Handles": 1024,
        "ImageFileName": "explorer.exe",
        "Offset(V)": "0xfa8002345000",
        "PID": 2172,
        "PPID": 2076,
        "SessionId": 1,
        "Threads": 25,
        "Wow64": False,
    },
    {
        "__children": [],
        "CreateTime": "2023-11-15 08:02:45.000000 UTC+0000",
        "ExitTime": None,
        "File output": "-",
        "Handles": None,
        "ImageFileName": "mimikatz.exe",
        "Offset(V)": "0xfa8003456000",
        "PID": 3980,
        "PPID": 2172,
        "SessionId": 1,
        "Threads": 3,
        "Wow64": True,
    },
]


# ---------------------------------------------------------------------------
# Sample B: schema-conformant sample
# Keys match the Pydantic Process model's field names exactly.
# This is the format the wrapper's internal parsing logic expects.
# ---------------------------------------------------------------------------
SCHEMA_CONFORMANT_JSON: list[dict[str, object]] = [
    {
        "pid": 4,
        "ppid": 0,
        "name": "System",
        "offset": "0xfa8000c95040",
        "threads": 147,
        "handles": 2343,
        "session_id": None,
        "wow64": False,
        "create_time": "2023-11-15 08:00:00.000000",
        "exit_time": None,
    },
    {
        "pid": 388,
        "ppid": 4,
        "name": "smss.exe",
        "offset": "0xfa8001234000",
        "threads": 2,
        "handles": 35,
        "session_id": 0,
        "wow64": False,
        "create_time": "2023-11-15 08:00:00.543210",
        "exit_time": None,
    },
    {
        "pid": 2172,
        "ppid": 2076,
        "name": "explorer.exe",
        "offset": "0xfa8002345000",
        "threads": 25,
        "handles": 1024,
        "session_id": 1,
        "wow64": False,
        "create_time": "2023-11-15 08:01:12.100000",
        "exit_time": None,
    },
    {
        "pid": 3980,
        "ppid": 2172,
        "name": "mimikatz.exe",
        "offset": "0xfa8003456000",
        "threads": 3,
        "handles": None,
        "session_id": 1,
        "wow64": True,
        "create_time": "2023-11-15 08:02:45.000000",
        "exit_time": None,
    },
    {
        "pid": 5100,
        "ppid": 3980,
        "name": "lsass.exe",
        "offset": "0xfa8004567000",
        "threads": 10,
        "handles": None,
        "session_id": None,
        "wow64": False,
        "create_time": None,
        "exit_time": "2023-11-15 08:03:01.000000",
    },
]


async def _run_wrapper(json_sample: list[dict[str, object]], tmp_path: Path) -> object:
    """Invoke volatility_pslist with the subprocess mocked to return json_sample."""
    dummy_image = tmp_path / "memory.raw"
    dummy_image.write_bytes(b"dummy")
    stdout = json.dumps(json_sample).encode()
    with patch(
        "sentinel.tools._subprocess.run_tool",
        new=AsyncMock(return_value=(0, stdout, b"")),
    ):
        return await volatility_pslist(PslistInput(memory_image=dummy_image))


def main() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # -- Sample A: real vol3 JSON format ------------------------------------
        print("=" * 70)
        print("SAMPLE A: Real Volatility 3 JSON format (uppercase column names)")
        print("=" * 70)
        result_a = asyncio.run(_run_wrapper(REAL_VOL3_JSON, tmp))
        print(f"Status       : {result_a.status}")
        print(f"Error        : {result_a.error}")
        parsed_a = result_a.payload.get("processes", []) if result_a.payload else []
        print(f"Parsed procs : {len(parsed_a)} of {len(REAL_VOL3_JSON)}")
        skip_notes_a = result_a.notes or []
        print(f"Skip notes   : {len(skip_notes_a)} entries skipped")
        if skip_notes_a:
            print(f"  First skip : {skip_notes_a[0][:120]}")
        print()
        print("RE-VALIDATION (post-fix): Field aliases + populate_by_name=True applied.")
        print("Real vol3 JSON (PID, PPID, ImageFileName, ...) is now parsed correctly.")
        print("TreeGrid extras (__children, 'File output') are stripped before validation.")
        print()

        # -- Sample B: schema-conformant JSON -----------------------------------
        print("=" * 70)
        print("SAMPLE B: Schema-conformant JSON (matches Pydantic Process model)")
        print("=" * 70)
        result_b = asyncio.run(_run_wrapper(SCHEMA_CONFORMANT_JSON, tmp))
        print(f"Status       : {result_b.status}")
        print(f"Error        : {result_b.error}")
        parsed_b: list[dict[str, object]] = (
            result_b.payload.get("processes", []) if result_b.payload else []
        )
        print(f"Parsed procs : {len(parsed_b)} of {len(SCHEMA_CONFORMANT_JSON)}")
        print()
        for i, raw in enumerate(parsed_b[:5]):
            proc = Process.model_validate(raw)
            print(
                f"  Process {i + 1}: pid={proc.pid} ppid={proc.ppid} "
                f"name={proc.name!r} wow64={proc.wow64} "
                f"handles={proc.handles} session_id={proc.session_id}"
            )
        print()

        # -- Assertions ---------------------------------------------------------
        assert result_a.status == ToolStatus.OK, (
            f"Expected OK for real vol3 format after fix, got {result_a.status}"
        )
        assert len(parsed_a) == len(REAL_VOL3_JSON), (
            f"Expected {len(REAL_VOL3_JSON)} parsed processes from real vol3 format, "
            f"got {len(parsed_a)}"
        )

        assert result_b.status == ToolStatus.OK, (
            f"Expected OK for schema-conformant format, got {result_b.status}"
        )
        assert len(parsed_b) == len(SCHEMA_CONFORMANT_JSON), (
            f"Expected {len(SCHEMA_CONFORMANT_JSON)} processes, got {len(parsed_b)}"
        )

        print("All assertions passed.")
        print()
        print("SUMMARY")
        print("-------")
        print(f"Real vol3 JSON  -> {len(parsed_a)}/{len(REAL_VOL3_JSON)} parsed (FIXED)")
        print(f"Schema JSON     -> {len(parsed_b)}/{len(SCHEMA_CONFORMANT_JSON)} parsed (all OK)")


if __name__ == "__main__":
    main()
