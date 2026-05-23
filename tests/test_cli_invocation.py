"""Regression test: python -m sentinel.cli demo must produce visible output.

Guards against the silent-exit bug caused by a missing __main__ guard.
"""

from __future__ import annotations

import subprocess
import sys


def test_demo_module_invocation() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "demo", "--seed", "42"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Non-zero exit: {result.returncode}\nstderr: {result.stderr}"
    assert "ALETHEIA SENTINEL" in result.stdout, "Banner not found in stdout"
    assert "[CHAIN]" in result.stdout, "[CHAIN] section not found in stdout"
