"""Benchmark runner.

Iterates over a list of Cases, creates a fresh Orchestrator per case via the
provided factory, runs the session, and scores the results. Each case runs
independently so receipt chains do not bleed between cases.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from sentinel.agents.orchestrator import SessionResult
from sentinel.benchmark.cases import Case
from sentinel.benchmark.scoring import BenchmarkResult, compute_score


class OrchestratorProtocol(Protocol):
    """Structural protocol satisfied by Orchestrator and test mocks alike."""

    async def run(self, case_id: str) -> SessionResult: ...


async def run_benchmark(
    cases: list[Case],
    orchestrator_factory: Callable[[], OrchestratorProtocol],
) -> list[BenchmarkResult]:
    """Run every Case through a fresh orchestrator and return scored results.

    Results are returned in the same order as ``cases``. If an orchestration
    raises RuntimeError or ValueError, the case is recorded as a failed result
    (F1=0, error_message set) rather than crashing the entire benchmark run.
    Wall time is measured per case.
    """
    results: list[BenchmarkResult] = []
    for case in cases:
        orch = orchestrator_factory()
        start = time.monotonic()
        try:
            session_result = await orch.run(case.case_id)
            elapsed = time.monotonic() - start
            score = compute_score(case.expected_findings, session_result.state.findings)
            score.wall_seconds = elapsed
        except (RuntimeError, ValueError) as exc:
            elapsed = time.monotonic() - start
            score = BenchmarkResult(
                precision=0.0,
                recall=0.0,
                f1=0.0,
                error_message=str(exc),
                wall_seconds=elapsed,
            )
        results.append(score)
    return results
