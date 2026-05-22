"""Accuracy benchmark harness for Aletheia Sentinel."""

from __future__ import annotations

from sentinel.benchmark.cases import Case, ExpectedFinding
from sentinel.benchmark.runner import OrchestratorProtocol, run_benchmark
from sentinel.benchmark.scoring import BenchmarkResult, compute_score

__all__ = [
    "BenchmarkResult",
    "Case",
    "ExpectedFinding",
    "OrchestratorProtocol",
    "compute_score",
    "run_benchmark",
]
