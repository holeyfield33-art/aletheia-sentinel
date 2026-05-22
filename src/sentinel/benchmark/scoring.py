"""Precision/recall/F1 scoring for benchmark cases.

A reported ToolResult matches an ExpectedFinding when every key_field in the
expected finding is present in the result payload with a compatible value:
- String values: substring match (expected in actual)
- Numeric values (int/float in payload): exact float comparison
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.benchmark.cases import ExpectedFinding
from sentinel.tools.base import ToolResult


@dataclass
class BenchmarkResult:
    """Scoring outcome for one benchmark case."""

    precision: float
    recall: float
    f1: float
    matched: list[tuple[ExpectedFinding, ToolResult]] = field(default_factory=list)
    missed: list[ExpectedFinding] = field(default_factory=list)
    spurious: list[ToolResult] = field(default_factory=list)
    wall_seconds: float = 0.0
    error_message: str | None = None


def compute_score(
    expected: list[ExpectedFinding],
    reported: list[ToolResult],
) -> BenchmarkResult:
    """Compute precision/recall/F1 for one benchmark case.

    Edge-case conventions:
    - Both empty: P=R=F1=1.0 (trivially perfect).
    - Expected empty, reported non-empty: P=0.0 (all spurious), R=1.0, F1=0.0.
    - Reported empty, expected non-empty: P=1.0 (no false positives), R=0.0, F1=0.0.
    """
    if not expected and not reported:
        return BenchmarkResult(precision=1.0, recall=1.0, f1=1.0)

    if not expected:
        return BenchmarkResult(
            precision=0.0,
            recall=1.0,
            f1=0.0,
            spurious=list(reported),
        )

    if not reported:
        return BenchmarkResult(
            precision=1.0,
            recall=0.0,
            f1=0.0,
            missed=list(expected),
        )

    matched: list[tuple[ExpectedFinding, ToolResult]] = []
    missed: list[ExpectedFinding] = []
    used: set[int] = set()

    for exp in expected:
        found = False
        for i, rep in enumerate(reported):
            if i not in used and _matches(exp, rep):
                matched.append((exp, rep))
                used.add(i)
                found = True
                break
        if not found:
            missed.append(exp)

    spurious = [rep for i, rep in enumerate(reported) if i not in used]

    tp = len(matched)
    precision = tp / len(reported)
    recall = tp / len(expected)
    denom = precision + recall
    f1 = 2.0 * precision * recall / denom if denom > 0.0 else 0.0

    return BenchmarkResult(
        precision=precision,
        recall=recall,
        f1=f1,
        matched=matched,
        missed=missed,
        spurious=spurious,
    )


def _matches(exp: ExpectedFinding, rep: ToolResult) -> bool:
    """Return True if every key_field in exp is satisfied by rep's payload."""
    payload = rep.payload or {}
    for key, expected_val in exp.key_fields.items():
        actual = payload.get(key)
        if actual is None:
            return False
        if isinstance(actual, (int, float)) and not isinstance(actual, bool):
            try:
                if float(expected_val) != float(actual):
                    return False
            except ValueError:
                return False
        else:
            if expected_val not in str(actual):
                return False
    return True
