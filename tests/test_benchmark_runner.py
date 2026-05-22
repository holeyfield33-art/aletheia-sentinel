"""Tests for the benchmark runner.

Verifies: wall time is recorded per case, results are returned in the same
order as input cases, and orchestration errors are captured as failed
BenchmarkResults rather than propagating.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from sentinel.agents.orchestrator import (
    SessionResult,
    SessionState,
    StopReason,
)
from sentinel.audit.receipts import ReceiptChain
from sentinel.benchmark.cases import Case, ExpectedFinding
from sentinel.benchmark.runner import OrchestratorProtocol, run_benchmark
from sentinel.tools.base import ToolResult, ToolStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chain() -> ReceiptChain:
    return ReceiptChain(secret=b"test-secret-32-bytes-of-entropy-yes", session_id="bench-test")


def _case(case_id: str, expected: list[ExpectedFinding] | None = None) -> Case:
    return Case(
        case_id=case_id,
        description=f"Test case {case_id}",
        expected_findings=expected or [],
    )


def _ok_finding(tool_name: str = "volatility.pslist") -> ToolResult:
    return ToolResult(tool_name=tool_name, status=ToolStatus.OK, payload={"mocked": True})


def _session_result(case_id: str, findings: list[ToolResult] | None = None) -> SessionResult:
    state = SessionState(case_id=case_id, findings=findings or [])
    return SessionResult(
        stop_reason=StopReason.SCOUT_DONE,
        iterations=1,
        report="test report",
        state=state,
        chain_length=0,
    )


@dataclass
class MockOrchestrator:
    """Orchestrator that returns a canned SessionResult."""

    findings: list[ToolResult] = field(default_factory=list)
    case_id_seen: str = ""

    async def run(self, case_id: str) -> SessionResult:
        self.case_id_seen = case_id
        return _session_result(case_id, self.findings)


@dataclass
class ErrorOrchestrator:
    """Orchestrator that always raises RuntimeError."""

    message: str = "orchestration failed"

    async def run(self, case_id: str) -> SessionResult:
        raise RuntimeError(self.message)


# ---------------------------------------------------------------------------
# Test 1: wall time is recorded per case
# ---------------------------------------------------------------------------


async def test_runner_records_wall_time() -> None:
    """BenchmarkResult.wall_seconds must be positive for each case."""
    cases = [_case("case-001"), _case("case-002")]
    call_count = 0

    def factory() -> OrchestratorProtocol:
        nonlocal call_count
        call_count += 1
        return MockOrchestrator()

    results = await run_benchmark(cases, factory)

    assert len(results) == 2
    assert call_count == 2
    for r in results:
        assert r.wall_seconds >= 0.0


# ---------------------------------------------------------------------------
# Test 2: results returned in the same order as input cases
# ---------------------------------------------------------------------------


async def test_runner_results_in_order() -> None:
    """Results must be in the same order as the input case list."""
    finding_a = _ok_finding("volatility.pslist")
    finding_b = _ok_finding("regripper.amcache")

    expected_a = [ExpectedFinding(type="process", key_fields={"mocked": "True"})]
    expected_b = [ExpectedFinding(type="amcache", key_fields={"mocked": "True"})]

    cases = [
        _case("case-A", expected_a),
        _case("case-B", expected_b),
    ]

    def factory_a() -> OrchestratorProtocol:
        return MockOrchestrator(findings=[finding_a])

    def factory_b() -> OrchestratorProtocol:
        return MockOrchestrator(findings=[finding_b])

    factories = [factory_a, factory_b]
    idx = 0

    def rotating_factory() -> OrchestratorProtocol:
        nonlocal idx
        f = factories[idx % len(factories)]
        idx += 1
        return f()

    results = await run_benchmark(cases, rotating_factory)

    assert len(results) == 2
    # Both cases have mocked=True in findings, so both should have matches
    assert results[0].f1 == pytest.approx(1.0)
    assert results[1].f1 == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Test 3: orchestration error captured as failed BenchmarkResult
# ---------------------------------------------------------------------------


async def test_runner_captures_error_as_failed_result() -> None:
    """A case that throws RuntimeError must be captured as F1=0 with error_message."""
    cases = [_case("case-error")]

    def failing_factory() -> OrchestratorProtocol:
        return ErrorOrchestrator(message="simulated orchestration failure")

    results = await run_benchmark(cases, failing_factory)

    assert len(results) == 1
    r = results[0]
    assert r.f1 == pytest.approx(0.0)
    assert r.precision == pytest.approx(0.0)
    assert r.recall == pytest.approx(0.0)
    assert r.error_message is not None
    assert "simulated orchestration failure" in r.error_message


# ---------------------------------------------------------------------------
# Test 4: empty case list returns empty results
# ---------------------------------------------------------------------------


async def test_runner_empty_cases_returns_empty_list() -> None:
    """run_benchmark with no cases must return an empty list."""

    def factory() -> OrchestratorProtocol:
        return MockOrchestrator()

    results = await run_benchmark([], factory)
    assert results == []


# ---------------------------------------------------------------------------
# Test 5: successful case followed by error case -- both captured
# ---------------------------------------------------------------------------


async def test_runner_mixed_success_and_error() -> None:
    """A successful case followed by a failing case must both be recorded."""
    cases = [_case("ok-case"), _case("err-case")]
    orch_instances: list[OrchestratorProtocol] = [
        MockOrchestrator(),
        ErrorOrchestrator(),
    ]
    call_index = 0

    def factory() -> OrchestratorProtocol:
        nonlocal call_index
        orch = orch_instances[call_index]
        call_index += 1
        return orch

    results = await run_benchmark(cases, factory)

    assert len(results) == 2
    assert results[0].error_message is None
    assert results[1].error_message is not None
    assert results[1].f1 == pytest.approx(0.0)
