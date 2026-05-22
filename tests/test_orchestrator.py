"""Tests for the multi-agent orchestrator.

These tests validate hackathon judging criterion #1 (autonomous execution
quality): can the orchestrator self-correct, terminate cleanly, and never
spiral? They use mock agents so the loop behaviour is deterministic and
isolated from any LLM calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from sentinel.agents.orchestrator import (
    NitpickerReview,
    Orchestrator,
    OrchestratorConfig,
    ScoutDecision,
    SessionState,
    SpectralHealth,
    StopReason,
)
from sentinel.audit.receipts import ReceiptChain
from sentinel.spectral.gate import FixedSpectralGate
from sentinel.tools.base import ToolResult, ToolStatus

# ---------- Mock agents ----------


@dataclass
class ScriptedScout:
    """Replays a fixed list of decisions, looping the last one if exhausted."""

    decisions: list[ScoutDecision] = field(default_factory=list)
    calls: int = 0

    async def decide(self, state: SessionState) -> ScoutDecision:
        if self.calls < len(self.decisions):
            decision = self.decisions[self.calls]
        else:
            # If the script runs out, keep returning the last decision. Useful
            # for testing iteration caps with a non-terminal scout.
            decision = self.decisions[-1]
        self.calls += 1
        return decision


@dataclass
class FixedNitpicker:
    """Returns the same acceptance verdict for every result."""

    accept: bool = True

    async def review(self, state: SessionState, fresh: ToolResult) -> NitpickerReview:
        return NitpickerReview(accepted=self.accept, reasoning="fixed verdict")


@dataclass
class TemplateJudge:
    """Returns a simple summary report based on accumulated state."""

    async def synthesize(self, state: SessionState) -> str:
        return (
            f"case={state.case_id} findings={len(state.findings)} "
            f"rejected={len(state.rejected)} iterations={state.iteration}"
        )


def _ok_result(tool_name: str = "volatility.pslist") -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        status=ToolStatus.OK,
        payload={"pids": [1, 2, 3]},
    )


async def _ok_executor(tool_name: str, args: dict[str, object]) -> ToolResult:
    return _ok_result(tool_name)


# ---------- Tests ----------


async def test_scout_done_terminates_cleanly(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    scout = ScriptedScout(decisions=[ScoutDecision(done=True, reason="nothing to triage")])
    orch = Orchestrator(
        config=OrchestratorConfig(),
        scout=scout,
        nitpicker=FixedNitpicker(accept=True),
        judge=TemplateJudge(),
        gate=FixedSpectralGate(SpectralHealth.HEALTHY),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-001")

    assert result.stop_reason is StopReason.SCOUT_DONE
    assert result.iterations == 1
    assert result.chain_length == 0  # no tool executions because scout said done immediately


async def test_happy_path_records_findings_and_chains_receipts(
    hmac_secret: bytes, session_id: str
) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    scout = ScriptedScout(
        decisions=[
            ScoutDecision(done=False, reason="enumerate processes", tool_name="volatility.pslist"),
            ScoutDecision(done=False, reason="check amcache", tool_name="regripper.amcache"),
            ScoutDecision(done=True, reason="triage complete"),
        ]
    )
    orch = Orchestrator(
        config=OrchestratorConfig(),
        scout=scout,
        nitpicker=FixedNitpicker(accept=True),
        judge=TemplateJudge(),
        gate=FixedSpectralGate(SpectralHealth.HEALTHY),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-002")

    assert result.stop_reason is StopReason.SCOUT_DONE
    assert len(result.state.findings) == 2
    assert result.state.findings[0].tool_name == "volatility.pslist"
    assert result.state.findings[0].receipt_sequence == 0
    assert result.state.findings[1].receipt_sequence == 1
    chain.verify()  # the chain must validate post-run


async def test_max_iterations_cap_terminates(
    hmac_secret: bytes, session_id: str
) -> None:
    """A non-terminal scout must not run forever."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    scout = ScriptedScout(
        decisions=[
            ScoutDecision(done=False, reason="keep going", tool_name="volatility.pslist"),
        ]
    )
    orch = Orchestrator(
        config=OrchestratorConfig(max_iterations=5),
        scout=scout,
        nitpicker=FixedNitpicker(accept=True),
        judge=TemplateJudge(),
        gate=FixedSpectralGate(SpectralHealth.HEALTHY),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-003")

    assert result.stop_reason is StopReason.MAX_ITERATIONS
    assert result.iterations == 5


async def test_consecutive_stressed_cap_terminates(
    hmac_secret: bytes, session_id: str
) -> None:
    """If the spectral gate keeps flagging STRESSED, abort the session."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    scout = ScriptedScout(
        decisions=[
            ScoutDecision(done=False, reason="t1", tool_name="volatility.pslist"),
        ]
    )
    orch = Orchestrator(
        config=OrchestratorConfig(max_consecutive_stressed=2, max_iterations=20),
        scout=scout,
        nitpicker=FixedNitpicker(accept=True),
        judge=TemplateJudge(),
        gate=FixedSpectralGate(SpectralHealth.STRESSED),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-004")

    assert result.stop_reason is StopReason.MAX_STRESSED
    assert len(result.state.findings) == 0
    assert len(result.state.rejected) == 2


async def test_nitpicker_rejection_routes_to_rejected_pile(
    hmac_secret: bytes, session_id: str
) -> None:
    """Findings the Nitpicker rejects must not appear in accepted findings."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    scout = ScriptedScout(
        decisions=[
            ScoutDecision(done=False, reason="t1", tool_name="volatility.pslist"),
            ScoutDecision(done=False, reason="t2", tool_name="regripper.amcache"),
            ScoutDecision(done=True, reason="done"),
        ]
    )
    orch = Orchestrator(
        config=OrchestratorConfig(max_consecutive_stressed=10),
        scout=scout,
        nitpicker=FixedNitpicker(accept=False),
        judge=TemplateJudge(),
        gate=FixedSpectralGate(SpectralHealth.HEALTHY),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-005")

    assert result.stop_reason is StopReason.SCOUT_DONE
    assert len(result.state.findings) == 0
    assert len(result.state.rejected) == 2


async def test_stressed_counter_resets_after_a_healthy_finding(
    hmac_secret: bytes, session_id: str
) -> None:
    """A run of STRESSED outputs followed by a HEALTHY one should not abort."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)

    class TwoStressedThenHealthy:
        """Gate that returns STRESSED twice, then HEALTHY for everything else."""

        def __init__(self) -> None:
            self.calls = 0

        async def evaluate(self, sample: str) -> SpectralHealth:
            self.calls += 1
            if self.calls <= 2:
                return SpectralHealth.STRESSED
            return SpectralHealth.HEALTHY

    scout = ScriptedScout(
        decisions=[
            ScoutDecision(done=False, reason="t1", tool_name="volatility.pslist"),
            ScoutDecision(done=False, reason="t2", tool_name="volatility.pslist"),
            ScoutDecision(done=False, reason="t3", tool_name="volatility.pslist"),
            ScoutDecision(done=True, reason="done"),
        ]
    )
    orch = Orchestrator(
        config=OrchestratorConfig(max_consecutive_stressed=3),
        scout=scout,
        nitpicker=FixedNitpicker(accept=True),
        judge=TemplateJudge(),
        gate=TwoStressedThenHealthy(),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-006")

    assert result.stop_reason is StopReason.SCOUT_DONE
    assert len(result.state.findings) == 1
    assert len(result.state.rejected) == 2


async def test_orchestrator_config_rejects_nonpositive_caps() -> None:
    with pytest.raises(ValueError):
        OrchestratorConfig(max_iterations=0)
    with pytest.raises(ValueError):
        OrchestratorConfig(max_consecutive_stressed=0)
    with pytest.raises(ValueError):
        OrchestratorConfig(max_wall_seconds=0)
