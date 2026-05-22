"""Multi-agent orchestrator for autonomous incident response.

The orchestrator owns the receipt chain, the iteration cap, and the
termination logic. Agents (Scout, Nitpicker, Judge) are pluggable Protocols --
the orchestrator does not know or care which LLM is behind each role.

Termination is the hardest part of multi-agent systems. The hackathon brief
explicitly warns: "agent loops can get stuck in infinite conversational
spirals without careful termination conditions." This module enforces three
caps, any one of which ends the session with a partial report:

    1. max_iterations              hard ceiling on Scout decisions
    2. max_consecutive_stressed    spectral failures in a row before aborting
    3. max_wall_seconds            real-time deadline
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from sentinel.audit.receipts import ReceiptChain
from sentinel.tools.base import ToolResult


class StopReason(StrEnum):
    """Why a session ended."""

    SCOUT_DONE = "scout_done"
    MAX_ITERATIONS = "max_iterations"
    MAX_STRESSED = "max_stressed"
    WALL_TIMEOUT = "wall_timeout"


class SpectralHealth(StrEnum):
    """Classification returned by the spectral gate.

    Matches the regime monitor in aletheia-trader: HEALTHY when GUE spacing
    ratio is near 0.6, CAUTION when it drifts, STRESSED when reasoning is
    statistically inconsistent with a coherent attention manifold.
    """

    HEALTHY = "healthy"
    CAUTION = "caution"
    STRESSED = "stressed"


@dataclass(frozen=True)
class OrchestratorConfig:
    """Hard caps on a session. All three must be positive.

    Defaults aim at a 30-minute triage session with up to 50 tool calls and
    tolerance for 3 consecutive hallucination-flagged results before giving up.
    """

    max_iterations: int = 50
    max_consecutive_stressed: int = 3
    max_wall_seconds: float = 1800.0

    def __post_init__(self) -> None:
        if self.max_iterations <= 0:
            raise ValueError("max_iterations must be positive")
        if self.max_consecutive_stressed <= 0:
            raise ValueError("max_consecutive_stressed must be positive")
        if self.max_wall_seconds <= 0:
            raise ValueError("max_wall_seconds must be positive")


@dataclass
class SessionState:
    """Mutable state passed between agents during a session.

    Findings accrue here. The Judge reads this at the end to produce the
    final report. Agents may read the whole history but only the orchestrator
    is allowed to mutate it.
    """

    case_id: str
    iteration: int = 0
    consecutive_stressed: int = 0
    findings: list[ToolResult] = field(default_factory=list)
    rejected: list[ToolResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at


@dataclass(frozen=True)
class ScoutDecision:
    """A Scout's next move.

    If ``done`` is True, the investigation is complete and the orchestrator
    proceeds to the Judge. Otherwise ``tool_name`` and ``tool_args`` describe
    the next MCP call to execute. ``reason`` is logged for the audit trail.
    """

    done: bool
    reason: str
    tool_name: str | None = None
    tool_args: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class ScoutAgent(Protocol):
    """Plans the next forensic tool call."""

    async def decide(self, state: SessionState) -> ScoutDecision: ...


@runtime_checkable
class NitpickerAgent(Protocol):
    """Reviews a fresh tool result against accumulated findings.

    Returns True if the result is consistent with the existing finding set
    (accept), False if a discrepancy was found and the result should be
    re-investigated.
    """

    async def review(self, state: SessionState, fresh: ToolResult) -> bool: ...


@runtime_checkable
class JudgeAgent(Protocol):
    """Synthesizes the final report from accepted findings."""

    async def synthesize(self, state: SessionState) -> str: ...


@runtime_checkable
class SpectralGate(Protocol):
    """Returns the GUE-spacing health of a reasoning sample."""

    async def evaluate(self, sample: str) -> SpectralHealth: ...


ToolExecutor = Callable[[str, dict[str, object]], Awaitable[ToolResult]]
"""Async callable that turns (tool_name, args) into a ToolResult.

Production wiring goes through the MCP server. Tests inject a fake.
"""


@dataclass(frozen=True)
class SessionResult:
    """Final outcome of a session."""

    stop_reason: StopReason
    iterations: int
    report: str
    state: SessionState
    chain_length: int


class Orchestrator:
    """Runs one investigation session end to end."""

    def __init__(
        self,
        *,
        config: OrchestratorConfig,
        scout: ScoutAgent,
        nitpicker: NitpickerAgent,
        judge: JudgeAgent,
        gate: SpectralGate,
        execute_tool: ToolExecutor,
        chain: ReceiptChain,
    ) -> None:
        self._config = config
        self._scout = scout
        self._nitpicker = nitpicker
        self._judge = judge
        self._gate = gate
        self._execute_tool = execute_tool
        self._chain = chain

    async def run(self, case_id: str) -> SessionResult:
        state = SessionState(case_id=case_id)
        stop_reason: StopReason | None = None

        while stop_reason is None:
            # Termination checks come first so a session can never start a
            # new iteration past its cap.
            if state.iteration >= self._config.max_iterations:
                stop_reason = StopReason.MAX_ITERATIONS
                break
            if state.elapsed() >= self._config.max_wall_seconds:
                stop_reason = StopReason.WALL_TIMEOUT
                break
            if state.consecutive_stressed >= self._config.max_consecutive_stressed:
                stop_reason = StopReason.MAX_STRESSED
                break

            decision = await self._scout.decide(state)
            state.iteration += 1

            if decision.done:
                stop_reason = StopReason.SCOUT_DONE
                break

            if decision.tool_name is None:
                # Scout returned a non-terminal decision with no tool. Treat
                # as a confused cycle so we don't loop forever on bad output.
                state.consecutive_stressed += 1
                continue

            result = await self._execute_tool(decision.tool_name, decision.tool_args)
            receipt = self._chain.append(
                tool_name=decision.tool_name,
                tool_input=_canonical_args(decision.tool_args),
                tool_output=result.to_canonical_bytes(),
            )
            result_with_seq = result.with_receipt(receipt.sequence)

            accepted = await self._nitpicker.review(state, result_with_seq)
            health = await self._gate.evaluate(_review_sample(result_with_seq))

            if health is SpectralHealth.STRESSED or not accepted:
                state.rejected.append(result_with_seq)
                state.consecutive_stressed += 1
                continue

            state.consecutive_stressed = 0
            state.findings.append(result_with_seq)

        # stop_reason is guaranteed non-None by the loop's exit condition
        assert stop_reason is not None
        report = await self._judge.synthesize(state)
        return SessionResult(
            stop_reason=stop_reason,
            iterations=state.iteration,
            report=report,
            state=state,
            chain_length=self._chain.length,
        )


def _canonical_args(args: dict[str, object]) -> bytes:
    """Canonical JSON encoding of Scout's tool args for the receipt chain."""
    return json.dumps(args, sort_keys=True, default=str).encode("utf-8")


def _review_sample(result: ToolResult) -> str:
    """Extract a reasoning sample for the spectral gate.

    Today we feed the canonical JSON of the tool result. A future iteration
    will feed the Nitpicker's natural-language reasoning instead -- that's the
    actual surface where hallucinations manifest. The gate signature is
    forward-compatible: still takes a string.
    """
    return result.to_canonical_bytes().decode("utf-8", errors="replace")
