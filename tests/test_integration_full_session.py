"""Integration tests: full session end-to-end, wiring layer, and Claude agent classes.

The real Anthropic API is never called. anthropic.AsyncAnthropic is either
injected as a MagicMock or patched at import time so that messages.create
returns canned responses.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

from sentinel.agents.llm import ClaudeJudge, ClaudeNitpicker, ClaudeScout
from sentinel.agents.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    ScoutDecision,
    SessionState,
    SpectralHealth,
    StopReason,
)
from sentinel.agents.wiring import build_executor
from sentinel.audit.receipts import ReceiptChain
from sentinel.spectral.gate import FixedSpectralGate
from sentinel.tools.base import ToolResult, ToolStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _text_response(text: str) -> MagicMock:
    """Build a minimal mock anthropic.Message whose first block is a text block."""
    block = MagicMock()
    block.type = "text"
    block.text = text
    msg = MagicMock()
    msg.content = [block]
    return msg


def _mock_client(*responses: str) -> MagicMock:
    """Return a mock AsyncAnthropic client whose messages.create cycles through responses."""
    client = MagicMock()
    client.messages.create = AsyncMock(
        side_effect=[_text_response(r) for r in responses]
    )
    return client


async def _ok_executor(tool_name: str, args: dict[str, object]) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        status=ToolStatus.OK,
        payload={"mocked": True},
    )


# ---------------------------------------------------------------------------
# Test 1: full happy-path session with mocked Claude agents
# ---------------------------------------------------------------------------


async def test_happy_path_full_session_with_claude_agents(
    hmac_secret: bytes, session_id: str
) -> None:
    """3-tool investigation ending with scout done; chain must validate."""
    catalog = [{"name": "volatility.pslist", "description": "list procs"}]

    scout_1 = json.dumps(
        {
            "done": False,
            "reason": "enumerate processes",
            "tool_name": "volatility.pslist",
            "tool_args": {},
        }
    )
    scout_2 = json.dumps(
        {
            "done": False,
            "reason": "check network connections",
            "tool_name": "volatility.netscan",
            "tool_args": {},
        }
    )
    scout_3 = json.dumps(
        {
            "done": False,
            "reason": "check amcache",
            "tool_name": "regripper.amcache",
            "tool_args": {},
        }
    )
    scout_4 = json.dumps({"done": True, "reason": "triage complete", "tool_name": None})
    judge_report = (
        "## Executive Summary\nNo active threats.\n"
        "## Timeline\nN/A\n"
        "## Indicators of Compromise\nNone.\n"
        "## Recommended Containment\nNone.\n"
        "## Confidence Caveats\nNo rejected findings."
    )

    # Order: scout, nitpicker, scout, nitpicker, scout, nitpicker, scout, judge
    client = _mock_client(
        scout_1, "YES",
        scout_2, "YES",
        scout_3, "YES",
        scout_4,
        judge_report,
    )

    scout = ClaudeScout(client=client, tool_catalog=catalog)
    nitpicker = ClaudeNitpicker(client=client)
    judge = ClaudeJudge(client=client)

    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    orch = Orchestrator(
        config=OrchestratorConfig(max_iterations=20),
        scout=scout,
        nitpicker=nitpicker,
        judge=judge,
        gate=FixedSpectralGate(SpectralHealth.HEALTHY),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-int-001")

    assert result.stop_reason is StopReason.SCOUT_DONE
    assert len(result.state.findings) == 3
    assert result.report  # non-empty
    assert result.chain_length == 3
    chain.verify()  # receipt chain must be intact


# ---------------------------------------------------------------------------
# Test 2: spectral gate STRESSED trips the consecutive-stressed cap
# ---------------------------------------------------------------------------


async def test_stressed_gate_stops_session(hmac_secret: bytes, session_id: str) -> None:
    """FixedSpectralGate(STRESSED) should produce StopReason.MAX_STRESSED."""
    from dataclasses import dataclass, field

    @dataclass
    class AlwaysRunScout:
        calls: int = 0
        decisions: list[ScoutDecision] = field(default_factory=list)

        def __post_init__(self) -> None:
            self.decisions = [
                ScoutDecision(
                    done=False, reason="probe", tool_name="volatility.pslist"
                )
            ]

        async def decide(self, state: SessionState) -> ScoutDecision:
            self.calls += 1
            return self.decisions[0]

    @dataclass
    class AcceptAll:
        async def review(self, state: SessionState, fresh: ToolResult) -> bool:
            return True

    @dataclass
    class SimpleJudge:
        async def synthesize(self, state: SessionState) -> str:
            return "partial report"

    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    orch = Orchestrator(
        config=OrchestratorConfig(max_consecutive_stressed=2, max_iterations=20),
        scout=AlwaysRunScout(),
        nitpicker=AcceptAll(),
        judge=SimpleJudge(),
        gate=FixedSpectralGate(SpectralHealth.STRESSED),
        execute_tool=_ok_executor,
        chain=chain,
    )

    result = await orch.run("case-int-002")

    assert result.stop_reason is StopReason.MAX_STRESSED
    assert len(result.state.findings) == 0
    assert len(result.state.rejected) == 2


# ---------------------------------------------------------------------------
# Test 3: wiring layer unknown tool returns ToolStatus.ERROR
# ---------------------------------------------------------------------------


async def test_wiring_unknown_tool_returns_error() -> None:
    """build_executor with an unmapped tool name must return ERROR, not raise."""
    executor = build_executor(MagicMock())  # server arg unused in direct-dispatch path

    result = await executor("nonexistent.tool", {})

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert "nonexistent.tool" in result.error


# ---------------------------------------------------------------------------
# Test 4: ClaudeScout returns fallback on malformed JSON
# ---------------------------------------------------------------------------


async def test_claude_scout_malformed_json_returns_fallback() -> None:
    """If Claude returns unparseable JSON, decide() returns a non-terminal fallback."""
    client = _mock_client("this is not json at all ...")
    scout = ClaudeScout(client=client, tool_catalog=[])
    state = SessionState(case_id="case-int-003")

    decision = await scout.decide(state)

    assert decision.done is False
    assert decision.tool_name is None
    assert "malformed" in decision.reason


# ---------------------------------------------------------------------------
# Test 5: ClaudeNitpicker returns False on ambiguous / non-YES response
# ---------------------------------------------------------------------------


async def test_claude_nitpicker_ambiguous_response_returns_false() -> None:
    """Nitpicker returns False whenever the response is not a clear YES."""
    client = _mock_client("I am not sure about this one.")
    nitpicker = ClaudeNitpicker(client=client)
    state = SessionState(case_id="case-int-004")
    fresh = ToolResult(tool_name="volatility.pslist", status=ToolStatus.OK)

    accepted = await nitpicker.review(state, fresh)

    assert accepted is False


# ---------------------------------------------------------------------------
# Test 6: ClaudeNitpicker returns True on clear YES response
# ---------------------------------------------------------------------------


async def test_claude_nitpicker_yes_accepts_result() -> None:
    """Nitpicker returns True when Claude responds with YES."""
    client = _mock_client("YES")
    nitpicker = ClaudeNitpicker(client=client)
    state = SessionState(case_id="case-int-005")
    fresh = ToolResult(tool_name="volatility.pslist", status=ToolStatus.OK)

    accepted = await nitpicker.review(state, fresh)

    assert accepted is True


# ---------------------------------------------------------------------------
# Test 7: receipt chain validates after mocked API session
# ---------------------------------------------------------------------------


async def test_chain_validates_after_session(hmac_secret: bytes, session_id: str) -> None:
    """chain.verify() must not raise after any completed session."""
    scout_resp = json.dumps(
        {"done": False, "reason": "check", "tool_name": "volatility.pslist", "tool_args": {}}
    )
    done_resp = json.dumps({"done": True, "reason": "done", "tool_name": None})
    judge_resp = (
        "# Report\n\n## Executive Summary\nClean.\n"
        "## Timeline\n\n## Indicators of Compromise\n\n"
        "## Recommended Containment\n\n## Confidence Caveats\n"
    )

    client = _mock_client(scout_resp, "YES", done_resp, judge_resp)
    catalog: list[dict[str, object]] = []
    scout = ClaudeScout(client=client, tool_catalog=catalog)
    nitpicker = ClaudeNitpicker(client=client)
    judge = ClaudeJudge(client=client)

    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    orch = Orchestrator(
        config=OrchestratorConfig(max_iterations=10),
        scout=scout,
        nitpicker=nitpicker,
        judge=judge,
        gate=FixedSpectralGate(SpectralHealth.HEALTHY),
        execute_tool=_ok_executor,
        chain=chain,
    )

    await orch.run("case-int-006")
    chain.verify()  # must not raise


# ---------------------------------------------------------------------------
# Test 8: wiring known tools (mocked at subprocess level) return valid results
# ---------------------------------------------------------------------------


async def test_wiring_known_tools_exist_in_dispatch() -> None:
    """All five canonical tool names must be present in the dispatch table."""
    from sentinel.agents.wiring import _DISPATCH

    expected = {
        "volatility.pslist",
        "volatility.netscan",
        "regripper.amcache",
        "plaso.log2timeline",
        "evtxecmd.parse_security",
    }
    assert set(_DISPATCH.keys()) == expected


# ---------------------------------------------------------------------------
# Test 9: ClaudeJudge returns non-empty string even on API error
# ---------------------------------------------------------------------------


async def test_claude_judge_api_error_returns_message() -> None:
    """Judge must return a string (not raise) when the API fails."""
    import anthropic

    client = MagicMock()
    client.messages.create = AsyncMock(
        side_effect=anthropic.APIConnectionError(request=MagicMock())
    )
    judge = ClaudeJudge(client=client)
    state = SessionState(case_id="case-int-007")

    report = await judge.synthesize(state)

    assert isinstance(report, str)
    assert report  # non-empty error message


# ---------------------------------------------------------------------------
# Test 10: ClaudeScout handles APIConnectionError gracefully
# ---------------------------------------------------------------------------


async def test_claude_scout_connection_error_returns_fallback() -> None:
    """Scout must return a non-terminal decision (not raise) on network error."""
    import anthropic

    client = MagicMock()
    client.messages.create = AsyncMock(
        side_effect=anthropic.APIConnectionError(request=MagicMock())
    )
    scout = ClaudeScout(client=client, tool_catalog=[])
    state = SessionState(case_id="case-int-008")

    decision = await scout.decide(state)

    assert decision.done is False
    assert decision.tool_name is None
    assert "connection error" in decision.reason
