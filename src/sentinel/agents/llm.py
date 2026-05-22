"""Claude-backed implementations of the Scout, Nitpicker, and Judge protocols.

All three classes use AsyncAnthropic. API key is expected in ANTHROPIC_API_KEY.
Exception handling is narrow: APIConnectionError (network) is caught separately
from APIError (HTTP/API-level), per the CLAUDE.md rule against broad except.
"""

from __future__ import annotations

import json
import os
from typing import Any

import anthropic
from anthropic.types import Message

from sentinel.agents.orchestrator import ScoutDecision, SessionState
from sentinel.tools.base import ToolResult

_MODEL = "claude-opus-4-7"

_SCOUT_SYSTEM = (
    "You are a forensic triage assistant. You will be given information about an "
    "active investigation: the case ID, iteration count, findings collected so far, "
    "and the available forensic tools. "
    "Your job is to decide the single next least-invasive tool call that will most "
    "advance the investigation, or to declare the investigation complete. "
    "You MUST respond with a single JSON object and nothing else. "
    'Schema: {"done": bool, "reason": string, "tool_name": string|null, '
    '"tool_args": object}. '
    "Set done=true and tool_name=null when no further tool calls are needed."
)

_NITPICKER_SYSTEM = (
    "You are a forensic consistency reviewer. You will be given a fresh tool result "
    "and the set of findings already accepted in this investigation. "
    "Decide whether the fresh result is consistent with the existing findings. "
    "Respond with exactly one word: YES if consistent, NO if inconsistent or ambiguous."
)

_JUDGE_SYSTEM = (
    "You are a senior incident responder. You will be given all accepted forensic "
    "findings and any rejected findings from an investigation session. "
    "Produce a markdown incident report with EXACTLY these sections: "
    "## Executive Summary, ## Timeline, ## Indicators of Compromise, "
    "## Recommended Containment, ## Confidence Caveats. "
    "Cite rejected findings under Confidence Caveats to explain uncertainty."
)


def make_client() -> anthropic.AsyncAnthropic:
    """Construct AsyncAnthropic, failing fast if the API key is absent."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. "
            "Export your Anthropic API key before running: "
            "export ANTHROPIC_API_KEY=sk-ant-..."
        )
    return anthropic.AsyncAnthropic(api_key=api_key)


def _extract_text(response: Message) -> str:
    """Pull the first text block out of a Claude response."""
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


class ClaudeScout:
    """Scout backed by Claude. Plans the next forensic tool call."""

    def __init__(
        self,
        *,
        client: anthropic.AsyncAnthropic,
        tool_catalog: list[dict[str, Any]],
    ) -> None:
        self._client = client
        self._catalog = tool_catalog

    async def decide(self, state: SessionState) -> ScoutDecision:
        findings_json = json.dumps(
            [f.model_dump(mode="json") for f in state.findings],
            separators=(",", ":"),
        )
        tools_json = json.dumps(self._catalog, indent=2)
        prompt = (
            f"Case: {state.case_id}\n"
            f"Iteration: {state.iteration}\n"
            f"Accepted findings so far ({len(state.findings)}): {findings_json}\n\n"
            f"Available tools:\n{tools_json}\n\n"
            "What is the next step? Reply with JSON only."
        )
        try:
            response = await self._client.messages.create(
                model=_MODEL,
                max_tokens=512,
                system=_SCOUT_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIConnectionError as exc:
            return ScoutDecision(
                done=False, reason=f"connection error: {exc}", tool_name=None
            )
        except anthropic.APIError as exc:
            return ScoutDecision(done=False, reason=f"api error: {exc}", tool_name=None)

        text = _extract_text(response)
        try:
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                raise ValueError("expected JSON object")
            data: dict[str, Any] = parsed
            done = bool(data.get("done", False))
            reason = str(data.get("reason", ""))
            tool_name_raw = data.get("tool_name")
            tool_name = str(tool_name_raw) if tool_name_raw is not None else None
            raw_args = data.get("tool_args", {})
            tool_args: dict[str, object] = raw_args if isinstance(raw_args, dict) else {}
            return ScoutDecision(
                done=done, reason=reason, tool_name=tool_name, tool_args=tool_args
            )
        except (json.JSONDecodeError, ValueError):
            return ScoutDecision(
                done=False, reason="malformed scout response", tool_name=None
            )


class ClaudeNitpicker:
    """Nitpicker backed by Claude. Reviews each fresh result for consistency."""

    def __init__(self, *, client: anthropic.AsyncAnthropic) -> None:
        self._client = client

    async def review(self, state: SessionState, fresh: ToolResult) -> bool:
        fresh_json = json.dumps(fresh.model_dump(mode="json"), indent=2)
        findings_json = json.dumps(
            [f.model_dump(mode="json") for f in state.findings],
            separators=(",", ":"),
        )
        prompt = (
            f"Fresh result:\n{fresh_json}\n\n"
            f"Existing accepted findings: {findings_json}\n\n"
            "Is the fresh result consistent with the existing findings? Reply YES or NO."
        )
        try:
            response = await self._client.messages.create(
                model=_MODEL,
                max_tokens=16,
                system=_NITPICKER_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIConnectionError:
            return False
        except anthropic.APIError:
            return False

        text = _extract_text(response).strip().upper()
        return text.startswith("YES")


class ClaudeJudge:
    """Judge backed by Claude. Synthesizes accepted findings into a final report."""

    def __init__(self, *, client: anthropic.AsyncAnthropic) -> None:
        self._client = client

    async def synthesize(self, state: SessionState) -> str:
        findings_json = json.dumps(
            [f.model_dump(mode="json") for f in state.findings],
            indent=2,
        )
        rejected_json = json.dumps(
            [f.model_dump(mode="json") for f in state.rejected],
            indent=2,
        )
        prompt = (
            f"Case ID: {state.case_id}\n"
            f"Iterations completed: {state.iteration}\n\n"
            f"Accepted findings ({len(state.findings)}):\n{findings_json}\n\n"
            f"Rejected findings ({len(state.rejected)}):\n{rejected_json}\n\n"
            "Produce the incident report now."
        )
        try:
            response = await self._client.messages.create(
                model=_MODEL,
                max_tokens=2048,
                system=_JUDGE_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIConnectionError as exc:
            return f"Report unavailable (connection error): {exc}"
        except anthropic.APIError as exc:
            return f"Report unavailable (api error): {exc}"

        return _extract_text(response)
