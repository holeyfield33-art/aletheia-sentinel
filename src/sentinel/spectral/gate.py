"""Spectral health gate.

Calls the Geometric Brain MCP server to compute the GUE eigenvalue-spacing
health of a reasoning sample. The remote endpoint is wired up in week 3 of
the sprint; this module currently exposes the interface plus a deterministic
fixture used by tests.

Validated finding from prior Geometric Brain work: text-proxy health-check
scores cluster around r = 0.41-0.43 for all English prose regardless of
content. The HEALTHY threshold here is calibrated against that baseline.
The manifold-audit endpoint (with real model eigenvalues) is the diagnostic
path with real value, and that is what production wiring will use.
"""

from __future__ import annotations

import json
import logging

import httpx

from sentinel.agents.orchestrator import SpectralHealth

log = logging.getLogger(__name__)

# Calibration thresholds from Geometric Brain validation runs.
# Tune as we collect more data during the sprint.
HEALTHY_MIN_R = 0.55
CAUTION_MIN_R = 0.40


class RemoteSpectralGate:
    """Production spectral gate: calls geometric-brain-mcp.

    Sends MCP JSON-RPC requests to the brain_health_check tool and maps the
    returned r_ratio to a SpectralHealth classification.

    Network failures return CAUTION rather than HEALTHY or STRESSED. This is a
    deliberate design choice: when the remote service is unavailable we degrade
    gracefully by signalling reduced confidence without blocking the agent.
    STRESSED would incorrectly penalise the session for an infrastructure
    problem; HEALTHY would suppress the confidence warning entirely. CAUTION
    means "unknown health -- proceed conservatively."
    """

    def __init__(
        self,
        *,
        endpoint: str = "https://geometric-brain-mcp.onrender.com/mcp/",
        timeout_seconds: float = 10.0,
    ) -> None:
        self._endpoint = endpoint
        self._timeout = timeout_seconds

    async def evaluate(self, sample: str) -> SpectralHealth:
        if not sample:
            # Empty sample is statistically meaningless; treat as CAUTION
            # rather than HEALTHY so the orchestrator stays conservative.
            return SpectralHealth.CAUTION

        # Geometric Brain runs MCP streamable-HTTP, which requires a session
        # handshake before tools/call: initialize -> capture the
        # mcp-session-id response header -> notifications/initialized ->
        # tools/call with that header. A bare tools/call POST is rejected
        # with "Missing session ID". Arguments are wrapped in "params" to
        # match the server's brain_health_check schema.
        init_payload = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aletheia-sentinel", "version": "0.1.0"},
            },
        }
        call_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "brain_health_check",
                "arguments": {"params": {"text": sample}},
            },
        }

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            ) as client:
                init = await client.post(self._endpoint, json=init_payload)
                init.raise_for_status()
                session_id = init.headers.get("mcp-session-id")
                session = {"mcp-session-id": session_id} if session_id else {}
                await client.post(
                    self._endpoint,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers=session,
                )
                response = await client.post(
                    self._endpoint, json=call_payload, headers=session
                )
                response.raise_for_status()
                body: dict[str, object] = _parse_mcp_body(response)
        except httpx.ConnectError as exc:
            log.warning("spectral gate connect error (returning CAUTION): %s", exc)
            return SpectralHealth.CAUTION
        except httpx.TimeoutException as exc:
            log.warning("spectral gate timeout (returning CAUTION): %s", exc)
            return SpectralHealth.CAUTION
        except httpx.HTTPStatusError as exc:
            log.warning(
                "spectral gate HTTP %d (returning CAUTION): %s",
                exc.response.status_code,
                exc,
            )
            return SpectralHealth.CAUTION

        r_ratio = _extract_r_ratio(body)
        return classify(r_ratio)


class FixedSpectralGate:
    """Test fixture: returns a configured health value for every call.

    Used by unit tests to make orchestrator behaviour deterministic without
    a network dependency.
    """

    def __init__(self, verdict: SpectralHealth) -> None:
        self._verdict = verdict

    async def evaluate(self, sample: str) -> SpectralHealth:
        return self._verdict


def classify(r_ratio: float) -> SpectralHealth:
    """Map a GUE spacing ratio to a health classification.

    Pure function so the thresholds can be unit-tested.
    """
    if r_ratio >= HEALTHY_MIN_R:
        return SpectralHealth.HEALTHY
    if r_ratio >= CAUTION_MIN_R:
        return SpectralHealth.CAUTION
    return SpectralHealth.STRESSED


def _parse_mcp_body(response: httpx.Response) -> dict[str, object]:
    """Decode an MCP streamable-HTTP response.

    The server may answer with plain JSON or a text/event-stream body whose
    ``data:`` line carries the JSON-RPC message. Both decode to the same dict.
    """
    content_type = response.headers.get("content-type", "")
    if isinstance(content_type, str) and "text/event-stream" in content_type:
        for line in response.text.splitlines():
            if line.startswith("data:"):
                parsed: dict[str, object] = json.loads(line[len("data:"):].strip())
                return parsed
        raise ValueError("event-stream response contained no data line")
    body: dict[str, object] = response.json()
    return body


def _extract_r_ratio(body: dict[str, object]) -> float:
    """Pull the r-ratio out of a brain_health_check response.

    Geometric Brain returns r_ratio at the top level, nested under the
    JSON-RPC ``result`` key, or (live server, schema 1.1.x) as a JSON string
    inside ``result.content[0].text``. If the schema shifts we fail loud
    rather than silently treating drift as HEALTHY.
    """
    value = body.get("r_ratio")
    if value is None:
        result = body.get("result")
        if isinstance(result, dict):
            value = result.get("r_ratio")
            if value is None:
                content = result.get("content")
                if isinstance(content, list) and content:
                    first = content[0]
                    if isinstance(first, dict) and isinstance(first.get("text"), str):
                        inner = json.loads(first["text"])
                        if isinstance(inner, dict):
                            value = inner.get("r_ratio")
    if not isinstance(value, (int, float)):
        raise ValueError(
            f"brain_health_check response missing numeric r_ratio: {body!r}"
        )
    return float(value)
