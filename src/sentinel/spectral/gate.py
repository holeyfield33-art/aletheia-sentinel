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
        endpoint: str = "https://geometric-brain-mcp.onrender.com/mcp",
        timeout_seconds: float = 10.0,
    ) -> None:
        self._endpoint = endpoint
        self._timeout = timeout_seconds

    async def evaluate(self, sample: str) -> SpectralHealth:
        if not sample:
            # Empty sample is statistically meaningless; treat as CAUTION
            # rather than HEALTHY so the orchestrator stays conservative.
            return SpectralHealth.CAUTION

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "brain_health_check",
                "arguments": {"text": sample},
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(self._endpoint, json=payload)
                response.raise_for_status()
                body: dict[str, object] = response.json()
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


def _extract_r_ratio(body: dict[str, object]) -> float:
    """Pull the r-ratio out of a brain_health_check response.

    Geometric Brain returns r_ratio either at the top level or nested under
    the JSON-RPC ``result`` key. If the schema shifts we fail loud rather than
    silently treating drift as HEALTHY.
    """
    value = body.get("r_ratio")
    if value is None:
        result = body.get("result")
        if isinstance(result, dict):
            value = result.get("r_ratio")
    if not isinstance(value, (int, float)):
        raise ValueError(
            f"brain_health_check response missing numeric r_ratio: {body!r}"
        )
    return float(value)
