"""Unit tests for the spectral gate.

Verifies: MCP JSON-RPC happy path, all three network-error paths return
CAUTION, and the classify() threshold boundaries.  No real HTTP calls are
made -- httpx.AsyncClient is mocked at the module level.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sentinel.agents.orchestrator import SpectralHealth
from sentinel.spectral.gate import RemoteSpectralGate, classify

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(response_json: dict[str, object] | None = None) -> MagicMock:
    """Return an AsyncClient mock whose post() returns a prepared response."""
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=response_json or {})

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


# ---------------------------------------------------------------------------
# Network error paths -- all must return CAUTION
# ---------------------------------------------------------------------------


async def test_connect_error_returns_caution() -> None:
    """ConnectError (DNS failure, connection refused) must degrade to CAUTION."""
    gate = RemoteSpectralGate()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("some reasoning text")

    assert result is SpectralHealth.CAUTION


async def test_timeout_returns_caution() -> None:
    """TimeoutException must degrade to CAUTION, not propagate."""
    gate = RemoteSpectralGate()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("some reasoning text")

    assert result is SpectralHealth.CAUTION


async def test_http_status_error_returns_caution() -> None:
    """HTTP 5xx response must degrade to CAUTION."""
    gate = RemoteSpectralGate()

    mock_response = MagicMock()
    mock_response.status_code = 503
    mock_response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "503 Service Unavailable",
            request=MagicMock(),
            response=mock_response,
        )
    )

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("some reasoning text")

    assert result is SpectralHealth.CAUTION


# ---------------------------------------------------------------------------
# Happy path -- correct JSON-RPC response shapes
# ---------------------------------------------------------------------------


async def test_healthy_response_from_nested_result() -> None:
    """r_ratio nested in JSON-RPC 'result' key above HEALTHY threshold => HEALTHY."""
    gate = RemoteSpectralGate()
    body: dict[str, object] = {"jsonrpc": "2.0", "id": 1, "result": {"r_ratio": 0.60}}
    mock_client = _make_mock_client(body)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("coherent reasoning sample")

    assert result is SpectralHealth.HEALTHY


async def test_caution_response_from_nested_result() -> None:
    """r_ratio in CAUTION band (>= 0.40 and < 0.55) => CAUTION."""
    gate = RemoteSpectralGate()
    body: dict[str, object] = {"jsonrpc": "2.0", "id": 1, "result": {"r_ratio": 0.45}}
    mock_client = _make_mock_client(body)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("slightly drifting reasoning")

    assert result is SpectralHealth.CAUTION


async def test_stressed_response_from_nested_result() -> None:
    """r_ratio below CAUTION threshold => STRESSED."""
    gate = RemoteSpectralGate()
    body: dict[str, object] = {"jsonrpc": "2.0", "id": 1, "result": {"r_ratio": 0.30}}
    mock_client = _make_mock_client(body)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("incoherent reasoning sample")

    assert result is SpectralHealth.STRESSED


# ---------------------------------------------------------------------------
# classify() threshold boundaries (pure function, no mocking needed)
# ---------------------------------------------------------------------------


def test_classify_at_healthy_threshold() -> None:
    assert classify(0.55) is SpectralHealth.HEALTHY


def test_classify_just_below_healthy() -> None:
    assert classify(0.549) is SpectralHealth.CAUTION


def test_classify_at_caution_threshold() -> None:
    assert classify(0.40) is SpectralHealth.CAUTION


def test_classify_just_below_caution() -> None:
    assert classify(0.399) is SpectralHealth.STRESSED


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


async def test_empty_sample_returns_caution() -> None:
    """An empty string sample must return CAUTION without hitting the network."""
    gate = RemoteSpectralGate()
    result = await gate.evaluate("")
    assert result is SpectralHealth.CAUTION


async def test_sends_correct_jsonrpc_payload() -> None:
    """The POST body must use JSON-RPC 2.0 with method=tools/call."""
    gate = RemoteSpectralGate()
    body: dict[str, object] = {"result": {"r_ratio": 0.6}}
    mock_client = _make_mock_client(body)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        await gate.evaluate("test reasoning")

    call_kwargs = mock_client.post.call_args
    assert call_kwargs is not None
    posted_json: dict[str, object] = call_kwargs.kwargs.get("json") or call_kwargs.args[1]
    assert posted_json["method"] == "tools/call"
    assert posted_json["jsonrpc"] == "2.0"
    params = posted_json["params"]
    assert isinstance(params, dict)
    assert params["name"] == "brain_health_check"


async def test_top_level_r_ratio_also_parsed() -> None:
    """r_ratio at top level (not nested in result) must also be accepted."""
    gate = RemoteSpectralGate()
    body: dict[str, object] = {"r_ratio": 0.57}
    mock_client = _make_mock_client(body)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        result = await gate.evaluate("top level ratio test")

    assert result is SpectralHealth.HEALTHY


async def test_missing_r_ratio_raises_value_error() -> None:
    """A response without r_ratio must raise ValueError (not silently return HEALTHY)."""
    gate = RemoteSpectralGate()
    body: dict[str, object] = {"result": {"some_other_field": 1}}
    mock_client = _make_mock_client(body)

    with patch("sentinel.spectral.gate.httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(ValueError, match="r_ratio"):
            await gate.evaluate("test")
