"""Shared pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture
def hmac_secret() -> bytes:
    """Deterministic secret for tests. NEVER reuse for real audit logs."""
    return b"test-secret-32-bytes-of-entropy-yes"


@pytest.fixture
def session_id() -> str:
    return "session-test-0001"
