"""Base types for forensic tool wrappers.

Every SIFT tool exposed through the MCP server returns a ToolResult. This is
the only object the LLM ever sees from a tool execution -- raw stdout from
volatility, plaso, etc. is parsed into structured fields *server-side* before
crossing the trust boundary. That keeps the agent reasoning over typed data
and prevents context-window overload from massive text dumps.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity of a forensic finding.

    Strings (not ints) so the LLM can reason about them directly without a
    legend in the prompt.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolStatus(StrEnum):
    """Outcome of one tool execution."""

    OK = "ok"
    PARTIAL = "partial"
    """Tool ran but some output was unparseable or evidence was incomplete."""

    ERROR = "error"
    """Tool failed to execute. `error` field carries the human-readable cause."""


class ToolResult(BaseModel):
    """Result of a single forensic tool execution.

    The ``payload`` field is intentionally untyped at this layer (dict[str, Any])
    so the outer envelope can be shared across every tool. Individual tool
    modules define their own Pydantic models for the payload contents and
    validate at the call site.

    ``receipt_sequence`` is populated by the orchestrator *after* the receipt
    chain records the execution. Tools themselves do not see the chain.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(description="Canonical tool identifier, e.g. 'volatility.pslist'")
    status: ToolStatus
    payload: dict[str, Any] | None = Field(
        default=None,
        description="Parsed result body. Schema is tool-specific.",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Non-fatal parser warnings or analyst hints.",
    )
    error: str | None = Field(
        default=None,
        description="Human-readable error if status is ERROR.",
    )
    receipt_sequence: int | None = Field(
        default=None,
        description=(
            "Index into the session receipt chain. Populated by the orchestrator "
            "after this result has been hashed into the chain."
        ),
    )

    def to_canonical_bytes(self) -> bytes:
        """Serialize for hashing into the receipt chain.

        Excludes ``receipt_sequence`` (populated *after* hashing) so the hash
        is stable. Sorted keys so the canonical form is reproducible across
        runs and across Python versions.
        """
        body = self.model_dump(exclude={"receipt_sequence"}, mode="json")
        return json.dumps(body, sort_keys=True).encode("utf-8")

    def with_receipt(self, sequence: int) -> ToolResult:
        """Return a copy with ``receipt_sequence`` set."""
        return self.model_copy(update={"receipt_sequence": sequence})
