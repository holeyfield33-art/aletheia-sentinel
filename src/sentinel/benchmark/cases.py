"""Benchmark case definitions.

A Case bundles the ground-truth expected findings for one investigation
scenario with the paths to the evidence artefacts the agent would examine.
Evidence paths are never committed to git; the fixtures reference hypothetical
paths used only for demo and documentation purposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExpectedFinding:
    """A single finding the agent is expected to discover.

    ``type`` is a logical category (e.g. "process", "connection",
    "amcache_entry"). ``key_fields`` are matched against the tool result
    payload: substring for string values, exact for numeric values.
    """

    type: str
    key_fields: dict[str, str] = field(default_factory=dict)


@dataclass
class Case:
    """One benchmark scenario with ground-truth expected findings."""

    case_id: str
    description: str
    expected_findings: list[ExpectedFinding] = field(default_factory=list)
    evidence_paths: dict[str, Path] = field(default_factory=dict)
