"""Prompt-content guards for the evidence-discipline rules.

These pin the prompt-layer behavior that keeps the agent from asserting
malice without evidence (Scout) and from letting an unverified process drive
the compromise verdict (Judge), plus the exact Judge report sections that the
orchestrator/integration tests parse. The behavior itself is exercised on real
images; these guard the contract so a future edit cannot silently drop it.
"""

from __future__ import annotations

from sentinel.agents.llm import _JUDGE_SYSTEM, _NITPICKER_SYSTEM, _SCOUT_SYSTEM

_JUDGE_SECTIONS = (
    "## Executive Summary",
    "## Timeline",
    "## Indicators of Compromise",
    "## Recommended Containment",
    "## Confidence Caveats",
)


def test_scout_requires_evidence_based_identity() -> None:
    """Scout must demand identity verification, not name+port heuristics."""
    assert "identity verified" in _SCOUT_SYSTEM
    assert "identity-checked" in _SCOUT_SYSTEM
    assert "not by its name and port alone" in _SCOUT_SYSTEM
    # The retired "least-invasive" heuristic must not creep back in.
    assert "least-invasive" not in _SCOUT_SYSTEM


def test_judge_enforces_evidence_bounded_classification() -> None:
    """Judge must hold unverified flags as suspicious pending verification."""
    assert "suspicious pending verification" in _JUDGE_SYSTEM
    assert "A process name plus a listening port is NOT sufficient" in _JUDGE_SYSTEM
    assert "do not let overall compromise confidence be driven" in _JUDGE_SYSTEM


def test_judge_does_not_soften_evidenced_implants() -> None:
    """The rule narrows unverified flags only; evidenced malice stays asserted."""
    assert "MUST be reported as malicious" in _JUDGE_SYSTEM
    assert "it does not soften" in _JUDGE_SYSTEM


def test_judge_report_sections_are_byte_identical() -> None:
    """Section headers are parsed downstream; they must not drift."""
    for section in _JUDGE_SECTIONS:
        assert section in _JUDGE_SYSTEM


def test_nitpicker_is_consistency_only() -> None:
    """Nitpicker is a consistency reviewer, not an evidence-grounding gate."""
    assert "consistency" in _NITPICKER_SYSTEM.lower()
