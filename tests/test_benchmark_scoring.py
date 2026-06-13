"""Tests for benchmark scoring logic.

Covers: perfect match, zero overlap, partial match, empty-expected and
empty-reported edge cases, substring string matching, and exact numeric
matching.
"""

from __future__ import annotations

from typing import Any

import pytest

from sentinel.benchmark.cases import ExpectedFinding
from sentinel.benchmark.scoring import compute_score
from sentinel.tools.base import ToolResult, ToolStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(type_: str, **fields: str) -> ExpectedFinding:
    return ExpectedFinding(type=type_, key_fields=dict(fields))


def _result(tool_name: str, **payload: Any) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        status=ToolStatus.OK,
        payload=dict(payload) if payload else None,
    )


# ---------------------------------------------------------------------------
# Test 1: perfect match
# ---------------------------------------------------------------------------


def test_perfect_match_gives_full_scores() -> None:
    """All expected findings present, no spurious => P=R=F1=1.0."""
    expected = [_finding("process", name="mimikatz.exe", pid="1234")]
    reported = [_result("volatility.pslist", name="mimikatz.exe", pid=1234)]

    result = compute_score(expected, reported)

    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(1.0)
    assert result.f1 == pytest.approx(1.0)
    assert len(result.matched) == 1
    assert len(result.missed) == 0
    assert len(result.spurious) == 0


# ---------------------------------------------------------------------------
# Test 2: zero overlap
# ---------------------------------------------------------------------------


def test_zero_overlap_gives_zero_scores() -> None:
    """No match between expected and reported => P=R=F1=0."""
    expected = [_finding("process", name="mimikatz.exe")]
    reported = [_result("volatility.pslist", name="notepad.exe")]

    result = compute_score(expected, reported)

    assert result.precision == pytest.approx(0.0)
    assert result.recall == pytest.approx(0.0)
    assert result.f1 == pytest.approx(0.0)
    assert len(result.matched) == 0
    assert len(result.missed) == 1
    assert len(result.spurious) == 1


# ---------------------------------------------------------------------------
# Test 3: partial match
# ---------------------------------------------------------------------------


def test_partial_match_mixed_matched_missed_spurious() -> None:
    """2 expected, 3 reported: 1 match, 1 missed, 2 spurious."""
    expected = [
        _finding("process", name="mimikatz.exe"),
        _finding("connection", remote_port="4444"),
    ]
    reported = [
        _result("volatility.pslist", name="mimikatz.exe"),
        _result("volatility.pslist", name="explorer.exe"),
        _result("volatility.netscan", remote_port=8080),
    ]

    result = compute_score(expected, reported)

    assert result.precision == pytest.approx(1 / 3)
    assert result.recall == pytest.approx(0.5)
    assert result.f1 == pytest.approx(2 * (1 / 3) * 0.5 / (1 / 3 + 0.5))
    assert len(result.matched) == 1
    assert len(result.missed) == 1
    assert len(result.spurious) == 2


# ---------------------------------------------------------------------------
# Test 4: empty expected, empty reported
# ---------------------------------------------------------------------------


def test_both_empty_gives_perfect_scores() -> None:
    """Empty expected AND empty reported => trivially perfect P=R=F1=1.0."""
    result = compute_score([], [])

    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(1.0)
    assert result.f1 == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Test 5: empty expected, non-empty reported
# ---------------------------------------------------------------------------


def test_empty_expected_nonempty_reported_precision_zero() -> None:
    """No expected findings but agent reported something => precision=0.0."""
    reported = [_result("volatility.pslist", name="explorer.exe")]

    result = compute_score([], reported)

    assert result.precision == pytest.approx(0.0)
    assert result.recall == pytest.approx(1.0)
    assert result.f1 == pytest.approx(0.0)
    assert len(result.spurious) == 1


# ---------------------------------------------------------------------------
# Test 6: non-empty expected, empty reported
# ---------------------------------------------------------------------------


def test_empty_reported_nonempty_expected_recall_zero() -> None:
    """Expected findings but agent reported nothing => recall=0.0."""
    expected = [_finding("process", name="mimikatz.exe")]

    result = compute_score(expected, [])

    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(0.0)
    assert result.f1 == pytest.approx(0.0)
    assert len(result.missed) == 1


# ---------------------------------------------------------------------------
# Test 7: substring matching for string fields
# ---------------------------------------------------------------------------


def test_substring_match_for_string_fields() -> None:
    """Expected value 'mimikatz' should match payload value 'mimikatz.exe'."""
    expected = [_finding("process", name="mimikatz")]
    reported = [_result("volatility.pslist", name="mimikatz.exe")]

    result = compute_score(expected, reported)

    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(1.0)
    assert len(result.matched) == 1


def test_substring_no_match_when_not_substring() -> None:
    """Expected value 'mimikatz' must NOT match 'notepad.exe'."""
    expected = [_finding("process", name="mimikatz")]
    reported = [_result("volatility.pslist", name="notepad.exe")]

    result = compute_score(expected, reported)

    assert len(result.matched) == 0
    assert len(result.missed) == 1


# ---------------------------------------------------------------------------
# Test 8: exact matching for numeric fields
# ---------------------------------------------------------------------------


def test_exact_match_for_numeric_fields() -> None:
    """Expected '1234' should match payload int 1234 but not 1235."""
    expected_match = [_finding("process", pid="1234")]
    expected_no_match = [_finding("process", pid="9999")]
    reported = [_result("volatility.pslist", pid=1234)]

    match_result = compute_score(expected_match, reported)
    no_match_result = compute_score(expected_no_match, reported)

    assert len(match_result.matched) == 1
    assert len(no_match_result.matched) == 0


def test_float_exact_match() -> None:
    """Expected '0.5' should match payload float 0.5."""
    expected = [_finding("metric", value="0.5")]
    reported = [_result("some.tool", value=0.5)]

    result = compute_score(expected, reported)

    assert len(result.matched) == 1


# ---------------------------------------------------------------------------
# Test 9: missing key in payload does not match
# ---------------------------------------------------------------------------


def test_missing_key_in_payload_no_match() -> None:
    """If a key_field key is absent from the payload, the finding must not match."""
    expected = [_finding("process", name="mimikatz.exe", nonexistent_field="x")]
    reported = [_result("volatility.pslist", name="mimikatz.exe")]

    result = compute_score(expected, reported)

    assert len(result.matched) == 0
    assert len(result.missed) == 1


# ---------------------------------------------------------------------------
# Test 10: one reported finding satisfies at most one expected
# ---------------------------------------------------------------------------


def test_one_reported_satisfies_only_one_expected() -> None:
    """A single reported finding cannot match more than one expected finding."""
    expected = [
        _finding("process", name="mimikatz.exe"),
        _finding("process", name="mimikatz.exe"),
    ]
    reported = [_result("volatility.pslist", name="mimikatz.exe")]

    result = compute_score(expected, reported)

    assert len(result.matched) == 1
    assert len(result.missed) == 1
    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Test 11: nested list payload (real tool result shape)
# ---------------------------------------------------------------------------


def test_nested_list_payload_matches() -> None:
    """key_fields must match fields inside a nested list of records (real pslist shape)."""
    expected = [_finding("process", name="mimikatz", pid="1234")]
    reported = [
        ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.OK,
            payload={"processes": [{"pid": 1234, "name": "mimikatz.exe", "ppid": 4}]},
        )
    ]

    result = compute_score(expected, reported)

    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(1.0)
    assert len(result.matched) == 1


# ---------------------------------------------------------------------------
# Test 12: nested list -- all key_fields must come from the same record
# ---------------------------------------------------------------------------


def test_nested_list_all_fields_must_match_same_record() -> None:
    """A finding mixing fields from two different process entries must not match."""
    expected = [_finding("process", name="mimikatz.exe", pid="5678")]
    reported = [
        ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.OK,
            payload={
                "processes": [
                    {"pid": 1234, "name": "mimikatz.exe"},
                    {"pid": 5678, "name": "notepad.exe"},
                ]
            },
        )
    ]

    result = compute_score(expected, reported)

    assert len(result.matched) == 0
    assert len(result.missed) == 1


# ---------------------------------------------------------------------------
# Test 13: nested dict payload (e.g. event summary wrapper)
# ---------------------------------------------------------------------------


def test_nested_dict_payload_matches() -> None:
    """key_fields must match inside a nested dict (not just the top-level payload)."""
    expected = [_finding("event", event_id="4624")]
    reported = [
        ToolResult(
            tool_name="evtxecmd.security",
            status=ToolStatus.OK,
            payload={"events": [{"event_id": 4624, "level": "Information"}]},
        )
    ]

    result = compute_score(expected, reported)

    assert result.recall == pytest.approx(1.0)
    assert len(result.matched) == 1


# ---------------------------------------------------------------------------
# Test 14: nested payload -- no match when field absent in every record
# ---------------------------------------------------------------------------


def test_nested_list_no_match_when_field_absent() -> None:
    """A key_field absent from every nested record must not match."""
    expected = [_finding("process", name="mimikatz.exe", nonexistent="x")]
    reported = [
        ToolResult(
            tool_name="volatility.pslist",
            status=ToolStatus.OK,
            payload={"processes": [{"pid": 1234, "name": "mimikatz.exe"}]},
        )
    ]

    result = compute_score(expected, reported)

    assert len(result.matched) == 0
    assert len(result.missed) == 1
