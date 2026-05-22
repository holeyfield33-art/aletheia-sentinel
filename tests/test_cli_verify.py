"""Tests for the sentinel verify subcommand.

Covers: valid chain (exit 0), tampered input_sha256 (exit 1),
wrong HMAC secret (exit 1), and missing file (exit 1).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from sentinel.audit.receipts import ReceiptChain
from sentinel.cli import _cmd_verify

_SECRET = b"test-verify-secret-32-bytes-abcd"
_SECRET_STR = _SECRET.decode()
_SESSION = "verify-test-session"


def _make_args(chain_path: str) -> argparse.Namespace:
    ns = argparse.Namespace()
    ns.chain_path = chain_path
    return ns


def _write_chain(tmp_path: Path, secret: bytes, session_id: str = _SESSION) -> Path:
    chain = ReceiptChain(secret=secret, session_id=session_id)
    chain.append(
        "volatility.pslist",
        b'{"memory_image": "/evidence/test.vmem"}',
        b'{"processes": [{"pid": 1, "name": "System"}]}',
    )
    chain.append(
        "regripper.amcache",
        b'{"hive_file": "/evidence/Amcache.hve"}',
        b'{"entries": []}',
    )
    p = tmp_path / "chain.jsonl"
    p.write_text(chain.to_jsonl(), encoding="ascii")
    return p


# ---------------------------------------------------------------------------
# Test 1: valid chain exits 0 and prints correct summary
# ---------------------------------------------------------------------------

def test_valid_chain_exits_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ALETHEIA_RECEIPT_SECRET", _SECRET_STR)
    chain_path = _write_chain(tmp_path, _SECRET)

    rc = _cmd_verify(_make_args(str(chain_path)))

    assert rc == 0
    out = capsys.readouterr().out
    assert "Chain valid" in out
    assert "2 receipts" in out


# ---------------------------------------------------------------------------
# Test 2: tampered receipt exits nonzero
# ---------------------------------------------------------------------------

def test_tampered_input_sha256_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ALETHEIA_RECEIPT_SECRET", _SECRET_STR)
    chain_path = _write_chain(tmp_path, _SECRET)

    lines = chain_path.read_text(encoding="ascii").splitlines()
    # Line 0 is the metadata header; line 1 is receipt #0.
    receipt_obj = json.loads(lines[1])
    receipt_obj["input_sha256"] = "f" * 64
    lines[1] = json.dumps(receipt_obj, sort_keys=True)
    chain_path.write_text("\n".join(lines), encoding="ascii")

    rc = _cmd_verify(_make_args(str(chain_path)))

    assert rc != 0
    err = capsys.readouterr().err
    assert "INVALID" in err


# ---------------------------------------------------------------------------
# Test 3: wrong HMAC secret exits nonzero
# ---------------------------------------------------------------------------

def test_wrong_secret_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    chain_path = _write_chain(tmp_path, _SECRET)
    monkeypatch.setenv("ALETHEIA_RECEIPT_SECRET", "wrong-secret-completely-different-x")

    rc = _cmd_verify(_make_args(str(chain_path)))

    assert rc != 0
    err = capsys.readouterr().err
    assert "INVALID" in err


# ---------------------------------------------------------------------------
# Test 4: missing file exits nonzero
# ---------------------------------------------------------------------------

def test_missing_file_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ALETHEIA_RECEIPT_SECRET", _SECRET_STR)
    nonexistent = str(tmp_path / "no-such-chain.jsonl")

    rc = _cmd_verify(_make_args(nonexistent))

    assert rc != 0
    err = capsys.readouterr().err
    assert "INVALID" in err


# ---------------------------------------------------------------------------
# Test 5: missing ALETHEIA_RECEIPT_SECRET exits nonzero
# ---------------------------------------------------------------------------

def test_missing_env_var_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ALETHEIA_RECEIPT_SECRET", raising=False)
    chain_path = _write_chain(tmp_path, _SECRET)

    rc = _cmd_verify(_make_args(str(chain_path)))

    assert rc != 0
    err = capsys.readouterr().err
    assert "INVALID" in err


# ---------------------------------------------------------------------------
# Test 6: empty chain (header only) still exits 0
# ---------------------------------------------------------------------------

def test_empty_chain_exits_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ALETHEIA_RECEIPT_SECRET", _SECRET_STR)
    chain = ReceiptChain(secret=_SECRET, session_id=_SESSION)
    chain_path = tmp_path / "empty.jsonl"
    chain_path.write_text(chain.to_jsonl(), encoding="ascii")

    rc = _cmd_verify(_make_args(str(chain_path)))

    assert rc == 0
    out = capsys.readouterr().out
    assert "0 receipts" in out
