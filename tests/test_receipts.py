"""Tests for the HMAC-signed receipt chain.

Each test validates a property that maps to hackathon judging criterion #5
(Audit Trail Quality): can a judge trace any finding back to the specific
tool execution that produced it, and detect tampering anywhere in between?
"""

from __future__ import annotations

import dataclasses

import pytest

from sentinel.audit.receipts import (
    GENESIS_PREV_DIGEST,
    ChainIntegrityError,
    ReceiptChain,
    secret_from_env,
)


def test_empty_chain_has_genesis_last_digest(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    assert chain.length == 0
    assert chain.last_digest == GENESIS_PREV_DIGEST


def test_first_receipt_points_at_genesis(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    receipt = chain.append("volatility.pslist", b"{}", b'{"pids":[1,2,3]}')
    assert receipt.sequence == 0
    assert receipt.prev_digest == GENESIS_PREV_DIGEST


def test_chain_links_via_prev_digest(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    first = chain.append("volatility.pslist", b"{}", b'{"pids":[1]}')
    second = chain.append("plaso.log2timeline", b"{}", b'{"events":42}')
    assert second.prev_digest == first.digest
    assert second.sequence == 1


def test_verify_passes_on_clean_chain(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    chain.append("volatility.pslist", b"{}", b'{"pids":[1]}')
    chain.append("plaso.log2timeline", b"{}", b'{"events":42}')
    chain.append("regripper.amcache", b"{}", b'{"keys":[]}')
    chain.verify()  # must not raise


def test_verify_detects_input_tampering(hmac_secret: bytes, session_id: str) -> None:
    """If someone swaps in a different input hash, verify must catch it."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    chain.append("volatility.pslist", b"{}", b'{"pids":[1]}')
    chain.append("plaso.log2timeline", b"{}", b'{"events":42}')

    # Tamper: replace a receipt with one that has a different input_sha256.
    original = chain.receipts()[1]
    tampered = dataclasses.replace(original, input_sha256="f" * 64)
    chain._receipts[1] = tampered  # noqa: SLF001

    with pytest.raises(ChainIntegrityError, match="Digest mismatch"):
        chain.verify()


def test_verify_detects_broken_prev_digest_pointer(
    hmac_secret: bytes, session_id: str
) -> None:
    """Excising a receipt should break the chain pointer."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    chain.append("a", b"{}", b'{"x":1}')
    chain.append("b", b"{}", b'{"x":2}')
    chain.append("c", b"{}", b'{"x":3}')

    # Remove the middle receipt and re-index the third one's sequence so the
    # sequence-gap check would pass -- proving that prev_digest is what catches it.
    middle = chain.receipts()[1]
    third = chain.receipts()[2]
    renumbered_third = dataclasses.replace(third, sequence=1)
    chain._receipts = [chain.receipts()[0], renumbered_third]  # noqa: SLF001
    del middle  # explicit: we are deleting it from the chain

    with pytest.raises(ChainIntegrityError, match="prev_digest"):
        chain.verify()


def test_verify_detects_wrong_secret(hmac_secret: bytes, session_id: str) -> None:
    """A chain signed with secret A must fail verify under secret B."""
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    chain.append("volatility.pslist", b"{}", b'{"pids":[1]}')

    # Reconstruct the chain object with a different secret but the same data.
    forged = ReceiptChain(secret=b"not-the-real-secret-zzzzzzzzzzzzz", session_id=session_id)
    forged._receipts = list(chain.receipts())  # noqa: SLF001

    with pytest.raises(ChainIntegrityError, match="HMAC signature invalid"):
        forged.verify()


def test_to_jsonl_serializes_every_receipt(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    chain.append("a", b"{}", b'{"x":1}')
    chain.append("b", b"{}", b'{"x":2}')

    jsonl = chain.to_jsonl()
    lines = jsonl.splitlines()
    assert len(lines) == 2
    assert '"tool_name": "a"' in lines[0]
    assert '"tool_name": "b"' in lines[1]


def test_empty_secret_rejected(session_id: str) -> None:
    with pytest.raises(ValueError, match="secret"):
        ReceiptChain(secret=b"", session_id=session_id)


def test_empty_session_id_rejected(hmac_secret: bytes) -> None:
    with pytest.raises(ValueError, match="session_id"):
        ReceiptChain(secret=hmac_secret, session_id="")


def test_empty_tool_name_rejected(hmac_secret: bytes, session_id: str) -> None:
    chain = ReceiptChain(secret=hmac_secret, session_id=session_id)
    with pytest.raises(ValueError, match="tool_name"):
        chain.append("", b"{}", b"{}")


def test_secret_from_env_raises_helpful_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALETHEIA_RECEIPT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match=r"secrets\.token_hex"):
        secret_from_env()


def test_secret_from_env_returns_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALETHEIA_RECEIPT_SECRET", "abc123")
    assert secret_from_env() == b"abc123"
