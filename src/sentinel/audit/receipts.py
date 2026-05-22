"""HMAC-signed audit receipts for forensic tool executions.

Every tool call produces a receipt. Receipts form a hash chain: each one
references the previous receipt's digest, so any tampering breaks the chain.
This is how judges (and practitioners) trace a finding back to the specific
tool execution that produced it.

The receipt itself never contains the raw tool input or output, only their
SHA-256 digests. Raw artifacts are written to disk separately so we do not
leak sensitive evidence content into the audit log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any

GENESIS_PREV_DIGEST = "0" * 64
"""First receipt in a session has no predecessor; it points at all zeros."""


@dataclass(frozen=True)
class Receipt:
    """Single audit receipt for one tool execution.

    Receipts are intentionally minimal: identity (sequence, timestamp, tool),
    integrity (input/output digests, chain pointer), and authentication (HMAC).
    """

    sequence: int
    timestamp_ns: int
    tool_name: str
    input_sha256: str
    output_sha256: str
    prev_digest: str
    digest: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


class ChainIntegrityError(Exception):
    """Raised when receipt chain validation fails."""


class ReceiptChain:
    """Append-only chain of receipts for a forensic session.

    Thread-safety is the caller's responsibility. The orchestrator is
    single-threaded by design -- agents share one chain so the audit trail
    is linear and unambiguous.
    """

    def __init__(self, secret: bytes, session_id: str) -> None:
        if not secret:
            raise ValueError("HMAC secret cannot be empty")
        if not session_id:
            raise ValueError("session_id cannot be empty")
        self._secret = secret
        self._session_id = session_id
        self._receipts: list[Receipt] = []

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def length(self) -> int:
        return len(self._receipts)

    @property
    def last_digest(self) -> str:
        if not self._receipts:
            return GENESIS_PREV_DIGEST
        return self._receipts[-1].digest

    def append(
        self,
        tool_name: str,
        tool_input: bytes,
        tool_output: bytes,
    ) -> Receipt:
        """Record a tool execution and return the new receipt.

        Inputs and outputs are bytes; the caller decides their canonical
        serialization (JSON, msgpack, raw) before calling. This module does
        not impose a format because it does not need to interpret content.
        """
        if not tool_name:
            raise ValueError("tool_name cannot be empty")

        sequence = len(self._receipts)
        timestamp_ns = time.time_ns()
        input_sha256 = hashlib.sha256(tool_input).hexdigest()
        output_sha256 = hashlib.sha256(tool_output).hexdigest()
        prev_digest = self.last_digest

        body = _canonical_body(
            session_id=self._session_id,
            sequence=sequence,
            timestamp_ns=timestamp_ns,
            tool_name=tool_name,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            prev_digest=prev_digest,
        )

        digest = hashlib.sha256(body).hexdigest()
        signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()

        receipt = Receipt(
            sequence=sequence,
            timestamp_ns=timestamp_ns,
            tool_name=tool_name,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            prev_digest=prev_digest,
            digest=digest,
            signature=signature,
        )
        self._receipts.append(receipt)
        return receipt

    def verify(self) -> None:
        """Re-validate the entire chain.

        Raises ChainIntegrityError on any failure (sequence gap, broken
        prev_digest pointer, digest mismatch, invalid signature).

        Run before producing the final report. Run again any time the chain
        was held in memory across an untrusted boundary.
        """
        prev_digest = GENESIS_PREV_DIGEST
        for expected_seq, receipt in enumerate(self._receipts):
            if receipt.sequence != expected_seq:
                raise ChainIntegrityError(
                    f"Sequence gap at index {expected_seq}: "
                    f"receipt claims sequence {receipt.sequence}"
                )
            if receipt.prev_digest != prev_digest:
                raise ChainIntegrityError(
                    f"Chain broken at sequence {receipt.sequence}: "
                    f"prev_digest does not match preceding receipt"
                )
            body = _canonical_body(
                session_id=self._session_id,
                sequence=receipt.sequence,
                timestamp_ns=receipt.timestamp_ns,
                tool_name=receipt.tool_name,
                input_sha256=receipt.input_sha256,
                output_sha256=receipt.output_sha256,
                prev_digest=receipt.prev_digest,
            )
            expected_digest = hashlib.sha256(body).hexdigest()
            if receipt.digest != expected_digest:
                raise ChainIntegrityError(
                    f"Digest mismatch at sequence {receipt.sequence}"
                )
            expected_sig = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(receipt.signature, expected_sig):
                raise ChainIntegrityError(
                    f"HMAC signature invalid at sequence {receipt.sequence}"
                )
            prev_digest = receipt.digest

    def receipts(self) -> tuple[Receipt, ...]:
        return tuple(self._receipts)

    def to_jsonl(self) -> str:
        """Serialize the chain as JSON Lines for on-disk persistence."""
        return "\n".join(r.to_json() for r in self._receipts)


def _canonical_body(
    *,
    session_id: str,
    sequence: int,
    timestamp_ns: int,
    tool_name: str,
    input_sha256: str,
    output_sha256: str,
    prev_digest: str,
) -> bytes:
    """Pipe-delimited canonical encoding for hashing and signing.

    Order is fixed. Do not change without bumping a chain-format version
    or you will silently invalidate every receipt ever produced.
    """
    return (
        f"v1|{session_id}|{sequence}|{timestamp_ns}|{tool_name}"
        f"|{input_sha256}|{output_sha256}|{prev_digest}"
    ).encode()


def secret_from_env(env_var: str = "ALETHEIA_RECEIPT_SECRET") -> bytes:
    """Load the HMAC secret from an environment variable.

    Raises RuntimeError with a helpful message if the variable is missing.
    """
    raw = os.environ.get(env_var)
    if not raw:
        raise RuntimeError(
            f"Missing {env_var}. Generate one with: "
            f'python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return raw.encode("utf-8")
