"""Byte-bound Ed25519 receipts with an explicit verifier trust store."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


@dataclass(frozen=True)
class SignedReceipt:
    receipt_id: str
    tenant: str
    task_id: str
    actor: str
    event: str
    payload_sha256: str
    previous_sha256: str
    created_at: str
    key_id: str
    signature: str

    def unsigned(self) -> dict[str, str]:
        value = asdict(self)
        value.pop("signature")
        return value

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(asdict(self))).hexdigest()


class ReceiptSigner:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        self._private_key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> "ReceiptSigner":
        return cls(Ed25519PrivateKey.generate(), key_id)

    @classmethod
    def from_private_bytes(cls, data: bytes, key_id: str) -> "ReceiptSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(data), key_id)

    def private_bytes(self) -> bytes:
        """Serialize the key for an operator-controlled secret store.

        SOUL Platform never writes this material itself and ships no trusted key.
        """
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(
        self,
        *,
        receipt_id: str,
        tenant: str,
        task_id: str,
        actor: str,
        event: str,
        payload: Mapping[str, Any],
        previous_sha256: str = "",
    ) -> SignedReceipt:
        unsigned = {
            "receipt_id": receipt_id,
            "tenant": tenant,
            "task_id": task_id,
            "actor": actor,
            "event": event,
            "payload_sha256": hashlib.sha256(canonical_json(payload)).hexdigest(),
            "previous_sha256": previous_sha256,
            "created_at": datetime.now(UTC).isoformat(),
            "key_id": self.key_id,
        }
        signature = base64.b64encode(self._private_key.sign(canonical_json(unsigned))).decode()
        return SignedReceipt(**unsigned, signature=signature)


class ReceiptVerifier:
    """Verifier keys are supplied by the operator; no trusted key is shipped in code."""

    def __init__(self, trust_store: Mapping[str, Ed25519PublicKey]) -> None:
        self._trust_store = dict(trust_store)

    def verify(self, receipt: SignedReceipt) -> bool:
        key = self._trust_store.get(receipt.key_id)
        if key is None:
            return False
        try:
            signature = base64.b64decode(receipt.signature, validate=True)
            if base64.b64encode(signature).decode("ascii") != receipt.signature:
                return False
            key.verify(signature, canonical_json(receipt.unsigned()))
        except (ValueError, TypeError):
            return False
        except Exception:
            return False
        return True

    def verify_payload(self, receipt: SignedReceipt, payload: Mapping[str, Any]) -> bool:
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        return digest == receipt.payload_sha256 and self.verify(receipt)

    def verify_chain(
        self,
        receipts: list[SignedReceipt],
        payloads: list[Mapping[str, Any]],
        *,
        expected_head: str | None = None,
        expected_tenant: str | None = None,
        expected_task_id: str | None = None,
    ) -> bool:
        """Verify signatures, payload bytes, linkage, uniqueness and an optional head.

        ``expected_head`` must come from an independent durable checkpoint. Without it,
        a valid prefix is necessarily indistinguishable from a truncated chain.
        """
        if not receipts or len(receipts) != len(payloads):
            return False
        if len({receipt.receipt_id for receipt in receipts}) != len(receipts):
            return False
        if receipts[0].previous_sha256 != "":
            return False
        for index, (receipt, payload) in enumerate(zip(receipts, payloads)):
            if expected_tenant is not None and receipt.tenant != expected_tenant:
                return False
            if expected_task_id is not None and receipt.task_id != expected_task_id:
                return False
            if receipt.tenant != receipts[0].tenant or receipt.task_id != receipts[0].task_id:
                return False
            if not self.verify_payload(receipt, payload):
                return False
            if index and receipt.previous_sha256 != receipts[index - 1].sha256():
                return False
        return expected_head is None or receipts[-1].sha256() == expected_head


class ReceiptCheckpointStore:
    """Independent durable head anchor used to detect valid-prefix truncation."""

    def __init__(self, path: str) -> None:
        self.path = path
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS receipt_heads ("
                "tenant TEXT NOT NULL, task_id TEXT NOT NULL, head_sha256 TEXT NOT NULL, "
                "updated_at TEXT NOT NULL, PRIMARY KEY(tenant,task_id))"
            )
            conn.commit()
        finally:
            conn.close()

    def record(self, receipt: SignedReceipt) -> None:
        head = receipt.sha256()
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT head_sha256 FROM receipt_heads WHERE tenant=? AND task_id=?",
                (receipt.tenant, receipt.task_id),
            ).fetchone()
            previous = str(row[0]) if row else ""
            if previous == head:
                conn.commit()
                return
            if previous != receipt.previous_sha256:
                raise ValueError("receipt does not extend the independent checkpoint head")
            conn.execute(
                "INSERT INTO receipt_heads VALUES(?,?,?,?) "
                "ON CONFLICT(tenant,task_id) DO UPDATE SET "
                "head_sha256=excluded.head_sha256,updated_at=excluded.updated_at",
                (receipt.tenant, receipt.task_id, head, datetime.now(UTC).isoformat()),
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def head(self, tenant: str, task_id: str) -> str | None:
        conn = sqlite3.connect(self.path)
        try:
            row = conn.execute(
                "SELECT head_sha256 FROM receipt_heads WHERE tenant=? AND task_id=?",
                (tenant, task_id),
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            conn.close()
