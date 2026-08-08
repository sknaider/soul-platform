"""Ed25519-authenticated principals for HTTP and other untrusted boundaries."""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from soul_platform.receipts import canonical_json


class AuthenticationDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifiedPrincipal:
    tenant: str
    actor: str
    key_id: str
    expires_at: int


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AuthenticationDenied("token encoding is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except Exception as exc:
        raise AuthenticationDenied("token encoding is invalid") from exc
    if _encode(raw) != value:
        raise AuthenticationDenied("token encoding is not canonical")
    return raw


class PrincipalTokenIssuer:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        self.private_key, self.key_id = private_key, key_id

    def issue(self, tenant: str, actor: str, *, ttl_seconds: int = 300) -> str:
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("ttl_seconds must be between 1 and 3600")
        now = int(time.time())
        payload = {
            "actor": actor, "exp": now + ttl_seconds, "iat": now,
            "key_id": self.key_id, "tenant": tenant,
        }
        data = canonical_json(payload)
        return f"{_encode(data)}.{_encode(self.private_key.sign(data))}"


class PrincipalTokenVerifier:
    def __init__(self, trust_store: Mapping[str, Ed25519PublicKey]) -> None:
        self.trust_store = dict(trust_store)

    def verify(self, token: str) -> VerifiedPrincipal:
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
        except ValueError as exc:
            raise AuthenticationDenied("token format is invalid") from exc
        data, signature = _decode(encoded_payload), _decode(encoded_signature)
        try:
            payload = json.loads(data)
        except Exception as exc:
            raise AuthenticationDenied("token payload is invalid") from exc
        if canonical_json(payload) != data or set(payload) != {"actor", "exp", "iat", "key_id", "tenant"}:
            raise AuthenticationDenied("token payload is not canonical")
        if not all(isinstance(payload[key], str) and payload[key] for key in ("actor", "key_id", "tenant")):
            raise AuthenticationDenied("token identity is invalid")
        if not isinstance(payload["iat"], int) or not isinstance(payload["exp"], int):
            raise AuthenticationDenied("token timestamps are invalid")
        now = int(time.time())
        if payload["iat"] > now + 30 or payload["exp"] <= now or payload["exp"] - payload["iat"] > 3600:
            raise AuthenticationDenied("token is expired or outside policy")
        key = self.trust_store.get(payload["key_id"])
        if key is None:
            raise AuthenticationDenied("token key is not trusted")
        try:
            key.verify(signature, data)
        except Exception as exc:
            raise AuthenticationDenied("token signature is invalid") from exc
        return VerifiedPrincipal(
            payload["tenant"], payload["actor"], payload["key_id"], payload["exp"]
        )
