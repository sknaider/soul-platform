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
    session_id: str = ""
    audience: str = ""


@dataclass(frozen=True)
class TrustedPrincipal:
    """Immutable identity binding for one trusted signing key."""

    public_key: Ed25519PublicKey
    tenant: str
    actor: str


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

    def issue(
        self,
        tenant: str,
        actor: str,
        *,
        ttl_seconds: int = 300,
        session_id: str = "",
        audience: str = "",
    ) -> str:
        if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 3600:
            raise ValueError("ttl_seconds must be between 1 and 3600")
        if not isinstance(session_id, str):
            raise ValueError("session_id must be a string")
        if len(session_id) > 256:
            raise ValueError("session_id must be at most 256 characters")
        if not isinstance(audience, str):
            raise ValueError("audience must be a string")
        if len(audience) > 256:
            raise ValueError("audience must be at most 256 characters")
        now = int(time.time())
        payload = {
            "actor": actor, "exp": now + ttl_seconds, "iat": now,
            "key_id": self.key_id, "tenant": tenant,
        }
        if session_id:
            payload["session_id"] = session_id
        if audience:
            payload["audience"] = audience
        data = canonical_json(payload)
        return f"{_encode(data)}.{_encode(self.private_key.sign(data))}"


class PrincipalTokenVerifier:
    def __init__(self, trust_store: Mapping[str, TrustedPrincipal]) -> None:
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
        base_claims = {"actor", "exp", "iat", "key_id", "tenant"}
        if canonical_json(payload) != data or frozenset(payload) not in {
            frozenset(base_claims),
            frozenset(base_claims | {"session_id"}),
            frozenset(base_claims | {"audience"}),
            frozenset(base_claims | {"session_id", "audience"}),
        }:
            raise AuthenticationDenied("token payload is not canonical")
        if not all(isinstance(payload[key], str) and payload[key] for key in ("actor", "key_id", "tenant")):
            raise AuthenticationDenied("token identity is invalid")
        session_id = payload.get("session_id", "")
        if (
            not isinstance(session_id, str)
            or len(session_id) > 256
            or ("session_id" in payload and not session_id)
        ):
            raise AuthenticationDenied("token session identity is invalid")
        audience = payload.get("audience", "")
        if (
            not isinstance(audience, str)
            or len(audience) > 256
            or ("audience" in payload and not audience)
        ):
            raise AuthenticationDenied("token audience is invalid")
        if not isinstance(payload["iat"], int) or not isinstance(payload["exp"], int):
            raise AuthenticationDenied("token timestamps are invalid")
        now = int(time.time())
        if payload["iat"] > now + 30 or payload["exp"] <= now or payload["exp"] - payload["iat"] > 3600:
            raise AuthenticationDenied("token is expired or outside policy")
        binding = self.trust_store.get(payload["key_id"])
        if binding is None:
            raise AuthenticationDenied("token key is not trusted")
        try:
            binding.public_key.verify(signature, data)
        except Exception as exc:
            raise AuthenticationDenied("token signature is invalid") from exc
        if payload["tenant"] != binding.tenant or payload["actor"] != binding.actor:
            raise AuthenticationDenied("token principal does not match its trusted key")
        return VerifiedPrincipal(
            payload["tenant"],
            payload["actor"],
            payload["key_id"],
            payload["exp"],
            session_id,
            audience,
        )
