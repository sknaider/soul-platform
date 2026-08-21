from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from soul_platform.auth import (
    AuthenticationDenied,
    PrincipalTokenIssuer,
    PrincipalTokenVerifier,
    TrustedPrincipal,
)


def _decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed(private, payload, *, canonical=True):
    data = json.dumps(
        payload,
        sort_keys=canonical,
        separators=(",", ":") if canonical else (", ", ": "),
    ).encode()
    return f"{_encode(data)}.{_encode(private.sign(data))}"


def _verifier(private, *, tenant="team", actor="alice"):
    return PrincipalTokenVerifier(
        {"auth-1": TrustedPrincipal(private.public_key(), tenant, actor)}
    )


def test_signed_session_is_covered_by_principal_signature():
    private = Ed25519PrivateKey.generate()
    issuer = PrincipalTokenIssuer(private, "auth-1")
    verifier = _verifier(private)
    token = issuer.issue(
        "team", "alice", session_id="browser-session-7", audience="soul-a"
    )
    verified = verifier.verify(token)
    assert (verified.tenant, verified.actor, verified.session_id, verified.audience) == (
        "team",
        "alice",
        "browser-session-7",
        "soul-a",
    )


def test_session_tamper_is_rejected_even_if_payload_remains_canonical():
    private = Ed25519PrivateKey.generate()
    issuer = PrincipalTokenIssuer(private, "auth-1")
    verifier = _verifier(private)
    token = issuer.issue(
        "team", "alice", session_id="original", audience="soul-a"
    )
    payload_part, signature_part = token.split(".")
    payload = json.loads(_decode(payload_part))
    payload["session_id"] = "attacker-chosen"
    tampered = f'{_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())}.{signature_part}'
    with pytest.raises(AuthenticationDenied, match="signature"):
        verifier.verify(tampered)


def test_legacy_principal_token_stays_compatible_but_has_no_session():
    private = Ed25519PrivateKey.generate()
    token = PrincipalTokenIssuer(private, "auth-1").issue("team", "alice")
    verified = _verifier(private).verify(token)
    assert verified.session_id == ""
    assert verified.audience == ""


def test_empty_or_oversized_explicit_session_is_rejected():
    private = Ed25519PrivateKey.generate()
    issuer = PrincipalTokenIssuer(private, "auth-1")
    with pytest.raises(ValueError, match="string"):
        issuer.issue("team", "alice", session_id=7)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="256"):
        issuer.issue("team", "alice", session_id="x" * 257)

    # Build a correctly signed token with an explicitly empty session claim.
    token = issuer.issue("team", "alice")
    payload = json.loads(_decode(token.split(".")[0]))
    payload["session_id"] = ""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    explicit_empty = f"{_encode(data)}.{_encode(private.sign(data))}"
    with pytest.raises(AuthenticationDenied, match="session"):
        _verifier(private).verify(explicit_empty)


def test_empty_or_oversized_explicit_audience_is_rejected():
    private = Ed25519PrivateKey.generate()
    issuer = PrincipalTokenIssuer(private, "auth-1")
    with pytest.raises(ValueError, match="string"):
        issuer.issue("team", "alice", audience=7)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="256"):
        issuer.issue("team", "alice", audience="x" * 257)

    token = issuer.issue("team", "alice")
    payload = json.loads(_decode(token.split(".")[0]))
    payload["audience"] = ""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    explicit_empty = f"{_encode(data)}.{_encode(private.sign(data))}"
    with pytest.raises(AuthenticationDenied, match="audience"):
        _verifier(private).verify(explicit_empty)


@pytest.mark.parametrize("token", ["no-dot", ".", "***.abc", "abc.***", "YWJj=.YWJj"])
def test_malformed_or_noncanonical_encoding_is_rejected(token):
    private = Ed25519PrivateKey.generate()
    with pytest.raises(AuthenticationDenied, match="format|encoding|payload"):
        _verifier(private).verify(token)


def test_noncanonical_payload_and_unknown_claim_are_rejected_before_signature_trust():
    private = Ed25519PrivateKey.generate()
    now = int(time.time())
    base = {
        "actor": "alice", "exp": now + 60, "iat": now,
        "key_id": "auth-1", "tenant": "team",
    }
    verifier = _verifier(private)
    with pytest.raises(AuthenticationDenied, match="canonical"):
        verifier.verify(_signed(private, base, canonical=False))
    with pytest.raises(AuthenticationDenied, match="canonical"):
        verifier.verify(_signed(private, {**base, "admin": True}))


@pytest.mark.parametrize("field", ["actor", "key_id", "tenant"])
def test_empty_or_wrong_type_identity_is_rejected(field):
    private = Ed25519PrivateKey.generate()
    now = int(time.time())
    payload = {
        "actor": "alice", "exp": now + 60, "iat": now,
        "key_id": "auth-1", "tenant": "team",
    }
    payload[field] = "" if field != "tenant" else 7
    with pytest.raises(AuthenticationDenied, match="identity"):
        _verifier(private).verify(
            _signed(private, payload)
        )


@pytest.mark.parametrize(
    "iat,exp",
    [
        ("now", 1),
        (1, "later"),
        (10_000_000_000, 10_000_000_100),
        (1, 2),
        (1, 4_000),
    ],
)
def test_invalid_expiry_timestamp_and_ttl_fail_closed(iat, exp):
    private = Ed25519PrivateKey.generate()
    payload = {
        "actor": "alice", "exp": exp, "iat": iat,
        "key_id": "auth-1", "tenant": "team",
    }
    with pytest.raises(AuthenticationDenied, match="timestamps|policy"):
        _verifier(private).verify(
            _signed(private, payload)
        )


def test_unknown_key_and_wrong_signature_are_rejected():
    trusted = Ed25519PrivateKey.generate()
    unknown = Ed25519PrivateKey.generate()
    now = int(time.time())
    payload = {
        "actor": "alice", "exp": now + 60, "iat": now,
        "key_id": "unknown", "tenant": "team",
    }
    verifier = _verifier(trusted)
    with pytest.raises(AuthenticationDenied, match="not trusted"):
        verifier.verify(_signed(unknown, payload))

    payload["key_id"] = "auth-1"
    with pytest.raises(AuthenticationDenied, match="signature"):
        verifier.verify(_signed(unknown, payload))


@pytest.mark.parametrize("ttl", [0, 3601, True])
def test_issuer_rejects_ttl_outside_policy(ttl):
    issuer = PrincipalTokenIssuer(Ed25519PrivateKey.generate(), "auth-1")
    with pytest.raises(ValueError, match="ttl_seconds"):
        issuer.issue("team", "alice", ttl_seconds=ttl)


def test_trusted_key_cannot_pivot_signed_tenant_or_actor():
    private = Ed25519PrivateKey.generate()
    verifier = _verifier(private)
    now = int(time.time())
    for tenant, actor in (("other", "alice"), ("team", "mallory")):
        payload = {
            "actor": actor,
            "exp": now + 60,
            "iat": now,
            "key_id": "auth-1",
            "tenant": tenant,
        }
        with pytest.raises(AuthenticationDenied, match="trusted key"):
            verifier.verify(_signed(private, payload))
