"""Test the current source tree, never a stale installed wheel."""

from __future__ import annotations

import sys
import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from soul_framework.identity.dni import (
    canonical_credential_bytes,
    canonical_trust_store_bytes,
    current_machine_binding_sha256,
    generate_soul_id,
)


SOURCE = Path(__file__).resolve().parents[1] / "src"
source_text = str(SOURCE)
if source_text not in sys.path:
    sys.path.insert(0, source_text)


@pytest.fixture(scope="session", autouse=True)
def _soul_dni_test_authority(tmp_path_factory):
    """A hermetic SIA for tests; production packages contain no issuer key."""
    import soul_framework.identity.dni as dni_module

    root = tmp_path_factory.mktemp("soul-dni-sia")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    soul_id = generate_soul_id()
    machine_soul_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    trust = {
        "schema": "soul.dni.trust.v1",
        "issuer": "SOUL Identity Authority Test",
        "keys": {"test-sia-1": base64.b64encode(public).decode("ascii")},
        "signing_key_id": "test-sia-1",
        "sequence": 1,
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "revoked_key_ids": [],
        "revoked_soul_dnis": [],
    }
    trust["signature"] = base64.b64encode(
        private.sign(canonical_trust_store_bytes(trust))
    ).decode("ascii")
    credential = {
        "schema": "soul.dni.credential.v1",
        "issuer": trust["issuer"],
        "issuer_key_id": "test-sia-1",
        "soul_dni": f"urn:soul:agent:{soul_id}",
        "soul_id": soul_id,
        "machine_soul_id": machine_soul_id,
        "machine_binding_sha256": current_machine_binding_sha256(),
        "lifecycle_state": "active",
        "sequence": 1,
        "trust_sequence": 1,
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "audience": ["soul-core", "soul-platform"],
    }
    credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(credential))
    ).decode("ascii")
    trust_file = root / "trust.json"
    credential_file = root / "credential.json"
    trust_file.write_text(json.dumps(trust, sort_keys=True), encoding="utf-8")
    credential_file.write_text(json.dumps(credential, sort_keys=True), encoding="utf-8")
    trust_file.chmod(0o600)
    credential_file.chmod(0o600)
    values = {
        "SOUL_DNI_CREDENTIAL": str(credential_file),
        "SOUL_DNI_TRUST_STORE": str(trust_file),
        "SOUL_DNI_TRUST_STORE_SHA256": hashlib.sha256(trust_file.read_bytes()).hexdigest(),
        "SOUL_DNI_MACHINE_SOUL_ID": machine_soul_id,
        "SOUL_DNI_VALUE": credential["soul_dni"],
    }
    previous = {key: os.environ.get(key) for key in values}
    previous_pins = dni_module._PINNED_SIA_KEY_SHA256
    dni_module._PINNED_SIA_KEY_SHA256 = (
        ("test-sia-1", hashlib.sha256(public).hexdigest()),
    )
    os.environ.update(values)
    try:
        yield {"private": private}
    finally:
        dni_module._PINNED_SIA_KEY_SHA256 = previous_pins
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
