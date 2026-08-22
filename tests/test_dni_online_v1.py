from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from soul_framework.identity.dni import (
    canonical_credential_bytes,
    canonical_trust_store_bytes,
    current_machine_binding_sha256,
    generate_soul_id,
)

from soul_platform import bootstrap, dni_online
from soul_platform.bootstrap import initialize


def _delivery(private, machine: str, soul_id: str, sequence: int) -> dict:
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    trust = {
        "schema": "soul.dni.trust.v1",
        "issuer": "SOUL Identity Authority Test",
        "keys": {"test-sia-1": base64.b64encode(public).decode("ascii")},
        "signing_key_id": "test-sia-1",
        "sequence": sequence,
        "issued_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=29)).isoformat().replace("+00:00", "Z"),
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
        "machine_soul_id": machine,
        "machine_binding_sha256": current_machine_binding_sha256(),
        "lifecycle_state": "active",
        "sequence": sequence,
        "trust_sequence": sequence,
        "issued_at": trust["issued_at"],
        "expires_at": trust["expires_at"],
        "audience": ["soul-core", "soul-platform"],
    }
    credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(credential))
    ).decode("ascii")
    trust_bytes = (
        json.dumps(trust, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return {
        "schema": "soul.dni.delivery.v1",
        "soul_dni": credential["soul_dni"],
        "machine_soul_id": machine,
        "credential": credential,
        "trust_store": trust,
        "trust_store_sha256": hashlib.sha256(trust_bytes).hexdigest(),
        "expires_at": credential["expires_at"],
    }


def test_online_acquire_proves_device_possession_and_renewal_preserves_identity(
    tmp_path, _soul_dni_test_authority, monkeypatch
):
    private = _soul_dni_test_authority["private"]
    machine = "4f01478d-8568-4f57-b84e-3ff0a8bc6f3a"
    soul_id = generate_soul_id()
    first = _delivery(private, machine, soul_id, 1)

    def enroll_post(endpoint, route, body, timeout):
        assert endpoint == "https://sia.soulsmemory.com"
        assert route == "/v1/dni/enroll" and timeout == 4
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(body["device_public_key"])
        )
        public.verify(
            base64.b64decode(body["signature"]),
            dni_online._canonical_device_proof("enroll", body),
        )
        assert body["machine_soul_id"] == machine
        assert body["enrollment_token_sha256"] == hashlib.sha256(
            b"A" * 48
        ).hexdigest()
        return first

    monkeypatch.setattr(dni_online, "_post", enroll_post)
    root = tmp_path / "soul"
    delivery = dni_online.acquire_dni_online(
        root=root,
        endpoint="https://sia.soulsmemory.com",
        enrollment_token="A" * 48,
        machine_soul_id=machine,
        timeout=4,
    )
    assert delivery.soul_dni == first["soul_dni"]
    assert (root / "soul-dni-device.pem").stat().st_mode & 0o077 == 0
    result = initialize(
        root=root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
        dni_credential=delivery.credential,
        dni_trust_store=delivery.trust_store,
        dni_trust_store_sha256=delivery.trust_store_sha256,
    )
    second = _delivery(private, machine, soul_id, 2)

    def renew_post(endpoint, route, body, timeout):
        assert route == "/v1/dni/renew"
        key = serialization.load_pem_private_key(
            (root / "soul-dni-device.pem").read_bytes(), password=None
        )
        key.public_key().verify(
            base64.b64decode(body["signature"]),
            dni_online._canonical_device_proof("renew", body),
        )
        assert body["expected_sequence"] == 1
        return second

    monkeypatch.setattr(dni_online, "_post", renew_post)
    renewed = dni_online.renew_dni_online(
        config=result.config, timeout=4, restart=False
    )
    assert renewed.soul_dni == delivery.soul_dni
    assert renewed.verified_dni("soul-platform").sequence == 2


def test_remote_http_sia_is_rejected_before_network(tmp_path):
    try:
        dni_online.acquire_dni_online(
            root=tmp_path / "soul",
            endpoint="http://sia.example.test",
            enrollment_token="B" * 48,
        )
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("remote plaintext SIA must fail closed")


def test_only_the_pinned_soul_tailnet_ip_may_use_overlay_http():
    assert dni_online._endpoint("http://100.75.201.110:8781") == (
        "http://100.75.201.110:8781"
    )
    for endpoint in (
        "http://100.75.201.111:8781",
        "http://" + "192.168." + "68.200:8781",
        "http://spark-2cdf.tail018bcc.ts.net:8781",
    ):
        with pytest.raises(ValueError, match="requires HTTPS"):
            dni_online._endpoint(endpoint)
    for endpoint in (
        "http://100.75.201.110",
        "http://100.75.201.110:8765",
        "http://100.75.201.110:65535",
    ):
        with pytest.raises(ValueError, match="port 8781"):
            dni_online._endpoint(endpoint)
    for endpoint in (
        "http://100.75.201.110:8781/prefix",
        "http://100.75.201.110:8781//evil",
    ):
        with pytest.raises(ValueError, match="URL"):
            dni_online._endpoint(endpoint)


def test_sia_http_client_ignores_ambient_proxy_and_redirects(monkeypatch):
    observed = {}

    class Response:
        is_redirect = False
        status_code = 200

        @staticmethod
        def json():
            return {"ok": True, "delivery": {"marker": "ok"}}

    class Client:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:9999")
    monkeypatch.setattr(dni_online.httpx, "Client", Client)
    assert dni_online._post("https://sia.example", "/v1/dni/enroll", {}, 3) == {
        "marker": "ok"
    }
    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False


def test_private_reader_rejects_fifo_without_blocking(tmp_path):
    if os.name == "nt" or not hasattr(os, "mkfifo"):
        return
    fifo = tmp_path / "authority.json"
    os.mkfifo(fifo, 0o600)
    assert stat.S_ISFIFO(fifo.stat().st_mode)
    try:
        dni_online._read_private_file(fifo, "authority config")
    except ValueError as exc:
        assert "regular file" in str(exc)
    else:
        raise AssertionError("FIFO must fail fast")


def test_online_acquire_rejects_signed_delivery_for_another_machine(
    tmp_path, _soul_dni_test_authority, monkeypatch
):
    private = _soul_dni_test_authority["private"]
    requested = "4f01478d-8568-4f57-b84e-3ff0a8bc6f3a"
    substituted = "aa8253a2-1ec2-4772-8a2d-5ff2987db3b8"
    delivery = _delivery(private, substituted, generate_soul_id(), 1)
    monkeypatch.setattr(dni_online, "_post", lambda *_args, **_kwargs: delivery)

    try:
        dni_online.acquire_dni_online(
            root=tmp_path / "soul",
            endpoint="https://sia.soulsmemory.com",
            enrollment_token="C" * 48,
            machine_soul_id=requested,
        )
    except PermissionError as exc:
        assert "machine identity" in str(exc)
    else:
        raise AssertionError("SIA must not substitute the requested machine identity")


def test_cli_enrollment_failure_never_echoes_token_or_digest(
    tmp_path, monkeypatch, capsys
):
    token = "SecretEnrollmentToken_" + "Z" * 42
    token_file = tmp_path / "token.txt"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    monkeypatch.setattr(
        dni_online,
        "acquire_dni_online",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError("SIA denied")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "soul-machine",
            "acquire-dni-online",
            "--root",
            str(tmp_path / "soul"),
            "--endpoint",
            "https://sia.soulsmemory.com",
            "--enrollment-token-file",
            str(token_file),
        ],
    )
    with pytest.raises(PermissionError) as exc:
        bootstrap.main()
    output = capsys.readouterr().out + capsys.readouterr().err + str(exc.value)
    assert token not in output
    assert hashlib.sha256(token.encode()).hexdigest() not in output


def test_startup_renewal_tolerates_network_only_while_current_dni_is_valid(
    tmp_path, monkeypatch
):
    config = tmp_path / "proxy.toml"
    config.write_text("placeholder")
    config.chmod(0o600)
    (tmp_path / "soul-dni-authority.json").write_text("{}")
    (tmp_path / "soul-dni-authority.json").chmod(0o600)
    monkeypatch.setattr(
        dni_online,
        "renew_dni_online_if_due",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    monkeypatch.setattr(
        "soul_platform.proxy.ProxySettings.from_toml", lambda _path: object()
    )
    assert dni_online.attempt_startup_renewal(config) is False
