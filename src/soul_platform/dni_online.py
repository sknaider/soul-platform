"""Client-side enrollment and periodic renewal for SOUL-issued DNI."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import stat
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from soul_framework.identity.dni import (
    current_machine_binding_sha256,
    verify_soul_dni,
)


_PROOF_DOMAIN = b"SOUL-DNI-DEVICE-PROOF-V1\0"
_SOUL_SIA_TAILNET_IPS = frozenset({"100.75.201.110"})


@dataclass(frozen=True)
class DNIOnlineDelivery:
    machine_soul_id: str
    soul_dni: str
    credential: Path
    trust_store: Path
    trust_store_sha256: str


def _canonical_device_proof(action: str, body: dict[str, object]) -> bytes:
    fields = (
        (
            "machine_soul_id",
            "machine_binding_sha256",
            "device_public_key",
            "enrollment_token_sha256",
            "nonce",
            "timestamp",
        )
        if action == "enroll"
        else (
            "soul_dni",
            "machine_soul_id",
            "machine_binding_sha256",
            "expected_sequence",
            "nonce",
            "timestamp",
        )
    )
    payload = {name: body.get(name) for name in fields}
    return _PROOF_DOMAIN + action.encode("ascii") + b"\0" + json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _endpoint(value: str) -> str:
    parsed = urlsplit(value.rstrip("/"))
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SIA endpoint must be an uncredentialed HTTP(S) URL")
    if parsed.scheme != "https":
        try:
            host = str(ipaddress.ip_address(parsed.hostname))
        except ValueError:
            host = parsed.hostname
        if host not in {"127.0.0.1", "::1", *_SOUL_SIA_TAILNET_IPS}:
            raise ValueError("remote SIA endpoint requires HTTPS")
        if host in _SOUL_SIA_TAILNET_IPS and parsed.port != 8781:
            raise ValueError("SOUL tailnet SIA endpoint must use port 8781")
    return value.rstrip("/")


def _private_dir(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError("SOUL root must be a real private directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)


def _read_private_file(path: Path, label: str, limit: int = 64 * 1024) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise PermissionError(f"{label} must be current-user-only")
        if info.st_size > limit:
            raise ValueError(f"{label} is too large")
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) > limit:
            raise ValueError(f"{label} is too large")
        return data
    finally:
        os.close(fd)


def _atomic_private(path: Path, data: bytes, *, replace: bool = False) -> None:
    if path.is_symlink() or (path.exists() and not replace):
        raise FileExistsError(path)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _device_key(root: Path) -> tuple[Ed25519PrivateKey, Path]:
    path = root / "soul-dni-device.pem"
    if path.exists():
        payload = _read_private_file(path, "DNI device key")
        key = serialization.load_pem_private_key(payload, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("DNI device key must be Ed25519")
        return key, path
    key = Ed25519PrivateKey.generate()
    _atomic_private(
        path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return key, path


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _post(endpoint: str, route: str, body: dict[str, object], timeout: float) -> dict:
    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        response = client.post(
            endpoint + route,
            json=body,
            headers={"Accept": "application/json", "Cache-Control": "no-store"},
        )
    if response.is_redirect:
        raise PermissionError("SIA redirects are forbidden")
    if response.status_code != 200:
        try:
            error = response.json().get("error", "request rejected")
        except Exception:
            error = "request rejected"
        raise PermissionError(f"SIA rejected request: {error}")
    value = response.json()
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise ValueError("SIA response is invalid")
    delivery = value.get("delivery")
    if not isinstance(delivery, dict):
        raise ValueError("SIA response has no DNI delivery")
    return delivery


def _publish_delivery(
    root: Path,
    delivery: dict,
    *,
    expected_machine_soul_id: str,
    expected_machine_binding_sha256: str,
) -> DNIOnlineDelivery:
    incoming = root / "dni-delivery"
    _private_dir(incoming)
    credential_value = delivery.get("credential")
    trust_value = delivery.get("trust_store")
    if not isinstance(credential_value, dict) or not isinstance(trust_value, dict):
        raise ValueError("SIA delivery documents are invalid")
    if str(delivery.get("machine_soul_id", "")) != expected_machine_soul_id:
        raise PermissionError("SIA delivery changed the requested machine identity")
    credential_bytes = (
        json.dumps(credential_value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    trust_bytes = (
        json.dumps(trust_value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    digest = hashlib.sha256(trust_bytes).hexdigest()
    if digest != delivery.get("trust_store_sha256"):
        raise PermissionError("SIA trust digest does not match delivered bytes")
    credential = incoming / "soul-dni.json"
    trust = incoming / "soul-dni-trust.json"
    credential_fd, credential_tmp = tempfile.mkstemp(prefix=".credential.", dir=incoming)
    trust_fd, trust_tmp = tempfile.mkstemp(prefix=".trust.", dir=incoming)
    try:
        with os.fdopen(credential_fd, "wb") as handle:
            handle.write(credential_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        with os.fdopen(trust_fd, "wb") as handle:
            handle.write(trust_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(credential_tmp, 0o600)
        os.chmod(trust_tmp, 0o600)
        verified = verify_soul_dni(
            Path(credential_tmp),
            Path(trust_tmp),
            expected_audience="soul-platform",
            expected_machine_soul_id=expected_machine_soul_id,
            expected_machine_binding_sha256=expected_machine_binding_sha256,
            expected_trust_store_sha256=digest,
        )
        if verified.soul_dni != str(delivery["soul_dni"]):
            raise PermissionError("SIA delivery identity does not match signed credential")
        os.replace(credential_tmp, credential)
        os.replace(trust_tmp, trust)
    finally:
        Path(credential_tmp).unlink(missing_ok=True)
        Path(trust_tmp).unlink(missing_ok=True)
    return DNIOnlineDelivery(
        machine_soul_id=str(delivery["machine_soul_id"]),
        soul_dni=str(delivery["soul_dni"]),
        credential=credential,
        trust_store=trust,
        trust_store_sha256=digest,
    )


def acquire_dni_online(
    *,
    root: Path,
    endpoint: str,
    enrollment_token: str,
    machine_soul_id: str | None = None,
    timeout: float = 15.0,
) -> DNIOnlineDelivery:
    root = root.expanduser().resolve()
    _private_dir(root)
    endpoint = _endpoint(endpoint)
    machine_soul_id = str(uuid.UUID(machine_soul_id or str(uuid.uuid4())))
    binding = current_machine_binding_sha256()
    key, key_path = _device_key(root)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    body: dict[str, object] = {
        "machine_soul_id": machine_soul_id,
        "machine_binding_sha256": binding,
        "device_public_key": base64.b64encode(public).decode("ascii"),
        "enrollment_token_sha256": hashlib.sha256(
            enrollment_token.encode("utf-8")
        ).hexdigest(),
        "nonce": secrets.token_urlsafe(24),
        "timestamp": _timestamp(),
    }
    body["signature"] = base64.b64encode(
        key.sign(_canonical_device_proof("enroll", body))
    ).decode("ascii")
    body["enrollment_token"] = enrollment_token
    delivery = _post(endpoint, "/v1/dni/enroll", body, timeout)
    published = _publish_delivery(
        root,
        delivery,
        expected_machine_soul_id=machine_soul_id,
        expected_machine_binding_sha256=binding,
    )
    config = {
        "schema": "soul.dni.authority-client.v1",
        "endpoint": endpoint,
        "device_key_file": str(key_path),
        "renew_before_days": 7,
    }
    _atomic_private(
        root / "soul-dni-authority.json",
        (json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        replace=(root / "soul-dni-authority.json").exists(),
    )
    return published


def renew_dni_online(
    *, config: Path, timeout: float = 15.0, restart: bool = True
):
    from soul_platform.autostart import AutostartContract, _current_platform, restart_descriptor
    from soul_platform.bootstrap import renew_dni
    config = config.expanduser().resolve()
    import tomllib

    raw = tomllib.loads(_read_private_file(config, "SOUL config").decode("utf-8"))
    soul = raw.get("soul")
    if not isinstance(soul, dict):
        raise ValueError("SOUL config has no soul section")
    root = config.parent
    credential = Path(str(soul.get("dni_credential_file", "")))
    trust = Path(str(soul.get("dni_trust_store_file", "")))
    if credential != root / "soul-dni.json" or trust != root / "soul-dni-trust.json":
        raise PermissionError("DNI paths must stay in the canonical SOUL root")
    current = verify_soul_dni(
        credential,
        trust,
        expected_audience="soul-platform",
        expected_machine_soul_id=str(soul.get("machine_soul_id", "")),
        expected_trust_store_sha256=str(soul.get("dni_trust_store_sha256", "")),
        allow_expired=True,
    )
    authority_config = json.loads(
        _read_private_file(root / "soul-dni-authority.json", "DNI authority config")
    )
    endpoint = _endpoint(str(authority_config.get("endpoint", "")))
    configured_key = Path(str(authority_config.get("device_key_file", "")))
    if configured_key != root / "soul-dni-device.pem":
        raise PermissionError("DNI device key must stay in the canonical SOUL root")
    key, _ = _device_key(root)
    binding = current_machine_binding_sha256()
    body: dict[str, object] = {
        "soul_dni": current.soul_dni,
        "machine_soul_id": current.machine_soul_id,
        "machine_binding_sha256": binding,
        "expected_sequence": current.sequence,
        "nonce": secrets.token_urlsafe(24),
        "timestamp": _timestamp(),
    }
    body["signature"] = base64.b64encode(
        key.sign(_canonical_device_proof("renew", body))
    ).decode("ascii")
    delivery = _post(endpoint, "/v1/dni/renew", body, timeout)
    incoming = _publish_delivery(
        root,
        delivery,
        expected_machine_soul_id=current.machine_soul_id,
        expected_machine_binding_sha256=binding,
    )
    renewed = renew_dni(
        config,
        dni_credential=incoming.credential,
        dni_trust_store=incoming.trust_store,
        dni_trust_store_sha256=incoming.trust_store_sha256,
    )
    if restart:
        restart_descriptor(AutostartContract.load(config), _current_platform())
    return renewed


def renew_dni_online_if_due(
    *, config: Path, timeout: float = 15.0, restart: bool = True, force: bool = False
) -> bool:
    """Renew before the 30-day deadline; expired credentials can still recover."""

    import tomllib

    config = config.expanduser().resolve()
    raw = tomllib.loads(_read_private_file(config, "SOUL config").decode("utf-8"))
    soul = raw.get("soul")
    if not isinstance(soul, dict):
        raise ValueError("SOUL config has no soul section")
    root = config.parent
    authority = json.loads(
        _read_private_file(root / "soul-dni-authority.json", "DNI authority config")
    )
    days = int(authority.get("renew_before_days", 7))
    if not 1 <= days <= 29:
        raise ValueError("DNI renew_before_days must be 1..29")
    current = verify_soul_dni(
        Path(str(soul.get("dni_credential_file", ""))),
        Path(str(soul.get("dni_trust_store_file", ""))),
        expected_audience="soul-platform",
        expected_machine_soul_id=str(soul.get("machine_soul_id", "")),
        expected_trust_store_sha256=str(soul.get("dni_trust_store_sha256", "")),
        allow_expired=True,
    )
    remaining = current.expires_at - datetime.now(timezone.utc)
    if not force and remaining.total_seconds() > days * 86400:
        return False
    renew_dni_online(config=config, timeout=timeout, restart=restart)
    return True


def attempt_startup_renewal(config: Path, *, timeout: float = 15.0) -> bool:
    """Best-effort early renewal; expired/unverifiable identities still fail closed."""

    config = config.expanduser().resolve()
    authority = config.parent / "soul-dni-authority.json"
    if not authority.exists():
        return False
    try:
        return renew_dni_online_if_due(
            config=config, timeout=timeout, restart=False
        )
    except Exception:
        # Network loss before the deadline is tolerated.  This validation is
        # intentionally strict: once the 30-day credential expires, startup
        # cannot proceed merely because renewal transport is unavailable.
        from soul_platform.proxy import ProxySettings

        ProxySettings.from_toml(config)
        return False
