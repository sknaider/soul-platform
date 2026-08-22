"""Byte-bound local-owner consent for cloud release of SOUL context."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

from soul_platform.proxy import ProxySettings


SCHEMA = "soul.context-egress-consent.v1"
WITNESS_SCHEMA = "soul.context-egress-witness.v1"
PROCESSORS = {"codex": "OpenAI", "claude": "Anthropic"}
PURPOSE = "persistent-memory-recall"
DATA_CLASSES = [
    "profile.identity",
    "profile.ocean",
    "profile.relationships",
    "profile.critical-rules",
    "approved-private-memory-excerpts",
]


def _path(settings: ProxySettings) -> Path:
    return settings.soul_db.parent / "context-egress-consent.json"


def _witness_path(settings: ProxySettings) -> Path:
    # Kept outside the consent document so replaying an older signed consent
    # cannot undo a later revocation.  This is a fail-closed anti-replay
    # witness, not a protection against an OS-owner restoring the whole root.
    return settings.soul_db.parent / "context-egress-witness.json"


def _key(settings: ProxySettings) -> bytes:
    path = settings.token_file
    if path.is_symlink() or not path.is_file():
        raise ValueError("SOUL token must be a regular file")
    raw = path.read_bytes().strip()
    if len(raw) < 32:
        raise ValueError("SOUL token is invalid")
    return hmac.new(raw, b"soul.context-egress-consent.v1\0", hashlib.sha256).digest()


def _owner_identity() -> str:
    # Import lazily to avoid a module cycle during MCP startup.
    from soul_platform.mcp_stdio import _owner_identity as resolve

    return resolve()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sign(settings: ProxySettings, payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return hmac.new(_key(settings), _canonical(unsigned), hashlib.sha256).hexdigest()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(_canonical(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load(settings: ProxySettings) -> dict[str, Any]:
    path = _path(settings)
    if path.is_symlink() or not path.is_file():
        return {"schema": SCHEMA, "machine_soul_id": settings.machine_soul_id, "grants": {}}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCHEMA
        or payload.get("machine_soul_id") != settings.machine_soul_id
        or not isinstance(payload.get("grants"), dict)
    ):
        raise ValueError("context consent store differs from this machine soul")
    return payload


def _load_witness(settings: ProxySettings) -> dict[str, Any]:
    path = _witness_path(settings)
    if path.is_symlink():
        raise ValueError("context consent witness must not be a symlink")
    if not path.exists():
        return {
            "schema": WITNESS_SCHEMA,
            "machine_soul_id": settings.machine_soul_id,
            "sequences": {},
        }
    if not path.is_file():
        raise ValueError("context consent witness must be a regular file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    signature = str(payload.get("signature") or "") if isinstance(payload, dict) else ""
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != WITNESS_SCHEMA
        or payload.get("machine_soul_id") != settings.machine_soul_id
        or not isinstance(payload.get("sequences"), dict)
        or not hmac.compare_digest(signature, _sign(settings, payload))
    ):
        raise ValueError("context consent witness is invalid")
    return payload


def _write_witness(settings: ProxySettings, payload: dict[str, Any]) -> None:
    signed = {key: value for key, value in payload.items() if key != "signature"}
    signed["signature"] = _sign(settings, signed)
    _atomic_json(_witness_path(settings), signed)


def _context_snapshot_sha256(settings: ProxySettings) -> str:
    """Hash the exact private context authorized by one consent grant.

    Any later profile, rule, relationship or approved-memory change invalidates
    the old grant.  Embeddings and volatile timestamps are intentionally
    excluded because they are not released to the processor.
    """

    digest = hashlib.sha256()
    digest.update(b"soul.context-snapshot.v1\0")
    digest.update(settings.machine_soul_id.encode("utf-8"))
    if not settings.soul_db.exists():
        digest.update(b"empty")
        return digest.hexdigest()
    connection = sqlite3.connect(settings.soul_db)
    try:
        queries = (
            (
                "identity",
                "SELECT agent,personality,boot_context,philosophy,ocean_scores "
                "FROM identity WHERE agent=? ORDER BY agent",
            ),
            (
                "relationships",
                "SELECT agent,person,trust_level,style,dynamic FROM relationships "
                "WHERE agent=? ORDER BY person",
            ),
            (
                "rules",
                "SELECT agent,rule_key,content,set_by,priority,active FROM rules "
                "WHERE agent=? AND active=1 ORDER BY rule_key",
            ),
            (
                "memories",
                "SELECT id,agent,category,content,importance,source,scope,metadata "
                "FROM memories WHERE agent=? AND invalid_at IS NULL ORDER BY id",
            ),
        )
        for label, query in queries:
            digest.update(label.encode("ascii") + b"\0")
            try:
                rows = connection.execute(query, (settings.soul_name,))
            except sqlite3.OperationalError as exc:
                if "no such table" not in str(exc):
                    raise
                continue
            for row in rows:
                digest.update(_canonical({"row": list(row)}))
                digest.update(b"\n")
    finally:
        connection.close()
    return digest.hexdigest()


def issue_context_consent(
    settings: ProxySettings,
    client_id: str,
    *,
    ttl_days: int = 365,
    expected_snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    """Issue exact processor/purpose consent from a local-owner CLI action."""

    if client_id not in PROCESSORS:
        raise ValueError("unsupported context processor")
    if not isinstance(ttl_days, int) or isinstance(ttl_days, bool) or not 1 <= ttl_days <= 365:
        raise ValueError("consent TTL must be 1..365 days")
    snapshot_sha256 = _context_snapshot_sha256(settings)
    if expected_snapshot_sha256 is not None and not hmac.compare_digest(
        snapshot_sha256, expected_snapshot_sha256
    ):
        raise ValueError("private context changed after owner confirmation")
    payload = _load(settings)
    witness = _load_witness(settings)
    sequence = int(witness["sequences"].get(client_id, 0)) + 1
    now = int(time.time())
    grant = {
        "client_id": client_id,
        "processor": PROCESSORS[client_id],
        "purpose": PURPOSE,
        "data_classes": DATA_CLASSES,
        "machine_soul_id": settings.machine_soul_id,
        "owner": _owner_identity(),
        "issued_unix": now,
        "expires_unix": now + ttl_days * 86400,
        "authorization_sequence": sequence,
        "context_snapshot_sha256": (
            expected_snapshot_sha256 or snapshot_sha256
        ),
        "enabled": True,
    }
    grant["signature"] = _sign(settings, grant)
    witness["sequences"][client_id] = sequence
    _write_witness(settings, witness)
    payload["grants"][client_id] = grant
    _atomic_json(_path(settings), payload)
    return grant


def prepare_context_consent(
    settings: ProxySettings,
    client_id: str,
    *,
    ttl_days: int = 365,
) -> dict[str, Any]:
    """Prepare the exact bytes the owner must confirm before grant issuance."""

    if client_id not in PROCESSORS:
        raise ValueError("unsupported context processor")
    if not isinstance(ttl_days, int) or isinstance(ttl_days, bool) or not 1 <= ttl_days <= 365:
        raise ValueError("consent TTL must be 1..365 days")
    statement = {
        "schema": "soul.context-consent-confirmation.v1",
        "machine_soul_id": settings.machine_soul_id,
        "client_id": client_id,
        "processor": PROCESSORS[client_id],
        "purpose": PURPOSE,
        "data_classes": DATA_CLASSES,
        "ttl_days": ttl_days,
        "context_snapshot_sha256": _context_snapshot_sha256(settings),
    }
    return {
        **statement,
        "confirmation_sha256": hashlib.sha256(_canonical(statement)).hexdigest(),
    }


def revoke_context_consent(settings: ProxySettings, client_id: str) -> dict[str, Any]:
    if client_id not in PROCESSORS:
        raise ValueError("unsupported context processor")
    payload = _load(settings)
    witness = _load_witness(settings)
    sequence = int(witness["sequences"].get(client_id, 0)) + 1
    now = int(time.time())
    grant = {
        "client_id": client_id,
        "processor": PROCESSORS[client_id],
        "purpose": PURPOSE,
        "data_classes": DATA_CLASSES,
        "machine_soul_id": settings.machine_soul_id,
        "owner": _owner_identity(),
        "issued_unix": now,
        "expires_unix": now,
        "authorization_sequence": sequence,
        "context_snapshot_sha256": _context_snapshot_sha256(settings),
        "enabled": False,
    }
    grant["signature"] = _sign(settings, grant)
    witness["sequences"][client_id] = sequence
    _write_witness(settings, witness)
    payload["grants"][client_id] = grant
    _atomic_json(_path(settings), payload)
    return grant


def verify_context_consent(settings: ProxySettings, client_id: str) -> dict[str, Any] | None:
    """Return a valid exact consent or None. Unknown/expired/revoked fails closed."""

    if client_id not in PROCESSORS:
        return None
    try:
        payload = _load(settings)
        witness = _load_witness(settings)
        grant = payload["grants"].get(client_id)
        if not isinstance(grant, dict):
            return None
        signature = str(grant.get("signature") or "")
        if not hmac.compare_digest(signature, _sign(settings, grant)):
            return None
        if (
            grant.get("enabled") is not True
            or grant.get("client_id") != client_id
            or grant.get("processor") != PROCESSORS[client_id]
            or grant.get("purpose") != PURPOSE
            or grant.get("data_classes") != DATA_CLASSES
            or grant.get("machine_soul_id") != settings.machine_soul_id
            or grant.get("owner") != _owner_identity()
            or int(grant.get("authorization_sequence", -1))
            != int(witness["sequences"].get(client_id, -2))
            or grant.get("context_snapshot_sha256") != _context_snapshot_sha256(settings)
            or int(grant.get("expires_unix", 0)) <= int(time.time())
        ):
            return None
        return grant
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def effective_scopes(
    settings: ProxySettings, client_id: str, declared_scopes: list[str]
) -> frozenset[str]:
    """Resolve every call; revocation takes effect without restarting MCP."""

    scopes = {scope for scope in declared_scopes if isinstance(scope, str)}
    if verify_context_consent(settings, client_id) is None:
        scopes.discard("memory.search.private")
        scopes.discard("boot.private")
    return frozenset(scopes)
