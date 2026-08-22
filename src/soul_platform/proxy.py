"""Authenticated local OpenAI-compatible gateway for one persistent machine soul.

The model is an interchangeable upstream. Identity and memory remain in the
canonical SOUL database configured for the device.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import base64
import sqlite3
import stat
import argparse
import asyncio
import sys
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from soul_framework import Soul
from soul_framework.config import SoulConfig
from soul_framework.identity.dni import VerifiedSoulDNI, verify_soul_dni

from soul_platform.auth import (
    AuthenticationDenied,
    PrincipalTokenVerifier,
    TrustedPrincipal,
    VerifiedPrincipal,
)
from soul_platform.local_embedding import LocalBgeM3Embedding
from soul_platform.runtime_attestation import verify_runtime_attestation
from soul_platform.t5_memory_egress import SQLiteT5EgressStore


# Hostnames are intentionally excluded.  Resolving ``localhost`` in httpx after
# validation creates a DNS/rebinding boundary that the proxy cannot pin.
LOOPBACK_HOSTS = {"127.0.0.1", "::1"}
VALID_ROLES = {"system", "user", "assistant", "tool"}


def _reject_non_finite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _strict_json_loads(payload: str | bytes | bytearray) -> Any:
    return json.loads(payload, parse_constant=_reject_non_finite_json)
UPSTREAM_API_KEY_ENV = "SOUL_PROXY_UPSTREAM_API_KEY"
WINDOWS_REPARSE_POINT = 0x400


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    if os.name == "nt" and path.exists():
        return bool(getattr(os.lstat(path), "st_file_attributes", 0) & WINDOWS_REPARSE_POINT)
    return False


def _assert_private_owned_file(path: Path, field: str) -> None:
    if _is_link_or_reparse(path) or not path.is_file():
        raise ValueError(f"{field} must be a regular file, never a symlink")
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != os.getuid():
            raise ValueError(f"{field} must be owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"{field} must not be accessible by group/other")


def _assert_private_directory(path: Path, field: str) -> None:
    if _is_link_or_reparse(path) or not path.is_dir():
        raise ValueError(f"{field} must be a real directory, never a symlink")
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != os.getuid():
            raise ValueError(f"{field} must be owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"{field} must not be accessible by group/other")


def _assert_no_symlink_components(path: Path, field: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and _is_link_or_reparse(current):
            raise ValueError(f"{field} contains a symlinked path component")


def _assert_windows_canonical_root(path: Path) -> None:
    if os.name != "nt":
        return
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise ValueError("LOCALAPPDATA is required on Windows")
    expected = (Path(local_app_data) / "SOUL").resolve()
    if path.resolve() != expected:
        raise ValueError("Windows SOUL state must stay inside %LOCALAPPDATA%\\SOUL")


def _absolute_path(value: object, field: str) -> Path:
    text = str(value or "")
    if not text or any(char in text for char in ("\x00", "\r", "\n")):
        raise ValueError(f"{field} must be a non-empty safe path")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    return path


@dataclass(frozen=True)
class ProxySettings:
    soul_name: str
    soul_db: Path
    machine_soul_id: str
    host: str
    port: int
    require_auth: bool
    token_file: Path
    upstream_kind: str
    upstream_base_url: str
    upstream_model: str
    embedding_provider: str = "bge-m3"
    embedding_dimensions: int = 1024
    embedding_model: str = "bge-m3"
    embedding_url: str = "http://127.0.0.1:11434/api/embed"
    embedding_timeout_seconds: float = 60.0
    memory_vector_index: str = "auto"
    upstream_api_key_env: str = UPSTREAM_API_KEY_ENV
    upstream_allow_remote: bool = False
    timeout_seconds: float = 180.0
    mem_k: int = 4
    auto_store: bool = False
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 8_388_608
    t5_mode: str = "locked"
    t5_tenant: str = ""
    t5_owner_subject: str = ""
    t5_principal_keys_file: Path | None = None
    t5_state_db: Path | None = None
    soul_dni: str = ""
    dni_credential_file: Path | None = None
    dni_trust_store_file: Path | None = None
    dni_trust_store_sha256: str = ""

    @classmethod
    def from_toml(cls, path: str | os.PathLike[str]) -> "ProxySettings":
        import tomllib

        config = _absolute_path(path, "config")
        _assert_no_symlink_components(config, "config")
        _assert_windows_canonical_root(config.parent)
        _assert_private_owned_file(config, "config")
        _assert_private_directory(config.parent, "config parent")
        raw = tomllib.loads(config.read_text(encoding="utf-8"))
        soul = raw.get("soul") or {}
        proxy = raw.get("proxy") or {}
        upstream = raw.get("upstream") or {}
        memory_egress = raw.get("memory_egress") or {}
        embedding = raw.get("embedding")
        legacy_embedding = embedding is None
        if legacy_embedding:
            embedding = {
                "provider": "simple",
                "dimensions": 128,
                "model": "simple",
                "url": "http://127.0.0.1:11434/api/embed",
                "timeout_seconds": 60,
                "vector_index": "exact",
            }
        elif not isinstance(embedding, dict):
            raise ValueError("embedding section must be a TOML table")
        settings = cls(
            soul_name=str(soul.get("name") or "MachineSoul"),
            soul_db=_absolute_path(soul.get("db"), "soul.db"),
            machine_soul_id=str(soul.get("machine_soul_id") or ""),
            host=str(proxy.get("host") or "127.0.0.1"),
            port=int(proxy.get("port", 11435)),
            require_auth=proxy.get("require_auth") is True,
            token_file=_absolute_path(proxy.get("token_file"), "proxy.token_file"),
            upstream_kind=str(upstream.get("kind") or "openai-compatible"),
            upstream_base_url=str(upstream.get("base_url") or "").rstrip("/"),
            upstream_model=str(upstream.get("model") or ""),
            embedding_provider=str(embedding.get("provider") or ""),
            embedding_dimensions=int(embedding.get("dimensions", 0)),
            embedding_model=str(embedding.get("model") or ""),
            embedding_url=str(embedding.get("url") or ""),
            embedding_timeout_seconds=float(embedding.get("timeout_seconds", 0)),
            memory_vector_index=str(embedding.get("vector_index") or ""),
            upstream_api_key_env=str(
                upstream.get("api_key_env") or "SOUL_PROXY_UPSTREAM_API_KEY"
            ),
            upstream_allow_remote=upstream.get("allow_remote") is True,
            timeout_seconds=float(upstream.get("timeout_seconds", 180)),
            mem_k=int(proxy.get("mem_k", 4)),
            auto_store=proxy.get("auto_store") is True,
            max_request_bytes=int(proxy.get("max_request_bytes", 1_048_576)),
            max_response_bytes=int(proxy.get("max_response_bytes", 8_388_608)),
            t5_mode=str(memory_egress.get("mode") or "locked"),
            t5_tenant=str(memory_egress.get("tenant") or ""),
            t5_owner_subject=str(memory_egress.get("owner_subject") or ""),
            t5_principal_keys_file=(
                _absolute_path(memory_egress.get("principal_keys_file"), "memory_egress.principal_keys_file")
                if memory_egress.get("principal_keys_file")
                else None
            ),
            t5_state_db=(
                _absolute_path(memory_egress.get("state_db"), "memory_egress.state_db")
                if memory_egress.get("state_db")
                else None
            ),
            soul_dni=str(soul.get("dni") or ""),
            dni_credential_file=(
                _absolute_path(soul.get("dni_credential_file"), "soul.dni_credential_file")
                if soul.get("dni_credential_file")
                else None
            ),
            dni_trust_store_file=(
                _absolute_path(soul.get("dni_trust_store_file"), "soul.dni_trust_store_file")
                if soul.get("dni_trust_store_file")
                else None
            ),
            dni_trust_store_sha256=str(soul.get("dni_trust_store_sha256") or ""),
        )
        if settings.soul_db.parent.resolve() != config.parent.resolve():
            raise ValueError("soul.db must stay inside the canonical SOUL root")
        if settings.token_file.parent.resolve() != config.parent.resolve():
            raise ValueError("proxy.token_file must stay inside the canonical SOUL root")
        if settings.t5_state_path.parent.resolve() != config.parent.resolve():
            raise ValueError("memory_egress.state_db must stay inside the canonical SOUL root")
        if (
            settings.t5_principal_keys_file is not None
            and settings.t5_principal_keys_file.parent.resolve() != config.parent.resolve()
        ):
            raise ValueError(
                "memory_egress.principal_keys_file must stay inside the canonical SOUL root"
            )
        for field, candidate in (
            ("soul.dni_credential_file", settings.dni_credential_file),
            ("soul.dni_trust_store_file", settings.dni_trust_store_file),
        ):
            if candidate is None or candidate.parent.resolve() != config.parent.resolve():
                raise ValueError(f"{field} must stay inside the canonical SOUL root")
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.soul_name or len(self.soul_name) > 64:
            raise ValueError("soul.name must be 1..64 characters")
        try:
            uuid.UUID(self.machine_soul_id)
        except (ValueError, AttributeError):
            raise ValueError("soul.machine_soul_id must be a UUID") from None
        verified = self.verified_dni("soul-platform")
        if verified.soul_dni != self.soul_dni:
            raise ValueError("soul.dni does not match the SOUL-issued credential")
        if self.host not in LOOPBACK_HOSTS:
            raise ValueError("proxy host must be loopback")
        if not 1024 <= self.port <= 65535:
            raise ValueError("proxy port must be between 1024 and 65535")
        if not self.require_auth:
            raise ValueError("proxy.require_auth must be true")
        if not 1 <= self.mem_k <= 20:
            raise ValueError("proxy.mem_k must be between 1 and 20")
        if not 4_096 <= self.max_request_bytes <= 8_388_608:
            raise ValueError("proxy.max_request_bytes outside safe range")
        if not 4_096 <= self.max_response_bytes <= 33_554_432:
            raise ValueError("proxy.max_response_bytes outside safe range")
        if not 1 <= self.timeout_seconds <= 600:
            raise ValueError("upstream.timeout_seconds outside safe range")
        parsed = urlsplit(self.upstream_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("upstream.base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("credentials are forbidden in upstream.base_url")
        if parsed.query or parsed.fragment:
            raise ValueError("query/fragment are forbidden in upstream.base_url")
        if parsed.hostname not in LOOPBACK_HOSTS:
            raise ValueError("remote upstreams are disabled in proxy v1")
        if self.upstream_allow_remote:
            raise ValueError("upstream.allow_remote is unsupported in proxy v1")
        if self.upstream_api_key_env != UPSTREAM_API_KEY_ENV:
            raise ValueError(f"upstream.api_key_env must be {UPSTREAM_API_KEY_ENV}")
        if not self.upstream_model:
            raise ValueError("upstream.model is required")
        profile = (
            self.embedding_provider,
            self.embedding_dimensions,
            self.embedding_model,
            self.memory_vector_index,
        )
        if profile not in {
            ("bge-m3", 1024, "bge-m3", "auto"),
            ("simple", 128, "simple", "exact"),
        }:
            raise ValueError(
                "embedding profile must be bge-m3/1024/auto or legacy simple/128/exact"
            )
        if not 1 <= self.embedding_timeout_seconds <= 600:
            raise ValueError("embedding.timeout_seconds outside safe range")
        embedding_url = urlsplit(self.embedding_url)
        if (
            embedding_url.scheme != "http"
            or embedding_url.hostname not in LOOPBACK_HOSTS
            or embedding_url.port is None
            or embedding_url.path != "/api/embed"
            or embedding_url.username
            or embedding_url.password
            or embedding_url.query
            or embedding_url.fragment
        ):
            raise ValueError(
                "embedding.url must be an uncredentialed loopback /api/embed URL"
            )
        _assert_no_symlink_components(self.soul_db, "soul.db")
        if self.t5_mode not in {"locked", "enforce", "compatibility-single-owner"}:
            raise ValueError(
                "memory_egress.mode must be locked, enforce or compatibility-single-owner"
            )
        tenant = self.t5_tenant.strip().casefold()
        owner = self.t5_owner_subject.strip().casefold()
        if self.t5_mode == "locked":
            if self.t5_principal_keys_file is not None:
                raise ValueError("locked memory egress cannot configure principal keys")
        elif not tenant or not owner:
            raise ValueError("memory_egress tenant and owner_subject are required")
        if self.t5_mode == "enforce":
            if self.t5_principal_keys_file is None:
                raise ValueError("enforce memory egress requires principal_keys_file")
            _assert_no_symlink_components(
                self.t5_principal_keys_file, "memory_egress.principal_keys_file"
            )
            _assert_private_owned_file(
                self.t5_principal_keys_file, "memory_egress.principal_keys_file"
            )
            self.principal_verifier()
        elif self.t5_mode == "compatibility-single-owner" and self.t5_principal_keys_file is not None:
            raise ValueError("single-owner compatibility must not accept principal keys")
        _assert_no_symlink_components(self.t5_state_path, "memory_egress.state_db")
        self.read_token()

    def verified_dni(self, audience: str) -> VerifiedSoulDNI:
        if self.dni_credential_file is None or self.dni_trust_store_file is None:
            raise ValueError("SOUL-issued DNI credential and trust store are required")
        verified = verify_soul_dni(
            self.dni_credential_file,
            self.dni_trust_store_file,
            expected_audience=audience,
            expected_machine_soul_id=self.machine_soul_id,
            expected_trust_store_sha256=self.dni_trust_store_sha256,
        )
        if verified.soul_dni != self.soul_dni:
            raise PermissionError(
                "SOUL DNI renewal changed the sovereign soul identity"
            )
        return verified

    def read_token(self) -> str:
        _assert_no_symlink_components(self.token_file, "proxy token_file")
        _assert_private_owned_file(self.token_file, "proxy token_file")
        token = self.token_file.read_text(encoding="utf-8").strip()
        if len(token.encode()) < 32:
            raise ValueError("proxy token must contain at least 32 bytes")
        return token

    @property
    def t5_state_path(self) -> Path:
        return self.t5_state_db or self.soul_db.with_name(
            f"{self.soul_db.stem}.t5-egress.sqlite3"
        )

    def principal_verifier(self) -> PrincipalTokenVerifier | None:
        if self.t5_mode != "enforce":
            return None
        assert self.t5_principal_keys_file is not None
        try:
            raw = json.loads(self.t5_principal_keys_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not raw:
                raise ValueError
            keys = {
                str(key_id): TrustedPrincipal(
                    public_key=Ed25519PublicKey.from_public_bytes(
                        base64.b64decode(value, validate=True)
                    ),
                    tenant=self.t5_tenant.strip().casefold(),
                    actor=self.t5_owner_subject.strip().casefold(),
                )
                for key_id, value in raw.items()
                if isinstance(key_id, str) and key_id and isinstance(value, str)
            }
            if set(keys) != set(raw):
                raise ValueError
        except Exception as exc:
            raise ValueError("principal trust store is invalid") from exc
        return PrincipalTokenVerifier(keys)

    @property
    def baseline_hash(self) -> str:
        # The active SQLite generation can change during a reversible embedding
        # migration.  Identity must not: bind the baseline to the stable UUID
        # and soul name, never to a storage filename.
        payload = f"{self.machine_soul_id}\0{self.soul_name}"
        return hashlib.sha256(payload.encode()).hexdigest()

    @property
    def conversation_ledger(self) -> Path:
        """Conversation history is durable but never part of semantic recall."""

        return self.soul_db.with_name(f"{self.soul_db.stem}.conversations.sqlite3")


class ConversationLedger:
    """Append-only, hash-linked conversation ledger.

    Raw prompts belong here, not in the factual memory index.  Keeping the
    ledger physically separate prevents questions and transient instructions
    from becoming identity facts merely because a client enabled persistence.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.head_path = path.with_name(f"{path.name}.head")

    def _write_head(self, head: str) -> None:
        temporary = self.head_path.with_name(
            f".{self.head_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, f"{head}\n".encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self.head_path)
        if os.name != "nt":
            os.chmod(self.head_path, 0o600)

    def _read_head(self) -> str:
        _assert_no_symlink_components(self.head_path, "conversation ledger head")
        _assert_private_owned_file(self.head_path, "conversation ledger head")
        value = self.head_path.read_text(encoding="ascii").strip().lower()
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("conversation ledger head witness is invalid")
        return value

    def initialize(self) -> None:
        _assert_no_symlink_components(self.path, "conversation ledger")
        if self.path.exists() and _is_link_or_reparse(self.path):
            raise ValueError("conversation ledger must never be a symlink")
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS conversation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_unix_ms INTEGER NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user')),
                    content TEXT NOT NULL,
                    response_sha256 TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS conversation_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            head = self._verify_connection(connection)
            enabled = connection.execute(
                "SELECT value FROM conversation_metadata WHERE key='head_witness_v1'"
            ).fetchone()
            if enabled is None:
                self._write_head(head)
                connection.execute(
                    "INSERT INTO conversation_metadata(key,value) VALUES('head_witness_v1','required')"
                )
            elif self._read_head() != head:
                raise ValueError("conversation ledger head witness does not match")
        if os.name != "nt":
            os.chmod(self.path, 0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{self.path}{suffix}")
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)

    @staticmethod
    def _entry_material(
        created: int, content: str, response_hash: str, previous: str
    ) -> bytes:
        return json.dumps(
            {
                "created_unix_ms": created,
                "role": "user",
                "content": content,
                "response_sha256": response_hash,
                "previous_sha256": previous,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @classmethod
    def _verify_connection(cls, connection: sqlite3.Connection) -> str:
        expected_previous = "0" * 64
        for row in connection.execute(
            "SELECT created_unix_ms, content, response_sha256, previous_sha256, "
            "entry_sha256 FROM conversation_events ORDER BY id"
        ):
            created, content, response_hash, previous, entry = row
            expected_entry = hashlib.sha256(
                cls._entry_material(created, content, response_hash, previous)
            ).hexdigest()
            if previous != expected_previous or not hmac.compare_digest(entry, expected_entry):
                raise ValueError("conversation ledger hash chain is invalid")
            expected_previous = entry
        return expected_previous

    def verify(self) -> str:
        with sqlite3.connect(self.path) as connection:
            head = self._verify_connection(connection)
        if self._read_head() != head:
            raise ValueError("conversation ledger head witness does not match")
        return head

    def append(self, content: str, response: bytes) -> str:
        created = int(time.time() * 1000)
        response_hash = hashlib.sha256(response).hexdigest()
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = self._verify_connection(connection)
            if self._read_head() != previous:
                raise ValueError("conversation ledger head witness does not match")
            material = self._entry_material(created, content, response_hash, previous)
            entry = hashlib.sha256(material).hexdigest()
            connection.execute(
                """
                INSERT INTO conversation_events
                    (created_unix_ms, role, content, response_sha256,
                     previous_sha256, entry_sha256)
                VALUES (?, 'user', ?, ?, ?, ?)
                """,
                (created, content, response_hash, previous, entry),
            )
            # Keep the SQLite write lock until the head is atomically advanced.
            # A crash can leave a mismatch (fail closed), never a silent race.
            self._write_head(entry)
            connection.commit()
        return entry


def create_app(
    settings: ProxySettings,
    *,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    upstream_attestor: Any | None = None,
    config_path: Path | None = None,
) -> FastAPI:
    settings.validate()
    runtime_attestor = upstream_attestor or verify_runtime_attestation
    principal_verifier = settings.principal_verifier()
    state: dict[str, Any] = {
        "soul": None,
        "upstream": None,
        "ledger": None,
        "t5_egress": None,
    }

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        settings.soul_db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(settings.soul_db.parent, 0o700)
        _assert_no_symlink_components(settings.soul_db, "soul.db")
        if settings.soul_db.is_symlink():
            raise ValueError("soul.db must never be a symlink")
        if not settings.soul_db.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(settings.soul_db, flags, 0o600)
            os.close(fd)
        ledger = ConversationLedger(settings.conversation_ledger)
        ledger.initialize()
        t5_egress = SQLiteT5EgressStore(settings.t5_state_path)
        await t5_egress.initialize()
        headers = {}
        key = os.environ.get(settings.upstream_api_key_env, "").strip()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        client = httpx.AsyncClient(
            timeout=settings.timeout_seconds,
            headers=headers,
            transport=upstream_transport,
            trust_env=False,
        )
        renewal_task = None
        if config_path is not None and (config_path.parent / "soul-dni-authority.json").exists():
            async def renewal_watch() -> None:
                from soul_platform.dni_online import renew_dni_online_if_due

                while True:
                    await asyncio.sleep(6 * 60 * 60)
                    try:
                        renewed = await asyncio.to_thread(
                            renew_dni_online_if_due,
                            config=config_path,
                            restart=False,
                        )
                    except Exception:
                        # The live per-request DNI gate remains authoritative.
                        # A transient outage before expiry is retried; after
                        # expiry every operational request is already denied.
                        continue
                    if renewed:
                        shutdown = getattr(_app.state, "request_shutdown", None)
                        if shutdown is not None:
                            shutdown()
                        return

            renewal_task = asyncio.create_task(
                renewal_watch(), name="soul-dni-renewal-watch"
            )
        try:
            soul_config = SoulConfig(
                backend="sqlite",
                backend_url=str(settings.soul_db),
                embedding_provider=settings.embedding_provider,
                embedding_dimensions=settings.embedding_dimensions,
                memory_vector_index=settings.memory_vector_index,
                ollama_embedding_model=settings.embedding_model,
                ollama_embedding_url=settings.embedding_url,
                ollama_embedding_timeout=settings.embedding_timeout_seconds,
                dni_credential_path=str(settings.dni_credential_file),
                dni_trust_store_path=str(settings.dni_trust_store_file),
                dni_trust_store_sha256=settings.dni_trust_store_sha256,
                machine_soul_id=settings.machine_soul_id,
            )
            embedding = None
            if settings.embedding_provider == "bge-m3":
                embedding = LocalBgeM3Embedding(
                    model=settings.embedding_model,
                    url=settings.embedding_url,
                    timeout=settings.embedding_timeout_seconds,
                    dimensions=settings.embedding_dimensions,
                )
            async with Soul.create(
                settings.soul_name, config=soul_config, embedding=embedding
            ) as soul:
                if settings.soul_db.exists() and os.name != "nt":
                    os.chmod(settings.soul_db, 0o600)
                state["soul"] = soul
                state["upstream"] = client
                state["ledger"] = ledger
                state["t5_egress"] = t5_egress
                if settings.t5_mode == "compatibility-single-owner":
                    with sqlite3.connect(settings.soul_db) as connection:
                        legacy_ids = [
                            row[0]
                            for row in connection.execute(
                                "SELECT id FROM memories WHERE invalid_at IS NULL"
                            )
                        ]
                    await t5_egress.bind_legacy_memories(
                        soul_id=settings.machine_soul_id,
                        memory_ids=legacy_ids,
                        tenant=settings.t5_tenant,
                        owner_subject=settings.t5_owner_subject,
                    )
                yield
        finally:
            if renewal_task is not None:
                renewal_task.cancel()
                try:
                    await renewal_task
                except asyncio.CancelledError:
                    pass
            state["soul"] = None
            state["upstream"] = None
            state["ledger"] = None
            state["t5_egress"] = None
            await client.aclose()

    app = FastAPI(title="SOUL Proxy", version="1", lifespan=lifespan)

    @app.middleware("http")
    async def require_live_soul_dni(request: Request, call_next):
        # Shutdown remains available so an expired instance can be stopped
        # cleanly. Every operational surface revalidates the renewable SOUL
        # credential and signed revocation snapshot before doing any work.
        if request.url.path != "/admin/shutdown":
            try:
                settings.verified_dni("soul-platform")
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "SOUL DNI renewal required",
                        "soul_connected": False,
                    },
                )
        response = await call_next(request)
        if request.url.path != "/admin/shutdown":
            try:
                settings.verified_dni("soul-platform")
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "SOUL DNI renewal required",
                        "soul_connected": False,
                    },
                )
        return response

    def require_token(authorization: str | None, x_soul_token: str | None) -> None:
        expected = settings.read_token()
        provided = x_soul_token or ""
        if authorization and authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        if not hmac.compare_digest(provided.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="local SOUL token required")

    def authenticated_interlocutor(
        x_soul_principal: str | None,
    ) -> VerifiedPrincipal | None:
        if settings.t5_mode == "locked":
            return None
        if settings.t5_mode == "compatibility-single-owner":
            return VerifiedPrincipal(
                tenant=settings.t5_tenant.strip().casefold(),
                actor=settings.t5_owner_subject.strip().casefold(),
                key_id="local-single-owner-compatibility",
                expires_at=0,
                session_id=f"legacy:{settings.machine_soul_id}",
                audience=settings.machine_soul_id,
            )
        if not x_soul_principal or principal_verifier is None:
            raise HTTPException(status_code=401, detail="signed SOUL principal required")
        try:
            principal = principal_verifier.verify(x_soul_principal.strip())
        except AuthenticationDenied:
            raise HTTPException(
                status_code=401, detail="signed SOUL principal invalid"
            ) from None
        if principal.tenant.strip().casefold() != settings.t5_tenant.strip().casefold():
            raise HTTPException(status_code=403, detail="SOUL principal tenant denied")
        if not principal.session_id:
            raise HTTPException(status_code=401, detail="signed SOUL session required")
        if not hmac.compare_digest(
            principal.audience.encode(), settings.machine_soul_id.encode()
        ):
            raise HTTPException(status_code=403, detail="SOUL principal audience denied")
        return principal

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": state["soul"] is not None,
            "machine_soul_id": settings.machine_soul_id,
            "baseline_hash": settings.baseline_hash,
        }

    @app.post("/admin/shutdown")
    async def shutdown(
        authorization: str | None = Header(None),
        x_soul_token: str | None = Header(None),
    ) -> dict[str, bool]:
        require_token(authorization, x_soul_token)
        callback = getattr(app.state, "request_shutdown", None)
        if callback is None:
            raise HTTPException(status_code=503, detail="shutdown controller unavailable")
        callback()
        return {"ok": True}

    @app.get("/ready")
    async def ready() -> JSONResponse:
        brain = False
        try:
            response = await state["upstream"].get(
                f"{settings.upstream_base_url}/models"
            )
            payload = response.json() if response.is_success else {}
            models = payload.get("data") if isinstance(payload, dict) else []
            brain = response.is_success and any(
                isinstance(item, dict) and item.get("id") == settings.upstream_model
                for item in (models or [])
            )
        except (httpx.HTTPError, ValueError):
            pass
        ready_now = state["soul"] is not None and brain
        return JSONResponse(
            status_code=200 if ready_now else 503,
            content={
                "ready": ready_now,
                "soul_loaded": state["soul"] is not None,
                "brain_reachable": brain,
            },
        )

    @app.get("/v1/models")
    async def models(
        authorization: str | None = Header(None),
        x_soul_token: str | None = Header(None),
    ) -> dict[str, Any]:
        require_token(authorization, x_soul_token)
        return {
            "object": "list",
            "data": [{"id": settings.upstream_model, "object": "model", "owned_by": "soul"}],
        }

    async def soul_context(
        query: str,
        principal: VerifiedPrincipal | None,
    ) -> tuple[str, list[dict[str, Any]], str]:
        try:
            runtime_is_attested = bool(runtime_attestor(settings))
        except Exception:
            runtime_is_attested = False
        if not runtime_is_attested:
            return (
                "El upstream local no está atestado para recibir identidad o memoria SOUL. "
                "Responde solo con conocimiento general y no inventes datos personales.",
                [],
                "blocked-unattested-upstream",
            )
        soul = state["soul"]
        egress = state["t5_egress"]
        if soul is None or egress is None:
            raise HTTPException(status_code=503, detail="machine soul is not loaded")
        try:
            boot = ""
            if (
                principal is not None
                and principal.tenant.strip().casefold() == settings.t5_tenant.strip().casefold()
                and principal.actor.strip().casefold()
                == settings.t5_owner_subject.strip().casefold()
            ):
                boot = await soul.boot()
            hits = (
                await soul.memory.search(query, limit=settings.mem_k)
                if query and principal is not None
                else []
            )
        except Exception:
            raise HTTPException(status_code=503, detail="machine soul recall failed") from None
        if principal is None:
            decision = None
            hits = []
            egress_reason = "locked-no-verified-interlocutor"
        else:
            try:
                decision = await egress.evaluate(
                    soul_id=settings.machine_soul_id,
                    tenant=principal.tenant,
                    session_id=principal.session_id,
                    interlocutor=principal.actor,
                    memory_ids=[hit.memory.id for hit in hits],
                )
            except Exception:
                raise HTTPException(
                    status_code=503, detail="machine soul egress policy failed"
                ) from None
            allowed_ids = set(decision.allowed_ids)
            hits = [hit for hit in hits if str(hit.memory.id) in allowed_ids]
            egress_reason = decision.reason
        evidence = [
            {
                "memory_id": hit.memory.id,
                "content_sha256": hashlib.sha256(hit.memory.content.encode()).hexdigest(),
                "score": round(float(hit.score), 6),
            }
            for hit in hits
        ]
        memories = "\n".join(f"- {hit.memory.content}" for hit in hits) or "(ninguna)"
        guard = (
            "Usa exclusivamente las memorias suministradas para datos personales. "
            "Si el dato no aparece, responde honestamente que no lo recuerdas; no lo inventes."
        )
        scoped_boot = boot or "(contexto de identidad privado no autorizado)"
        return (
            f"{guard}\n\n{scoped_boot}\n\n## Memorias relevantes\n{memories}",
            evidence,
            egress_reason,
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        authorization: str | None = Header(None),
        x_soul_token: str | None = Header(None),
        x_soul_principal: str | None = Header(None),
        x_soul_remember: str | None = Header(None),
    ) -> JSONResponse:
        require_token(authorization, x_soul_token)
        principal = authenticated_interlocutor(x_soul_principal)
        remember_header = (x_soul_remember or "").strip().lower()
        if remember_header not in {"", "true", "false"}:
            raise HTTPException(status_code=422, detail="X-Soul-Remember must be true or false")
        should_log = settings.auto_store if not remember_header else remember_header == "true"
        declared = request.headers.get("content-length")
        if declared:
            try:
                declared_size = int(declared)
            except ValueError:
                raise HTTPException(status_code=400, detail="invalid content-length") from None
            if declared_size < 0:
                raise HTTPException(status_code=400, detail="invalid content-length")
            if declared_size > settings.max_request_bytes:
                raise HTTPException(status_code=413, detail="request too large")
        raw = await request.body()
        if len(raw) > settings.max_request_bytes:
            raise HTTPException(status_code=413, detail="request too large")
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="invalid JSON") from None
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            raise HTTPException(status_code=422, detail="messages must be a list")
        fact_request = body.pop("soul_memory", None)
        fact_content = ""
        fact_importance = 5
        if fact_request is not None:
            if not isinstance(fact_request, dict):
                raise HTTPException(status_code=422, detail="soul_memory must be an object")
            if set(fact_request) - {"content", "importance"}:
                raise HTTPException(
                    status_code=422,
                    detail="soul_memory contains unsupported ownership metadata",
                )
            fact_content = fact_request.get("content", "")
            fact_importance = fact_request.get("importance", 5)
            if (
                not isinstance(fact_content, str)
                or not 1 <= len(fact_content.strip()) <= 4096
                or "?" in fact_content
                or not isinstance(fact_importance, int)
                or isinstance(fact_importance, bool)
                or not 1 <= fact_importance <= 10
            ):
                raise HTTPException(
                    status_code=422,
                    detail="soul_memory requires a declarative content and importance 1..10",
                )
            fact_content = fact_content.strip()
            if principal is None:
                raise HTTPException(
                    status_code=403,
                    detail="semantic memory writes require a verified interlocutor",
                )
        stream_value = body.get("stream")
        if stream_value not in (None, False, True):
            raise HTTPException(status_code=422, detail="stream must be a boolean")
        wants_stream = stream_value is True
        messages = body["messages"]
        if not 1 <= len(messages) <= 256:
            raise HTTPException(status_code=422, detail="messages count outside safe range")
        last_user = ""
        for message in messages:
            if not isinstance(message, dict) or message.get("role") not in VALID_ROLES:
                raise HTTPException(status_code=422, detail="invalid message role")
            if not isinstance(message.get("content"), str):
                raise HTTPException(status_code=422, detail="message content must be text")
            if message["role"] == "user":
                last_user = message["content"]
        block, evidence, egress_reason = await soul_context(last_user, principal)
        forwarded = dict(body)
        forwarded["messages"] = [{"role": "system", "content": block}] + messages
        forwarded["model"] = settings.upstream_model
        forwarded["stream"] = wants_stream
        try:
            async with state["upstream"].stream(
                "POST", f"{settings.upstream_base_url}/chat/completions", json=forwarded
            ) as response:
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > settings.max_response_bytes:
                        return JSONResponse(status_code=502, content={"error": "upstream response too large"})
                upstream_status = response.status_code
                upstream_content_type = response.headers.get("content-type", "")
        except (httpx.HTTPError, ValueError, json.JSONDecodeError):
            return JSONResponse(status_code=502, content={"error": "upstream request failed"})
        store_status = "disabled"
        headers = {
            "X-Soul-Id": settings.machine_soul_id,
            "X-Soul-Baseline": settings.baseline_hash,
            "X-Soul-Memories": str(len(evidence)),
            "X-Soul-Memory-Ids": ",".join(str(item["memory_id"]) for item in evidence),
            "X-Soul-Memory-SHA256": ",".join(item["content_sha256"] for item in evidence),
            "X-Soul-Egress": egress_reason,
            "X-Soul-Store": store_status,
        }
        if wants_stream:
            # Grok Build and other OpenAI-compatible clients require SSE when
            # stream=true. Buffer the bounded upstream response before exposing
            # status/headers so an oversized body still fails closed with 502
            # instead of becoming a truncated 200 after headers were committed.
            # The client still receives valid SSE bytes; v1 intentionally trades
            # token-by-token latency for deterministic size enforcement.
            if response.is_success and "text/event-stream" not in upstream_content_type.lower():
                return JSONResponse(
                    status_code=502,
                    content={"error": "upstream streaming response is not event-stream"},
                    headers=headers,
                )
            if response.is_success:
                try:
                    data_lines = [
                        line[5:].strip()
                        for line in bytes(content).decode("utf-8").splitlines()
                        if line.startswith("data:")
                    ]
                    if not data_lines or data_lines[-1] != "[DONE]":
                        raise ValueError("incomplete event stream")
                    for payload in data_lines[:-1]:
                        _strict_json_loads(payload)
                except (UnicodeDecodeError, ValueError):
                    return JSONResponse(
                        status_code=502,
                        content={"error": "upstream streaming response is invalid"},
                        headers=headers,
                    )
            data = None
        else:
            try:
                data = _strict_json_loads(content)
                # Prove that Starlette's strict JSON serializer can produce the
                # response before any persistent memory mutation is attempted.
                json.dumps(data, ensure_ascii=False, allow_nan=False)
            except (UnicodeDecodeError, ValueError):
                return JSONResponse(
                    status_code=502,
                    content={"error": "upstream request failed"},
                    headers=headers,
                )

        # Memory mutation is deliberately after response validation. A client
        # that observes 502 may safely retry without duplicating or poisoning
        # the persistent soul with a request whose response was unusable.
        if response.is_success and last_user and should_log:
            try:
                state["ledger"].append(last_user, bytes(content))
                store_status = "ledger"
            except Exception:
                # The upstream operation already happened. Preserve its response so a
                # client retry cannot duplicate model work or cost.
                store_status = "failed"
        if response.is_success and fact_content:
            try:
                from soul_platform.living_soul import propose_memory_candidate

                proposal = propose_memory_candidate(
                    settings,
                    client_id=f"proxy:{principal.actor}",
                    source_event_id=(
                        f"{principal.session_id}:"
                        f"{hashlib.sha256(raw).hexdigest()}"
                    ),
                    content=fact_content,
                    importance=fact_importance,
                    provenance={
                        "session_id": principal.session_id,
                        "surface": "openai-proxy",
                    },
                )
                if store_status == "disabled":
                    store_status = "fact-pending-review"
                elif store_status == "ledger":
                    store_status = "ledger+fact-pending-review"
                else:
                    store_status = "ledger-failed+fact-pending-review"
                headers["X-Soul-Candidate-Id"] = str(proposal["candidate_id"])
            except Exception:
                store_status = (
                    "ledger+candidate-failed" if store_status == "ledger" else "failed"
                )
        headers["X-Soul-Store"] = store_status
        if wants_stream:
            return Response(
                status_code=upstream_status,
                content=bytes(content),
                headers={**headers, "content-type": upstream_content_type or "text/event-stream"},
            )
        return JSONResponse(status_code=upstream_status, content=data, headers=headers)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m soul_platform.proxy")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = Path(args.config).expanduser().resolve()
    from soul_platform.dni_online import attempt_startup_renewal

    attempt_startup_renewal(config)
    settings = ProxySettings.from_toml(config)
    run_proxy(settings, config_path=config)


def run_proxy(settings: ProxySettings, *, config_path: Path | None = None) -> None:
    import uvicorn

    app = create_app(settings, config_path=config_path)
    config_options: dict[str, Any] = {
        "host": settings.host,
        "port": settings.port,
    }
    # Windows autostart uses pythonw.exe so no console flashes at logon.
    # pythonw deliberately exposes no stdout/stderr; Uvicorn's default logging
    # config otherwise exits before binding the socket.
    if sys.stdout is None or sys.stderr is None:
        config_options.update(log_config=None, access_log=False)
    server = uvicorn.Server(uvicorn.Config(app, **config_options))
    app.state.request_shutdown = lambda: setattr(server, "should_exit", True)
    server.run()


if __name__ == "__main__":
    main()
