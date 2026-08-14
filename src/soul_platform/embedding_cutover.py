"""Fail-closed MachineSoul cutover from 128-d embeddings to BGE-M3/portable ANN.

The expensive re-embedding is delegated to ``soul-framework==0.4.3`` and
always produces a separate candidate.  Activation never deletes the original
database: it preserves a serialized backup and atomically points the config at
the verified candidate while both SQLite generations are write-fenced.  A
rollback restores the exact prior config only if no post-cutover logical write
would be lost.

The caller must stop SOUL Platform before ``activate`` or ``rollback``.
Exclusive SQLite transactions make this requirement executable, not advisory.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soul_framework.embedding_migration import migrate_sqlite_embeddings

from soul_platform.local_embedding import LocalBgeM3Embedding
from soul_platform.proxy import ProxySettings

EMBEDDING_BLOCK = """[embedding]
provider = "bge-m3"
dimensions = 1024
model = "bge-m3"
url = "http://127.0.0.1:11434/api/embed"
timeout_seconds = 60
vector_index = "auto"
"""


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _logical_sqlite_sha256_connection(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for statement in connection.iterdump():
        digest.update(statement.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _logical_sqlite_sha256(path: Path) -> str:
    """Hash SQLite schema/data while ignoring page-layout and journal-mode bytes."""
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        return _logical_sqlite_sha256_connection(connection)
    finally:
        connection.close()


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    if os.name == "nt" and path.exists():
        return bool(getattr(os.lstat(path), "st_file_attributes", 0) & 0x400)
    return False


def _regular_file(path: Path, label: str) -> Path:
    path = _managed_path(path, label)
    if _is_link_or_reparse(path) or not path.is_file():
        raise ValueError(f"{label} must be a regular file, never a symlink/reparse point")
    return path.resolve()


def _managed_path(path: Path, label: str) -> Path:
    """Resolve a controlled path even when a crash temporarily removed its leaf."""
    path = path.expanduser().absolute()
    _safe_parent(path, label)
    if path.exists() and _is_link_or_reparse(path):
        raise ValueError(f"{label} must never be a symlink/reparse point")
    return path.resolve(strict=False)


def _safe_parent(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for part in path.absolute().parts[1:-1]:
        current /= part
        if current.exists() and _is_link_or_reparse(current):
            raise ValueError(f"{label} contains a symlink/reparse path component")


def _fsync_file(path: Path) -> None:
    """Make file contents and metadata durable before/after a namespace move."""
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    """Persist directory entries on POSIX; Windows has no portable dir fsync."""
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _after_durable_replace(_boundary: str) -> None:
    """Fault-injection seam: production is a no-op, tests emulate process death."""


def _after_activation_journal(
    _source: sqlite3.Connection, _candidate: sqlite3.Connection
) -> None:
    """Fault/adversary seam while source and candidate write fences are held."""


def _after_rollback_journal(
    _source: sqlite3.Connection, _candidate: sqlite3.Connection
) -> None:
    """Fault/adversary seam while both rollback generations remain fenced."""


def _durable_replace(source: Path, target: Path, *, boundary: str | None = None) -> None:
    """Replace a path and durably commit both its bytes and directory entries."""
    source = Path(source)
    target = Path(target)
    _fsync_file(source)
    os.replace(source, target)
    _fsync_file(target)
    _fsync_directory(target.parent)
    if source.parent != target.parent:
        _fsync_directory(source.parent)
    if boundary is not None:
        _after_durable_replace(boundary)


def _atomic_write(path: Path, payload: bytes, *, boundary: str | None = None) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        _durable_replace(Path(temporary), path, boundary=boundary)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_checkpoint(path: Path) -> dict[str, Any]:
    path = _regular_file(path, "checkpoint")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid migration checkpoint: {exc}") from exc
    if state.get("version") != 1 or not isinstance(state.get("plan"), dict):
        raise ValueError("unsupported migration checkpoint")
    return state


def _save_checkpoint(path: Path, state: dict[str, Any]) -> None:
    _atomic_write(
        path,
        (json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
    )


def _exclusive_sqlite_probe(path: Path, *, checkpoint_wal: bool = False) -> None:
    """Prove exclusivity and checkpoint a clean WAL before byte promotion.

    A stopped SQLite database may legitimately leave WAL/SHM files behind.
    Their mere existence is not proof that a writer is alive.  The exclusive
    transaction is the actual stop gate; once obtained, a TRUNCATE checkpoint
    folds committed WAL bytes into the database before its SHA is trusted.
    """
    wal = Path(f"{path}-wal")
    if wal.exists() and wal.stat().st_size:
        header = wal.read_bytes()[:4]
        if len(header) != 4 or int.from_bytes(header, "big") not in {
            0x377F0682,
            0x377F0683,
        }:
            raise RuntimeError("MachineSoul WAL is corrupt; stop SOUL Platform first")
    connection = sqlite3.connect(path, timeout=0, isolation_level=None)
    try:
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute("ROLLBACK")
        if checkpoint_wal:
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint and int(checkpoint[0]) != 0:
                raise RuntimeError("MachineSoul WAL checkpoint is busy")
    except sqlite3.OperationalError as exc:
        raise RuntimeError("MachineSoul database is busy; stop SOUL Platform first") from exc
    finally:
        connection.close()


def _verify_sqlite_candidate(path: Path, expected_rows: dict[str, Any]) -> None:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        result = connection.execute("PRAGMA quick_check").fetchall()
        if result != [("ok",)]:
            raise ValueError(f"candidate SQLite quick_check failed: {result}")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "memories" not in tables:
            raise ValueError("candidate memories schema is missing")
        for table in ("memories", "procedural_memories"):
            expected = int(expected_rows.get(table, 0))
            if table not in tables:
                if expected:
                    raise ValueError(f"candidate {table} schema is missing")
                continue
            columns = {
                str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')
            }
            if not {"id", "embedding"}.issubset(columns):
                raise ValueError(f"candidate {table} schema lacks id/embedding")
            migrated, mixed = connection.execute(
                f'SELECT COUNT(*), SUM(CASE WHEN length(embedding) != 4096 THEN 1 ELSE 0 END) '
                f'FROM "{table}" WHERE embedding IS NOT NULL'
            ).fetchone()
            if int(migrated) != expected or int(mixed or 0) != 0:
                raise ValueError(
                    f"candidate {table} embedding gate failed: "
                    f"rows={migrated}/{expected}, non_1024={int(mixed or 0)}"
                )
    finally:
        connection.close()


def _probe_bge() -> None:
    """Require a live local BGE-M3 endpoint returning finite 1024-d output."""
    provider = LocalBgeM3Embedding(dimensions=1024)
    try:
        vector = asyncio.run(provider.embed("SOUL BGE-M3 cutover readiness probe"))
    except Exception as exc:
        raise RuntimeError("local BGE-M3 readiness probe failed") from exc
    if len(vector) != 1024 or not all(math.isfinite(float(value)) for value in vector):
        raise RuntimeError("local BGE-M3 readiness probe returned invalid dimensions")


def _target_config(previous: bytes, *, active_db: Path | None = None) -> bytes:
    text = previous.decode("utf-8")
    replacement = f"{EMBEDDING_BLOCK.rstrip()}\n\n"
    pattern = re.compile(
        r"(?ms)^[ \t]*\[embedding\][ \t]*\r?\n.*?"
        r"(?=^[ \t]*\[[^\]]+\][ \t]*\r?$|\Z)"
    )
    if pattern.search(text):
        text = pattern.sub(replacement, text, count=1)
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text = f"{text}\n{replacement}"
    if active_db is not None:
        soul = re.compile(
            r"(?ms)(^[ \t]*\[soul\][ \t]*\r?\n)(.*?)(?=^[ \t]*\[[^\]]+\][ \t]*\r?$|\Z)"
        )
        match = soul.search(text)
        if match is None:
            raise ValueError("config is missing the soul section")
        body = match.group(2)
        quoted = json.dumps(str(active_db.resolve()), ensure_ascii=False)
        db_line = re.compile(r"(?m)^[ \t]*db[ \t]*=.*$")
        if not db_line.search(body):
            raise ValueError("config soul section is missing db")
        body = db_line.sub(f"db = {quoted}", body, count=1)
        text = text[: match.start(2)] + body + text[match.end(2) :]
    return text.encode("utf-8")


def _migration_hash(connection: sqlite3.Connection, *, include_vectors: bool) -> str:
    """Match Core's migration fingerprint using the already-frozen connection."""
    digest = hashlib.sha256()
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    for table in sorted(tables):
        columns = [
            str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')
        ]
        kept = [column for column in columns if (column == "embedding") == include_vectors]
        if include_vectors:
            if table not in {"memories", "procedural_memories"} or "embedding" not in columns:
                continue
            digest.update(f"table:{table}\n".encode())
            for row_id, embedding in connection.execute(
                f'SELECT id,embedding FROM "{table}" ORDER BY id'
            ):
                blob = bytes(embedding) if embedding is not None else b""
                digest.update(str(int(row_id)).encode())
                digest.update(b":")
                digest.update(hashlib.sha256(blob).digest())
            continue
        kept = [column for column in columns if column != "embedding"]
        if not kept:
            continue
        quoted = ",".join('"' + column.replace('"', '""') + '"' for column in kept)
        digest.update(f"table:{table}:{','.join(kept)}\n".encode())
        for row in connection.execute(f'SELECT {quoted} FROM "{table}" ORDER BY rowid'):
            digest.update(
                json.dumps(
                    list(row), ensure_ascii=False, separators=(",", ":"), default=str
                ).encode()
            )
            digest.update(b"\n")
    return digest.hexdigest()


def _sqlite_schema_sha256(connection: sqlite3.Connection) -> str:
    """Hash logical schema metadata without reopening the locked database file."""
    digest = hashlib.sha256()
    for row in connection.execute(
        "SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master "
        "ORDER BY type,name,tbl_name,sql"
    ):
        digest.update(
            json.dumps(list(row), ensure_ascii=False, separators=(",", ":")).encode()
        )
        digest.update(b"\n")
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    digest.update(f"user_version:{user_version}\n".encode())
    return digest.hexdigest()


@contextmanager
def _frozen_source(path: Path):
    """Hold SQLite's write fence until the config pointer is durably switched."""
    wal = Path(f"{path}-wal")
    if wal.exists() and wal.stat().st_size:
        header = wal.read_bytes()[:4]
        if len(header) != 4 or int.from_bytes(header, "big") not in {
            0x377F0682,
            0x377F0683,
        }:
            raise RuntimeError("MachineSoul WAL is corrupt; stop SOUL Platform first")
    connection = sqlite3.connect(path, timeout=0, isolation_level=None)
    try:
        connection.execute("BEGIN EXCLUSIVE")
        yield connection
        connection.execute("ROLLBACK")
    except sqlite3.OperationalError as exc:
        raise RuntimeError("MachineSoul database is busy; stop SOUL Platform first") from exc
    finally:
        connection.close()


async def prepare(
    source: Path,
    *,
    candidate: Path,
    checkpoint: Path,
    batch_size: int = 256,
    resume: bool = False,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """Build/resume a separate 1024-d candidate from a stable source snapshot."""
    source = _regular_file(source, "source")
    # Consolidate a valid crash-left WAL before Core fingerprints the source.
    # This changes SQLite's byte representation, never its logical rows.
    _exclusive_sqlite_probe(source, checkpoint_wal=True)
    provider = LocalBgeM3Embedding(dimensions=1024)
    return await migrate_sqlite_embeddings(
        source,
        provider,
        candidate=candidate,
        checkpoint=checkpoint,
        source_dimensions=128,
        target_dimensions=1024,
        batch_size=batch_size,
        resume=resume,
        max_batches=max_batches,
        provider_name="bge-m3:bge-m3",
    )


def verify_candidate(checkpoint: Path) -> dict[str, str]:
    """Bind the completed checkpoint to the still-live source and candidate bytes."""
    state = _load_checkpoint(checkpoint)
    if state.get("status") != "completed":
        raise ValueError("migration is not completed")
    plan = state["plan"]
    source = _regular_file(Path(plan["source"]), "source")
    candidate = _regular_file(Path(plan["candidate"]), "candidate")
    source_sha = _sha256(source)
    candidate_sha = _sha256(candidate)
    if source_sha != plan.get("source_sha256"):
        raise ValueError("source changed after migration")
    if candidate_sha != state.get("candidate_sha256"):
        raise ValueError("candidate bytes do not match checkpoint")
    if plan.get("source_dimensions") != 128 or plan.get("target_dimensions") != 1024:
        raise ValueError("checkpoint is not a 128-to-1024 migration")
    if not plan.get("source_nonvector_sha256") or not plan.get("source_vector_sha256"):
        raise ValueError("checkpoint lacks source logical fingerprints")
    _verify_sqlite_candidate(candidate, plan.get("rows") or {})
    expected_nonvector = plan["source_nonvector_sha256"]
    with sqlite3.connect(f"file:{candidate.resolve()}?mode=ro", uri=True) as connection:
        if _migration_hash(connection, include_vectors=False) != expected_nonvector:
            raise ValueError("candidate non-vector content differs from source")
    return {"source_sha256": source_sha, "candidate_sha256": candidate_sha}


def _digest_if_file(path: Path, label: str) -> str | None:
    path = _managed_path(path, label)
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError(f"{label} is not a regular file")
    return _sha256(path)


def _require_known_digest(
    path: Path, label: str, allowed: set[str | None]
) -> str | None:
    digest = _digest_if_file(path, label)
    if digest not in allowed:
        raise RuntimeError(f"{label} has ambiguous bytes; refusing recovery")
    return digest


def _validate_active(config: Path, state: dict[str, Any]) -> None:
    activation = state["activation"]
    if activation.get("strategy") == "config-pointer-v1":
        source = _regular_file(Path(state["plan"]["source"]), "preserved source")
        candidate = _regular_file(Path(state["plan"]["candidate"]), "active database")
        source_backup = _regular_file(
            Path(activation["source_backup"]), "source backup"
        )
        expected_nonvector = state["plan"].get("source_nonvector_sha256")
        expected_vector = state["plan"].get("source_vector_sha256")
        if expected_nonvector:
            with sqlite3.connect(
                f"file:{source.resolve()}?mode=ro", uri=True
            ) as connection:
                if (
                    _migration_hash(connection, include_vectors=False)
                    != expected_nonvector
                    or _migration_hash(connection, include_vectors=True)
                    != expected_vector
                    or _sqlite_schema_sha256(connection)
                    != activation["source_schema_sha256"]
                ):
                    raise RuntimeError(
                        "preserved source differs from the recorded original"
                    )
        if _sha256(source_backup) != activation["source_backup_sha256"]:
            raise RuntimeError("active source backup differs from the recorded original")
        candidate_sha = _sha256(candidate)
        if candidate_sha != activation["candidate_sha256"]:
            with sqlite3.connect(
                f"file:{candidate.resolve()}?mode=ro", uri=True
            ) as connection:
                if (
                    _migration_hash(connection, include_vectors=False)
                    != activation["candidate_nonvector_sha256"]
                    or _migration_hash(connection, include_vectors=True)
                    != activation["candidate_vector_sha256"]
                    or _sqlite_schema_sha256(connection)
                    != activation["candidate_schema_sha256"]
                ):
                    raise RuntimeError(
                        "active database differs from the recorded candidate"
                    )
        if _sha256(config) != activation["target_config_sha256"]:
            raise RuntimeError("active config differs from the recorded target")
        loaded = ProxySettings.from_toml(config)
        if loaded.soul_db.resolve() != candidate:
            raise RuntimeError("activated config points to another database")
        if (
            loaded.embedding_provider,
            loaded.embedding_dimensions,
            loaded.embedding_model,
            loaded.memory_vector_index,
        ) != ("bge-m3", 1024, "bge-m3", "auto"):
            raise RuntimeError("activated config is not BGE-M3/1024/auto")
        return
    source = _regular_file(Path(state["plan"]["source"]), "active database")
    source_backup = _regular_file(
        Path(activation["source_backup"]), "source backup"
    )
    candidate = _managed_path(Path(state["plan"]["candidate"]), "candidate")
    if candidate.exists():
        raise RuntimeError("active cutover still has a candidate path")
    active_sha = _sha256(source)
    if active_sha != activation["candidate_sha256"]:
        expected_logical = activation.get("candidate_logical_sha256")
        if not expected_logical or _logical_sqlite_sha256(source) != expected_logical:
            raise RuntimeError("active database differs from the recorded candidate")
    if _sha256(source_backup) != activation["source_sha256"]:
        raise RuntimeError("active source backup differs from the recorded original")
    if _sha256(config) != activation["target_config_sha256"]:
        raise RuntimeError("active config differs from the recorded target")
    loaded = ProxySettings.from_toml(config)
    if loaded.soul_db.resolve() != source:
        raise RuntimeError("activated config points to another database")
    if (
        loaded.embedding_provider,
        loaded.embedding_dimensions,
        loaded.embedding_model,
        loaded.memory_vector_index,
    ) != ("bge-m3", 1024, "bge-m3", "auto"):
        raise RuntimeError("activated config is not BGE-M3/1024/auto")


def _recover_interrupted_activation(
    config: Path, checkpoint: Path, state: dict[str, Any]
) -> dict[str, Any]:
    """Recover an ``activating`` journal to the exact pre-cutover generation."""
    activation = state["activation"]
    if activation.get("strategy") == "config-pointer-v1":
        previous_config_sha = str(activation["previous_config_sha256"])
        target_config_sha = str(activation["target_config_sha256"])
        config_backup = _regular_file(
            Path(activation["config_backup"]), "config backup"
        )
        if _sha256(config_backup) != previous_config_sha:
            raise RuntimeError("config backup changed; refusing activation recovery")
        config_digest = _require_known_digest(
            config, "config", {previous_config_sha, target_config_sha}
        )
        if config_digest == target_config_sha:
            activation.update(
                {
                    "status": "active",
                    "recovered_at": datetime.now(UTC).isoformat(),
                }
            )
            _validate_active(config, state)
        else:
            activation.update(
                {
                    "status": "activation-failed-rolled-back",
                    "recovered_at": datetime.now(UTC).isoformat(),
                }
            )
        _save_checkpoint(checkpoint, state)
        return state
    source_sha = str(activation["source_sha256"])
    candidate_sha = str(activation["candidate_sha256"])
    previous_config_sha = str(activation["previous_config_sha256"])
    target_config_sha = str(activation["target_config_sha256"])
    source = _managed_path(Path(state["plan"]["source"]), "source")
    candidate = _managed_path(Path(state["plan"]["candidate"]), "candidate")
    source_backup = _managed_path(
        Path(activation["source_backup"]), "source backup"
    )
    config_backup = _regular_file(
        Path(activation["config_backup"]), "config backup"
    )
    if _sha256(config_backup) != previous_config_sha:
        raise RuntimeError("config backup changed; refusing activation recovery")

    source_digest = _require_known_digest(
        source, "source", {None, source_sha, candidate_sha}
    )
    candidate_digest = _require_known_digest(
        candidate, "candidate", {None, candidate_sha}
    )
    backup_digest = _require_known_digest(
        source_backup, "source backup", {None, source_sha}
    )
    config_digest = _require_known_digest(
        config, "config", {previous_config_sha, target_config_sha}
    )

    # A promoted candidate is first returned to its named path.  The original
    # is then restored from the durable backup.  Every accepted layout has
    # exactly one copy of each generation, so recovery never guesses.
    if source_digest == candidate_sha:
        if candidate_digest is not None:
            raise RuntimeError("candidate generation is duplicated; refusing recovery")
        _durable_replace(source, candidate)
        source_digest = None
        candidate_digest = candidate_sha
    if source_digest is None:
        if backup_digest != source_sha:
            raise RuntimeError("original generation is missing; refusing recovery")
        _durable_replace(source_backup, source)
        source_digest = source_sha
        backup_digest = None
    if source_digest != source_sha or candidate_digest != candidate_sha:
        raise RuntimeError("activation generations are incomplete after recovery")
    if config_digest != previous_config_sha:
        _atomic_write(config, config_backup.read_bytes())
    if _sha256(config) != previous_config_sha:
        raise RuntimeError("config recovery did not restore the prior bytes")

    activation.update(
        {
            "status": "activation-failed-rolled-back",
            "recovered_at": datetime.now(UTC).isoformat(),
        }
    )
    _save_checkpoint(checkpoint, state)
    return state


def activate(config: Path, checkpoint: Path) -> dict[str, Any]:
    """Point at the verified candidate while retaining a lossless rollback path."""
    config = _regular_file(config, "config")
    checkpoint = _regular_file(checkpoint, "checkpoint")
    state = _load_checkpoint(checkpoint)
    plan = state["plan"]
    source = _managed_path(Path(plan["source"]), "source")
    candidate = _managed_path(Path(plan["candidate"]), "candidate")
    if source.parent != candidate.parent or source.parent != config.parent:
        raise ValueError("config, source and candidate must share one directory")
    paths = (source, candidate, config, checkpoint)
    if len({path.resolve() for path in paths}) != len(paths):
        raise ValueError("config, checkpoint, source and candidate must be distinct")
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if left.exists() and right.exists() and os.path.samefile(left, right):
                raise ValueError("config, checkpoint, source and candidate must not alias")
    prior_activation = state.get("activation") or {}
    prior_status = prior_activation.get("status")
    if prior_status == "activating":
        state = _recover_interrupted_activation(config, checkpoint, state)
        prior_activation = state["activation"]
        prior_status = prior_activation["status"]
    if prior_status == "active":
        _validate_active(config, state)
        return state
    if prior_status == "activation-failed-rolled-back":
        state.pop("activation", None)
        _save_checkpoint(checkpoint, state)
    elif prior_activation:
        raise ValueError("checkpoint already contains an activation record")

    hashes = verify_candidate(checkpoint)
    state = _load_checkpoint(checkpoint)
    plan = state["plan"]
    source = _regular_file(Path(plan["source"]), "source")
    candidate = _regular_file(Path(plan["candidate"]), "candidate")
    # Probe before freezing the source.  Activation then holds SQLite's own
    # write fence through the durable config-pointer switch: the original path
    # is never renamed underneath a WAL writer.
    _probe_bge()
    previous_config = config.read_bytes()
    target_config = _target_config(previous_config, active_db=candidate)
    stamp = _timestamp()
    source_backup = source.with_name(f"{source.name}.pre-bge-{stamp}.backup")
    config_backup = config.with_name(f"{config.name}.pre-bge-{stamp}.backup")
    _safe_parent(source_backup, "source backup")
    _safe_parent(config_backup, "config backup")
    if source_backup.exists() or config_backup.exists():
        raise FileExistsError("cutover backup path already exists")

    try:
        with sqlite3.connect(
            f"file:{candidate.resolve()}?mode=ro", uri=True
        ) as candidate_before:
            candidate_nonvector_sha = _migration_hash(
                candidate_before, include_vectors=False
            )
            candidate_vector_sha = _migration_hash(
                candidate_before, include_vectors=True
            )
            candidate_schema_sha = _sqlite_schema_sha256(candidate_before)
        with _frozen_source(source) as frozen, _frozen_source(
            candidate
        ) as frozen_candidate:
            expected_nonvector = plan.get("source_nonvector_sha256")
            expected_vector = plan.get("source_vector_sha256")
            if expected_nonvector and (
                _migration_hash(frozen, include_vectors=False) != expected_nonvector
                or _migration_hash(frozen, include_vectors=True) != expected_vector
            ):
                raise RuntimeError("source changed before the fenced config switch")
            source_schema_sha = _sqlite_schema_sha256(frozen)
            if (
                _migration_hash(frozen_candidate, include_vectors=False)
                != candidate_nonvector_sha
                or _migration_hash(frozen_candidate, include_vectors=True)
                != candidate_vector_sha
                or _sqlite_schema_sha256(frozen_candidate) != candidate_schema_sha
            ):
                raise RuntimeError("candidate changed before the fenced config switch")
            # serialize() folds this connection's WAL view into a standalone,
            # crash-safe backup while the write fence is still held.
            _atomic_write(source_backup, frozen.serialize())
            source_backup_sha = _sha256(source_backup)
            _atomic_write(config_backup, previous_config)
            state["activation"] = {
                "strategy": "config-pointer-v1",
                "status": "activating",
                "started_at": datetime.now(UTC).isoformat(),
                "source_backup": str(source_backup),
                "config_backup": str(config_backup),
                "source_sha256": source_backup_sha,
                "source_backup_sha256": source_backup_sha,
                "source_schema_sha256": source_schema_sha,
                "candidate_sha256": hashes["candidate_sha256"],
                "candidate_nonvector_sha256": candidate_nonvector_sha,
                "candidate_vector_sha256": candidate_vector_sha,
                "candidate_schema_sha256": candidate_schema_sha,
                "previous_config_sha256": hashlib.sha256(previous_config).hexdigest(),
                "target_config_sha256": hashlib.sha256(target_config).hexdigest(),
            }
            _save_checkpoint(checkpoint, state)
            _after_activation_journal(frozen, frozen_candidate)
            _atomic_write(config, target_config, boundary="activate-config")
            loaded = ProxySettings.from_toml(config)
            if loaded.soul_db.resolve() != candidate:
                raise RuntimeError("activated config points to another database")
            if (
                loaded.embedding_provider,
                loaded.embedding_dimensions,
                loaded.embedding_model,
                loaded.memory_vector_index,
            ) != ("bge-m3", 1024, "bge-m3", "auto"):
                raise RuntimeError("activated config is not BGE-M3/1024/auto")
            if (
                _migration_hash(frozen_candidate, include_vectors=False)
                != candidate_nonvector_sha
                or _migration_hash(frozen_candidate, include_vectors=True)
                != candidate_vector_sha
                or _sqlite_schema_sha256(frozen_candidate) != candidate_schema_sha
            ):
                raise RuntimeError("candidate changed during the fenced config switch")
            state["activation"].update(
                {"status": "active", "activated_at": datetime.now(UTC).isoformat()}
            )
            _save_checkpoint(checkpoint, state)
            return state
    except Exception:
        # Ordinary failures are recovered immediately.  BaseException is not
        # caught deliberately: tests use it to emulate power loss/process
        # death, and the next invocation must recover solely from durable state.
        interrupted = _load_checkpoint(checkpoint)
        if "activation" not in interrupted:
            raise
        try:
            _recover_interrupted_activation(config, checkpoint, interrupted)
        except Exception as recovery_error:
            # A concurrent writer can legitimately produce bytes which match
            # neither frozen generation.  Never overwrite those bytes merely
            # to make rollback look successful: retain every file and record a
            # fail-closed, human-resolvable journal state.
            failed = _load_checkpoint(checkpoint)
            failed["activation"].update(
                {
                    "status": "activation-aborted-ambiguous",
                    "recovery_error": str(recovery_error),
                    "aborted_at": datetime.now(UTC).isoformat(),
                }
            )
            _save_checkpoint(checkpoint, failed)
        raise


def _complete_rollback(
    config: Path, checkpoint: Path, state: dict[str, Any]
) -> dict[str, Any]:
    """Finish a journalled rollback, including after any prior process death."""
    activation = state["activation"]
    source_sha = str(activation["source_sha256"])
    candidate_sha = str(activation["candidate_sha256"])
    retained_sha = str(activation.get("rollback_candidate_sha256", candidate_sha))
    previous_config_sha = str(activation["previous_config_sha256"])
    target_config_sha = str(activation["target_config_sha256"])
    source = _managed_path(Path(state["plan"]["source"]), "active database")
    source_backup = _managed_path(
        Path(activation["source_backup"]), "source backup"
    )
    config_backup = _regular_file(
        Path(activation["config_backup"]), "config backup"
    )
    retained = _managed_path(
        Path(activation["retained_candidate"]), "retained candidate"
    )
    if _sha256(config_backup) != previous_config_sha:
        raise RuntimeError("config backup changed; refusing rollback recovery")

    source_digest = _require_known_digest(
        source, "active database", {None, source_sha, candidate_sha, retained_sha}
    )
    backup_digest = _require_known_digest(
        source_backup, "source backup", {None, source_sha}
    )
    retained_digest = _require_known_digest(
        retained, "retained candidate", {None, retained_sha}
    )
    config_digest = _require_known_digest(
        config, "config", {previous_config_sha, target_config_sha}
    )

    if retained_digest is None:
        if source_digest != retained_sha:
            raise RuntimeError("active candidate is missing; refusing rollback recovery")
        _exclusive_sqlite_probe(source)
        _durable_replace(
            source, retained, boundary="rollback-active-to-retained"
        )
        source_digest = None
        retained_digest = retained_sha
    elif source_digest == retained_sha:
        raise RuntimeError("candidate generation is duplicated; refusing rollback")

    if source_digest is None:
        if backup_digest != source_sha:
            raise RuntimeError("original backup is missing; refusing rollback recovery")
        _durable_replace(
            source_backup, source, boundary="rollback-backup-to-source"
        )
        source_digest = source_sha
        backup_digest = None
    if source_digest != source_sha or retained_digest != retained_sha:
        raise RuntimeError("rollback generations are incomplete")

    if config_digest != previous_config_sha:
        _atomic_write(
            config, config_backup.read_bytes(), boundary="rollback-config"
        )
    if _sha256(source) != source_sha or _sha256(retained) != retained_sha:
        raise RuntimeError("rollback byte verification failed")
    if _sha256(config) != previous_config_sha:
        raise RuntimeError("rollback config verification failed")

    activation.update(
        {
            "status": "rolled-back",
            "rolled_back_at": datetime.now(UTC).isoformat(),
        }
    )
    _save_checkpoint(checkpoint, state)
    return state


def rollback(config: Path, checkpoint: Path) -> dict[str, Any]:
    """Restore the exact pre-BGE database/config and retain the BGE candidate."""
    config = _regular_file(config, "config")
    checkpoint = _regular_file(checkpoint, "checkpoint")
    state = _load_checkpoint(checkpoint)
    activation = state.get("activation") or {}
    status = activation.get("status")
    if activation.get("strategy") == "config-pointer-v1":
        source = _regular_file(Path(state["plan"]["source"]), "preserved source")
        candidate = _regular_file(
            Path(state["plan"]["candidate"]), "active candidate"
        )
        config_backup = _regular_file(
            Path(activation["config_backup"]), "config backup"
        )
        previous_config_sha = str(activation["previous_config_sha256"])
        target_config_sha = str(activation["target_config_sha256"])
        if _sha256(config_backup) != previous_config_sha:
            raise RuntimeError("config backup changed; refusing rollback")
        if status == "rolled-back":
            if _sha256(config) != previous_config_sha:
                raise RuntimeError("rolled-back config no longer matches its journal")
            loaded = ProxySettings.from_toml(config)
            if loaded.soul_db.resolve() != source:
                raise RuntimeError("rolled-back config points to another database")
            return state
        if status not in {"active", "rolling-back"}:
            raise ValueError("checkpoint does not describe an active cutover")
        config_digest = _require_known_digest(
            config, "config", {previous_config_sha, target_config_sha}
        )
        if status == "active":
            if config_digest != target_config_sha:
                raise RuntimeError("active config differs from the recorded target")
            # The pointer is switched only while BOTH generations are fenced.
            # The inactive legacy source is still a writable SQLite file; it
            # must be proven unchanged immediately before it becomes active.
            # Core may have enabled WAL on the candidate, so compare logical
            # data/schema rather than page-layout bytes.  Any real write to
            # either generation blocks rollback instead of being discarded or
            # silently promoted.
            with _frozen_source(source) as frozen_source, _frozen_source(
                candidate
            ) as frozen_candidate:
                if (
                    _migration_hash(frozen_source, include_vectors=False)
                    != state["plan"]["source_nonvector_sha256"]
                    or _migration_hash(frozen_source, include_vectors=True)
                    != state["plan"]["source_vector_sha256"]
                    or _sqlite_schema_sha256(frozen_source)
                    != activation["source_schema_sha256"]
                ):
                    raise RuntimeError(
                        "preserved source differs from the recorded original"
                    )
                if (
                    _migration_hash(frozen_candidate, include_vectors=False)
                    != activation["candidate_nonvector_sha256"]
                    or _migration_hash(frozen_candidate, include_vectors=True)
                    != activation["candidate_vector_sha256"]
                    or _sqlite_schema_sha256(frozen_candidate)
                    != activation["candidate_schema_sha256"]
                ):
                    raise RuntimeError(
                        "active database differs from the recorded candidate"
                    )
                activation.update(
                    {
                        "status": "rolling-back",
                        "rollback_started_at": datetime.now(UTC).isoformat(),
                        "retained_candidate": str(candidate),
                        "rollback_candidate_sha256": hashlib.sha256(
                            frozen_candidate.serialize()
                        ).hexdigest(),
                    }
                )
                _save_checkpoint(checkpoint, state)
                _after_rollback_journal(frozen_source, frozen_candidate)
                _atomic_write(
                    config, config_backup.read_bytes(), boundary="rollback-config"
                )
        elif config_digest == target_config_sha:
            # Recovery is still before the durable pointer switch.  Re-check
            # both generations under the same fences before completing it.
            with _frozen_source(source) as frozen_source, _frozen_source(
                candidate
            ) as frozen_candidate:
                if (
                    _migration_hash(frozen_source, include_vectors=False)
                    != state["plan"]["source_nonvector_sha256"]
                    or _migration_hash(frozen_source, include_vectors=True)
                    != state["plan"]["source_vector_sha256"]
                    or _sqlite_schema_sha256(frozen_source)
                    != activation["source_schema_sha256"]
                    or _migration_hash(frozen_candidate, include_vectors=False)
                    != activation["candidate_nonvector_sha256"]
                    or _migration_hash(frozen_candidate, include_vectors=True)
                    != activation["candidate_vector_sha256"]
                    or _sqlite_schema_sha256(frozen_candidate)
                    != activation["candidate_schema_sha256"]
                ):
                    raise RuntimeError(
                        "rollback generation differs from its recorded state"
                    )
                _after_rollback_journal(frozen_source, frozen_candidate)
                _atomic_write(
                    config, config_backup.read_bytes(), boundary="rollback-config"
                )
        elif config_digest != previous_config_sha:
            raise RuntimeError("rollback config has ambiguous bytes")
        loaded = ProxySettings.from_toml(config)
        if _sha256(config) != previous_config_sha or loaded.soul_db.resolve() != source:
            raise RuntimeError("rollback config verification failed")
        activation.update(
            {"status": "rolled-back", "rolled_back_at": datetime.now(UTC).isoformat()}
        )
        _save_checkpoint(checkpoint, state)
        return state
    if status == "rolled-back":
        source = _regular_file(Path(state["plan"]["source"]), "restored database")
        retained = _regular_file(
            Path(activation["retained_candidate"]), "retained candidate"
        )
        if (
            _sha256(source) != activation["source_sha256"]
            or _sha256(retained)
            != activation.get("rollback_candidate_sha256", activation["candidate_sha256"])
            or _sha256(config) != activation["previous_config_sha256"]
        ):
            raise RuntimeError("rolled-back cutover no longer matches its journal")
        return state
    if status == "rolling-back":
        return _complete_rollback(config, checkpoint, state)
    if status != "active":
        raise ValueError("checkpoint does not describe an active cutover")

    source = _regular_file(Path(state["plan"]["source"]), "active database")
    # Core enables WAL on open, which legitimately changes SQLite page bytes.
    # Fold any stopped WAL first, then require the logical schema/data to still
    # equal the promoted candidate.  This permits recovery after a failed
    # startup but refuses to discard even one post-cutover logical write.
    _exclusive_sqlite_probe(source, checkpoint_wal=True)
    _validate_active(config, state)
    rollback_candidate_sha = _sha256(source)
    retained = source.with_name(f"{source.name}.bge-retained-{_timestamp()}.db")
    _safe_parent(retained, "retained candidate")
    if retained.exists():
        raise FileExistsError("rollback retention path already exists")
    activation.update(
        {
            "status": "rolling-back",
            "rollback_started_at": datetime.now(UTC).isoformat(),
            "retained_candidate": str(retained),
            "rollback_candidate_sha256": rollback_candidate_sha,
        }
    )
    _save_checkpoint(checkpoint, state)
    return _complete_rollback(config, checkpoint, state)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-machine-embedding-cutover")
    actions = parser.add_subparsers(dest="action", required=True)
    migrate = actions.add_parser("migrate")
    migrate.add_argument("source", type=Path)
    migrate.add_argument("--candidate", type=Path, required=True)
    migrate.add_argument("--checkpoint", type=Path, required=True)
    migrate.add_argument("--batch-size", type=int, default=256)
    migrate.add_argument("--resume", action="store_true")
    verify = actions.add_parser("verify")
    verify.add_argument("checkpoint", type=Path)
    activate_parser = actions.add_parser("activate")
    activate_parser.add_argument("config", type=Path)
    activate_parser.add_argument("checkpoint", type=Path)
    rollback_parser = actions.add_parser("rollback")
    rollback_parser.add_argument("config", type=Path)
    rollback_parser.add_argument("checkpoint", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "migrate":
            result = asyncio.run(
                prepare(
                    args.source,
                    candidate=args.candidate,
                    checkpoint=args.checkpoint,
                    batch_size=args.batch_size,
                    resume=args.resume,
                )
            )
        elif args.action == "verify":
            result = verify_candidate(args.checkpoint)
        elif args.action == "activate":
            result = activate(args.config, args.checkpoint)
        else:
            result = rollback(args.config, args.checkpoint)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
