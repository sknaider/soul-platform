from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from soul_platform.autowire.types import ProviderCandidate, ProviderState


class RegistryConflict(RuntimeError):
    pass


class ProviderRegistry:
    def __init__(
        self,
        path: Path,
        *,
        machine_soul_id: str,
        embedding_identity: tuple[str, int, str],
    ) -> None:
        self.path = path.resolve()
        self.machine_soul_id = machine_soul_id
        self.embedding_identity = embedding_identity
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS providers(
                    provider_id TEXT PRIMARY KEY, source TEXT NOT NULL, kind TEXT NOT NULL,
                    protocol TEXT NOT NULL, origin TEXT NOT NULL, base_url TEXT NOT NULL,
                    model TEXT NOT NULL, attestation TEXT NOT NULL, state TEXT NOT NULL,
                    memory_allowed INTEGER NOT NULL CHECK(memory_allowed IN (0,1)),
                    detail TEXT NOT NULL, first_seen_ms INTEGER NOT NULL,last_seen_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS binding(
                    id INTEGER PRIMARY KEY CHECK(id=1), provider_id TEXT,
                    generation INTEGER NOT NULL, updated_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,
                    subject TEXT NOT NULL,detail TEXT NOT NULL,created_ms INTEGER NOT NULL
                );
                """
            )
            expected = {
                "machine_soul_id": self.machine_soul_id,
                "embedding_identity": json.dumps(self.embedding_identity, separators=(",", ":")),
            }
            for key, value in expected.items():
                row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
                if row is not None and row["value"] != value:
                    raise RegistryConflict(f"immutable registry field changed: {key}")
                db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", (key, value))
            db.execute(
                "INSERT OR IGNORE INTO binding(id,provider_id,generation,updated_ms) VALUES(1,NULL,0,?)",
                (int(time.time() * 1000),),
            )

    def upsert(
        self,
        candidate: ProviderCandidate,
        *,
        state: ProviderState,
        memory_allowed: bool,
    ) -> None:
        now = int(time.time() * 1000)
        with self._connect() as db:
            db.execute(
                """INSERT INTO providers(
                    provider_id,source,kind,protocol,origin,base_url,model,attestation,
                    state,memory_allowed,detail,first_seen_ms,last_seen_ms
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(provider_id) DO UPDATE SET
                    kind=excluded.kind,protocol=excluded.protocol,base_url=excluded.base_url,
                    attestation=excluded.attestation,state=excluded.state,
                    memory_allowed=excluded.memory_allowed,detail=excluded.detail,
                    last_seen_ms=excluded.last_seen_ms""",
                (
                    candidate.provider_id,candidate.source,candidate.kind,candidate.protocol,
                    candidate.origin,candidate.base_url,candidate.model,candidate.attestation,
                    state.value,int(memory_allowed),candidate.detail[:400],now,now,
                ),
            )

    def mark_unseen_stale(self, seen: set[str]) -> None:
        with self._connect() as db:
            binding = db.execute("SELECT provider_id FROM binding WHERE id=1").fetchone()
            active_provider_id = None if binding is None else binding["provider_id"]
            rows = db.execute("SELECT provider_id,state FROM providers").fetchall()
            for row in rows:
                if row["provider_id"] not in seen:
                    state = (
                        ProviderState.ACTIVE_UNREACHABLE.value
                        if row["provider_id"] == active_provider_id
                        else ProviderState.STALE.value
                    )
                    db.execute(
                        "UPDATE providers SET state=?,memory_allowed=0 WHERE provider_id=?",
                        (state, row["provider_id"]),
                    )

    def assert_generation(self, expected_generation: int) -> None:
        _provider_id, observed = self.binding()
        if observed != expected_generation:
            raise RegistryConflict(
                f"binding generation changed: expected={expected_generation} observed={observed}"
            )

    def rows(self) -> list[dict[str, object]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM providers ORDER BY source,model")]

    def get(self, provider_id: str) -> dict[str, object] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM providers WHERE provider_id=?", (provider_id,)).fetchone()
            return None if row is None else dict(row)

    def binding(self) -> tuple[str | None, int]:
        with self._connect() as db:
            row = db.execute("SELECT provider_id,generation FROM binding WHERE id=1").fetchone()
            return (row["provider_id"], int(row["generation"]))

    def commit_binding(self, provider_id: str, *, expected_generation: int) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT generation FROM binding WHERE id=1").fetchone()
            observed = int(row["generation"])
            if observed != expected_generation:
                raise RegistryConflict(
                    f"binding generation changed: expected={expected_generation} observed={observed}"
                )
            generation = observed + 1
            db.execute(
                "UPDATE binding SET provider_id=?,generation=?,updated_ms=? WHERE id=1",
                (provider_id, generation, int(time.time() * 1000)),
            )
            return generation

    def audit(self, event: str, subject: str, detail: str) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO audit(event,subject,detail,created_ms) VALUES(?,?,?,?)",
                (event, subject, detail[:400], int(time.time() * 1000)),
            )
