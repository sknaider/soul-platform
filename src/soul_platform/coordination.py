"""Durable, idempotent multi-agent task coordination over SQLite.

SQLite is the portable reference store. The state machine and open JSON receipt
format are backend-neutral, so operators can move the same records to Postgres.
Caller identity must be authenticated by the API boundary; membership and role
authorization are resolved from this store, never from a role in the payload.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from soul_platform.receipts import ReceiptCheckpointStore, ReceiptSigner, SignedReceipt


class CoordinationDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    tenant: str
    objective: str
    state: str
    current_agent: str | None
    lease_until: str | None
    version: int


@dataclass(frozen=True)
class MessageRecord:
    message_id: str
    tenant: str
    channel: str
    sender: str
    content: str
    created_at: str


class CoordinatorStore:
    def __init__(
        self, path: str | Path, signer: ReceiptSigner,
        checkpoint_store: ReceiptCheckpointStore,
    ) -> None:
        self.path = str(path)
        self.signer = signer
        self.checkpoint_store = checkpoint_store
        if os.path.realpath(self.path) == os.path.realpath(checkpoint_store.path):
            raise ValueError("checkpoint store must be a separate durable database")
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _initialize_sync(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS members (
                    tenant TEXT NOT NULL, agent TEXT NOT NULL, role TEXT NOT NULL,
                    PRIMARY KEY (tenant, agent)
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, objective TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','claimed','completed','failed')),
                    current_agent TEXT, lease_until TEXT, version INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL, task_id TEXT NOT NULL, actor TEXT NOT NULL,
                    event TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL, receipt_json TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant, idempotency_key),
                    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS channels (
                    tenant TEXT NOT NULL, channel TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('team','dm')),
                    created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, channel)
                );
                CREATE TABLE IF NOT EXISTS channel_members (
                    tenant TEXT NOT NULL, channel TEXT NOT NULL, agent TEXT NOT NULL,
                    PRIMARY KEY (tenant, channel, agent),
                    FOREIGN KEY (tenant, channel) REFERENCES channels(tenant, channel)
                );
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, channel TEXT NOT NULL,
                    sender TEXT NOT NULL, content TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(tenant, idempotency_key),
                    FOREIGN KEY (tenant, channel) REFERENCES channels(tenant, channel)
                );
                CREATE TABLE IF NOT EXISTS schedules (
                    tenant TEXT NOT NULL, schedule_id TEXT NOT NULL, objective TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL, next_run TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), created_by TEXT NOT NULL,
                    PRIMARY KEY(tenant,schedule_id)
                );
                CREATE TABLE IF NOT EXISTS schedule_runs (
                    tenant TEXT NOT NULL, schedule_id TEXT NOT NULL, scheduled_for TEXT NOT NULL,
                    task_id TEXT NOT NULL, PRIMARY KEY(tenant,schedule_id,scheduled_for),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS receipt_checkpoint_outbox (
                    source TEXT NOT NULL, source_event_id INTEGER NOT NULL,
                    receipt_json TEXT NOT NULL, synced INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(source,source_event_id)
                );
                CREATE TABLE IF NOT EXISTS schedule_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL,
                    schedule_id TEXT NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, payload_json TEXT NOT NULL,
                    receipt_json TEXT NOT NULL, receipt_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(tenant,idempotency_key)
                );
                """
            )
            columns = {
                str(row["name"]) for row in conn.execute("PRAGMA table_info(events)")
            }
            if "payload_json" not in columns:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN payload_json TEXT NOT NULL "
                    "DEFAULT '{\"legacy_unverifiable\":true}'"
                )
            conn.execute(
                "INSERT OR IGNORE INTO receipt_checkpoint_outbox(source,source_event_id,receipt_json,synced) "
                "SELECT 'task',event_id,receipt_json,0 FROM events ORDER BY event_id"
            )
            conn.execute(
                "INSERT OR IGNORE INTO receipt_checkpoint_outbox(source,source_event_id,receipt_json,synced) "
                "SELECT 'schedule',event_id,receipt_json,0 FROM schedule_events ORDER BY event_id"
            )
            self._align_outbox_with_existing_heads_sync(conn)
            conn.commit()
            self._reconcile_pending_sync(conn)
        finally:
            conn.close()

    async def add_member(self, tenant: str, agent: str, role: str) -> None:
        if role not in {"lead", "worker", "reviewer"}:
            raise ValueError("unsupported role")
        async with self._lock:
            await asyncio.to_thread(self._add_member_sync, tenant, agent, role)

    def _add_member_sync(self, tenant: str, agent: str, role: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO members(tenant,agent,role) VALUES(?,?,?) "
                "ON CONFLICT(tenant,agent) DO UPDATE SET role=excluded.role",
                (tenant, agent, role),
            )
        finally:
            conn.close()

    async def transact(self, operation: Callable[[sqlite3.Connection], TaskRecord]) -> TaskRecord:
        return await asyncio.to_thread(self._transact_sync, operation)

    def _transact_sync(self, operation: Callable[[sqlite3.Connection], TaskRecord]) -> TaskRecord:
        conn = self._connect()
        try:
            self._reconcile_pending_sync(conn)
            conn.execute("BEGIN IMMEDIATE")
            result = operation(conn)
            conn.commit()
            # The authoritative event + outbox are already committed. A sidecar
            # outage must not turn a committed effect into a reported failure.
            # The next mutation is fail-closed until this reconciliation succeeds.
            try:
                self._reconcile_pending_sync(conn)
            except Exception:
                pass
            return result
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _reconcile_pending_sync(self, conn: sqlite3.Connection) -> int:
        rows = conn.execute(
            "SELECT source,source_event_id,receipt_json FROM receipt_checkpoint_outbox "
            "WHERE synced=0 ORDER BY CASE source WHEN 'task' THEN 0 ELSE 1 END,source_event_id"
        ).fetchall()
        for row in rows:
            receipt = SignedReceipt(**json.loads(row["receipt_json"]))
            self.checkpoint_store.record(receipt)
            conn.execute(
                "UPDATE receipt_checkpoint_outbox SET synced=1 WHERE source=? AND source_event_id=?",
                (row["source"], row["source_event_id"]),
            )
        return len(rows)

    def _align_outbox_with_existing_heads_sync(self, conn: sqlite3.Connection) -> None:
        """Mark historical prefixes already anchored by an existing sidecar."""
        groups: dict[tuple[str, str], list[tuple[str, int, str]]] = {}
        for source, table, id_column in (
            ("task", "events", "task_id"),
            ("schedule", "schedule_events", "schedule_id"),
        ):
            rows = conn.execute(
                f"SELECT event_id,tenant,{id_column},receipt_sha256 FROM {table} ORDER BY event_id"
            ).fetchall()
            for row in rows:
                task_id = str(row[id_column])
                if source == "schedule":
                    task_id = f"schedule:{task_id}"
                groups.setdefault((str(row["tenant"]), task_id), []).append(
                    (source, int(row["event_id"]), str(row["receipt_sha256"]))
                )
        for (tenant, task_id), chain in groups.items():
            head = self.checkpoint_store.head(tenant, task_id)
            if head is None:
                continue
            matched = False
            for source, event_id, digest in chain:
                conn.execute(
                    "UPDATE receipt_checkpoint_outbox SET synced=1 "
                    "WHERE source=? AND source_event_id=?", (source, event_id),
                )
                if digest == head:
                    matched = True
                    break
            if not matched:
                raise ValueError("checkpoint head is not present in the authoritative event chain")

    async def reconcile_checkpoints(self) -> int:
        def reconcile() -> int:
            conn = self._connect()
            try:
                return self._reconcile_pending_sync(conn)
            finally:
                conn.close()
        return await asyncio.to_thread(reconcile)

    async def checkpoint_pending_count(self) -> int:
        def count() -> int:
            conn = self._connect()
            try:
                return int(conn.execute(
                    "SELECT count(*) FROM receipt_checkpoint_outbox WHERE synced=0"
                ).fetchone()[0])
            finally:
                conn.close()
        return await asyncio.to_thread(count)

    def _member_role(self, conn: sqlite3.Connection, tenant: str, actor: str) -> str:
        row = conn.execute(
            "SELECT role FROM members WHERE tenant=? AND agent=?", (tenant, actor)
        ).fetchone()
        if row is None:
            raise CoordinationDenied("actor is not a member of this tenant")
        return str(row["role"])

    def _task(self, conn: sqlite3.Connection, task_id: str) -> TaskRecord:
        row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise CoordinationDenied("task does not exist")
        return TaskRecord(
            row["task_id"], row["tenant"], row["objective"], row["state"],
            row["current_agent"], row["lease_until"], row["version"],
        )

    def _idempotent(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        key: str,
        event: str,
        actor: str,
        *,
        expected_task_id: str | None = None,
        request: dict[str, Any],
    ) -> TaskRecord | None:
        row = conn.execute(
            "SELECT task_id,event,actor,payload_json FROM events "
            "WHERE tenant=? AND idempotency_key=?",
            (tenant, key),
        ).fetchone()
        if row is None:
            return None
        if row["event"] != event or row["actor"] != actor:
            raise CoordinationDenied("idempotency key was already used by another operation")
        if expected_task_id is not None and row["task_id"] != expected_task_id:
            raise CoordinationDenied("idempotency key belongs to another task")
        payload = json.loads(row["payload_json"])
        if payload.get("legacy_unverifiable"):
            raise CoordinationDenied(
                "legacy event has no payload bytes and cannot be replayed safely"
            )
        if payload.get("request") != request:
            raise CoordinationDenied("idempotency key payload does not match the request")
        return TaskRecord(**payload["task"])

    def _append_event(
        self,
        conn: sqlite3.Connection,
        task: TaskRecord,
        actor: str,
        event: str,
        key: str,
        payload: dict[str, Any],
    ) -> SignedReceipt:
        previous = conn.execute(
            "SELECT receipt_sha256 FROM events WHERE task_id=? ORDER BY event_id DESC LIMIT 1",
            (task.task_id,),
        ).fetchone()
        receipt = self.signer.sign(
            receipt_id=str(uuid.uuid4()), tenant=task.tenant, task_id=task.task_id,
            actor=actor, event=event, payload=payload,
            previous_sha256=previous["receipt_sha256"] if previous else "",
        )
        cursor = conn.execute(
            "INSERT INTO events(tenant,task_id,actor,event,idempotency_key,payload_json,receipt_json,receipt_sha256,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (task.tenant, task.task_id, actor, event, key,
             json.dumps(payload, sort_keys=True, separators=(",", ":")),
             json.dumps(asdict(receipt), sort_keys=True), receipt.sha256(), receipt.created_at),
        )
        conn.execute(
            "INSERT INTO receipt_checkpoint_outbox(source,source_event_id,receipt_json,synced) "
            "VALUES('task',?,?,0)",
            (cursor.lastrowid, json.dumps(asdict(receipt), sort_keys=True)),
        )
        return receipt

    async def events(self, tenant: str, task_id: str, actor: str) -> list[SignedReceipt]:
        return await asyncio.to_thread(self._events_sync, tenant, task_id, actor)

    def _events_sync(self, tenant: str, task_id: str, actor: str) -> list[SignedReceipt]:
        conn = self._connect()
        try:
            self._member_role(conn, tenant, actor)
            rows = conn.execute(
                "SELECT receipt_json FROM events WHERE tenant=? AND task_id=? ORDER BY event_id",
                (tenant, task_id),
            ).fetchall()
            return [SignedReceipt(**json.loads(row["receipt_json"])) for row in rows]
        finally:
            conn.close()

    async def event_payloads(
        self, tenant: str, task_id: str, actor: str
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._event_payloads_sync, tenant, task_id, actor)

    def _event_payloads_sync(
        self, tenant: str, task_id: str, actor: str
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            self._member_role(conn, tenant, actor)
            rows = conn.execute(
                "SELECT payload_json FROM events WHERE tenant=? AND task_id=? ORDER BY event_id",
                (tenant, task_id),
            ).fetchall()
            return [json.loads(row["payload_json"]) for row in rows]
        finally:
            conn.close()


class Coordinator:
    def __init__(self, store: CoordinatorStore) -> None:
        self.store = store

    @staticmethod
    def _lease_is_active(task: TaskRecord, now: datetime) -> bool:
        return bool(task.lease_until and datetime.fromisoformat(task.lease_until) > now)

    async def create_task(
        self, tenant: str, actor: str, objective: str, idempotency_key: str
    ) -> TaskRecord:
        def op(conn: sqlite3.Connection) -> TaskRecord:
            role = self.store._member_role(conn, tenant, actor)
            if role != "lead":
                raise CoordinationDenied("only a lead can create tasks")
            request = {"objective": objective}
            prior = self.store._idempotent(
                conn,
                tenant,
                idempotency_key,
                "created",
                actor,
                request=request,
            )
            if prior:
                return prior
            now = datetime.now(UTC).isoformat()
            task = TaskRecord(str(uuid.uuid4()), tenant, objective, "pending", None, None, 0)
            conn.execute(
                "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?)",
                (task.task_id, tenant, objective, task.state, None, None, 0, now, now),
            )
            payload = {"request": request, "task": asdict(task)}
            self.store._append_event(conn, task, actor, "created", idempotency_key, payload)
            return task
        return await self.store.transact(op)


    async def create_channel(
        self,
        tenant: str,
        actor: str,
        channel: str,
        *,
        kind: str,
        participants: set[str] | None = None,
    ) -> None:
        if kind not in {"team", "dm"} or not channel or len(channel) > 128:
            raise ValueError("invalid channel")
        participants = set(participants or set())

        def op(conn: sqlite3.Connection) -> TaskRecord:
            role = self.store._member_role(conn, tenant, actor)
            if role != "lead":
                raise CoordinationDenied("only a lead can create channels")
            if kind == "dm":
                participants.add(actor)
                if len(participants) != 2:
                    raise CoordinationDenied("a DM must have exactly two members")
                for member in participants:
                    self.store._member_role(conn, tenant, member)
            elif participants:
                raise CoordinationDenied("team channels derive membership from the tenant")
            try:
                conn.execute(
                    "INSERT INTO channels(tenant,channel,kind,created_by,created_at) VALUES(?,?,?,?,?)",
                    (tenant, channel, kind, actor, datetime.now(UTC).isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise CoordinationDenied("channel already exists") from exc
            for member in participants:
                conn.execute(
                    "INSERT INTO channel_members(tenant,channel,agent) VALUES(?,?,?)",
                    (tenant, channel, member),
                )
            # transact() is task-shaped; return a private sentinel never exposed.
            return TaskRecord(channel, tenant, channel, "completed", actor, None, 0)

        await self.store.transact(op)

    def _channel_access(
        self, conn: sqlite3.Connection, tenant: str, channel: str, actor: str
    ) -> None:
        self.store._member_role(conn, tenant, actor)
        row = conn.execute(
            "SELECT kind FROM channels WHERE tenant=? AND channel=?", (tenant, channel)
        ).fetchone()
        if row is None:
            raise CoordinationDenied("channel does not exist")
        if row["kind"] == "dm":
            member = conn.execute(
                "SELECT 1 FROM channel_members WHERE tenant=? AND channel=? AND agent=?",
                (tenant, channel, actor),
            ).fetchone()
            if member is None:
                raise CoordinationDenied("actor is not a member of this DM")

    async def send(
        self, tenant: str, channel: str, actor: str, content: str, idempotency_key: str
    ) -> MessageRecord:
        if not content or len(content.encode("utf-8")) > 65_536:
            raise ValueError("message must be between 1 and 65536 bytes")

        def op(conn: sqlite3.Connection) -> TaskRecord:
            self._channel_access(conn, tenant, channel, actor)
            row = conn.execute(
                "SELECT * FROM messages WHERE tenant=? AND idempotency_key=?",
                (tenant, idempotency_key),
            ).fetchone()
            if row is not None:
                if row["channel"] != channel or row["sender"] != actor or row["content"] != content:
                    raise CoordinationDenied("message idempotency key payload mismatch")
                record = MessageRecord(
                    row["message_id"], row["tenant"], row["channel"], row["sender"],
                    row["content"], row["created_at"],
                )
            else:
                record = MessageRecord(
                    str(uuid.uuid4()), tenant, channel, actor, content,
                    datetime.now(UTC).isoformat(),
                )
                conn.execute(
                    "INSERT INTO messages VALUES(?,?,?,?,?,?,?)",
                    (
                        record.message_id, tenant, channel, actor, content,
                        idempotency_key, record.created_at,
                    ),
                )
            # TaskRecord sentinel transports through the existing atomic helper.
            return TaskRecord(
                json.dumps(asdict(record), sort_keys=True), tenant, channel,
                "completed", actor, None, 0,
            )

        sentinel = await self.store.transact(op)
        return MessageRecord(**json.loads(sentinel.task_id))

    async def read(
        self, tenant: str, channel: str, actor: str, *, limit: int = 100
    ) -> list[MessageRecord]:
        if limit <= 0 or limit > 500:
            raise ValueError("limit must be between 1 and 500")

        def read_sync() -> list[MessageRecord]:
            conn = self.store._connect()
            try:
                self._channel_access(conn, tenant, channel, actor)
                rows = conn.execute(
                    "SELECT * FROM messages WHERE tenant=? AND channel=? "
                    "ORDER BY created_at DESC LIMIT ?", (tenant, channel, limit),
                ).fetchall()
                return [
                    MessageRecord(
                        row["message_id"], row["tenant"], row["channel"], row["sender"],
                        row["content"], row["created_at"],
                    )
                    for row in reversed(rows)
                ]
            finally:
                conn.close()

        return await asyncio.to_thread(read_sync)

    async def claim(
        self, task_id: str, actor: str, idempotency_key: str, lease_seconds: int = 60
    ) -> TaskRecord:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        def op(conn: sqlite3.Connection) -> TaskRecord:
            task = self.store._task(conn, task_id)
            role = self.store._member_role(conn, task.tenant, actor)
            if role not in {"lead", "worker"}:
                raise CoordinationDenied("reviewers cannot claim execution work")
            request = {"task_id": task_id, "lease_seconds": lease_seconds}
            prior = self.store._idempotent(
                conn,
                task.tenant,
                idempotency_key,
                "claimed",
                actor,
                expected_task_id=task_id,
                request=request,
            )
            if prior:
                return prior
            now = datetime.now(UTC)
            active_lease = self._lease_is_active(task, now)
            if task.state == "completed" or (task.state == "claimed" and active_lease):
                raise CoordinationDenied("task is not claimable")
            lease = (now + timedelta(seconds=lease_seconds)).isoformat()
            conn.execute(
                "UPDATE tasks SET state='claimed',current_agent=?,lease_until=?,version=version+1,updated_at=? "
                "WHERE task_id=?", (actor, lease, now.isoformat(), task_id),
            )
            claimed = self.store._task(conn, task_id)
            payload = {"request": request, "task": asdict(claimed)}
            self.store._append_event(conn, claimed, actor, "claimed", idempotency_key, payload)
            return claimed
        return await self.store.transact(op)


    async def handoff(
        self, task_id: str, actor: str, target: str, idempotency_key: str,
        expected_version: int, lease_seconds: int = 60,
    ) -> TaskRecord:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        def op(conn: sqlite3.Connection) -> TaskRecord:
            task = self.store._task(conn, task_id)
            actor_role = self.store._member_role(conn, task.tenant, actor)
            if actor_role not in {"lead", "worker"}:
                raise CoordinationDenied("current actor no longer has an execution role")
            target_role = self.store._member_role(conn, task.tenant, target)
            if target_role not in {"lead", "worker"}:
                raise CoordinationDenied("reviewers cannot receive execution work")
            request = {
                "task_id": task_id, "target": target, "lease_seconds": lease_seconds,
                "expected_version": expected_version,
            }
            prior = self.store._idempotent(
                conn,
                task.tenant,
                idempotency_key,
                "handoff",
                actor,
                expected_task_id=task_id,
                request=request,
            )
            if prior:
                return prior
            if task.state != "claimed" or task.current_agent != actor:
                raise CoordinationDenied("only the current claimant can hand off")
            if task.version != expected_version:
                raise CoordinationDenied("stale fencing token")
            now_dt = datetime.now(UTC)
            if not self._lease_is_active(task, now_dt):
                raise CoordinationDenied("claim lease expired before handoff")
            now = now_dt.isoformat()
            lease = (now_dt + timedelta(seconds=lease_seconds)).isoformat()
            conn.execute(
                "UPDATE tasks SET current_agent=?,lease_until=?,version=version+1,updated_at=? "
                "WHERE task_id=?", (target, lease, now, task_id),
            )
            handed = self.store._task(conn, task_id)
            payload = {"request": request, "task": asdict(handed)}
            self.store._append_event(conn, handed, actor, "handoff", idempotency_key, payload)
            return handed
        return await self.store.transact(op)


    async def complete(
        self, task_id: str, actor: str, idempotency_key: str, *, expected_version: int
    ) -> TaskRecord:
        def op(conn: sqlite3.Connection) -> TaskRecord:
            task = self.store._task(conn, task_id)
            actor_role = self.store._member_role(conn, task.tenant, actor)
            if actor_role not in {"lead", "worker"}:
                raise CoordinationDenied("current actor no longer has an execution role")
            request = {"task_id": task_id, "expected_version": expected_version}
            prior = self.store._idempotent(
                conn,
                task.tenant,
                idempotency_key,
                "completed",
                actor,
                expected_task_id=task_id,
                request=request,
            )
            if prior:
                return prior
            if task.state != "claimed" or task.current_agent != actor:
                raise CoordinationDenied("only the current claimant can complete")
            if task.version != expected_version:
                raise CoordinationDenied("stale fencing token")
            now_dt = datetime.now(UTC)
            if not self._lease_is_active(task, now_dt):
                raise CoordinationDenied("claim lease expired before completion")
            now = now_dt.isoformat()
            conn.execute(
                "UPDATE tasks SET state='completed',lease_until=NULL,version=version+1,updated_at=? "
                "WHERE task_id=?", (now, task_id),
            )
            completed = self.store._task(conn, task_id)
            payload = {"request": request, "task": asdict(completed)}
            self.store._append_event(conn, completed, actor, "completed", idempotency_key, payload)
            return completed
        return await self.store.transact(op)


class ChannelService(Coordinator):
    """Compatibility name for the coordinator's tenant-scoped messaging API."""

    pass
