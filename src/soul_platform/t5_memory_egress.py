"""Deterministic T5 memory-egress policy.

T5 is not a retrieval authorization failure.  It is a confused-deputy leak:
an agent can read a memory legitimately and then disclose it to the wrong
interlocutor.  This module is deliberately independent from prompts and model
judgement.  Callers provide provenance obtained from an authoritative store,
and use only the returned ``allowed_ids`` when constructing model context.

The default policy is fail-closed:

* missing/untrusted provenance is denied;
* private memory is usable only by its owner;
* one unsafe fragment denies the complete memory batch for that turn;
* repeated cross-owner attempts lock memory egress for the session; and
* gradual aggregation of non-public, cross-owner shared context is bounded by
  a rolling privacy budget.

Existing single-owner installations can opt into ``compatibility_single_owner``
explicitly.  Compatibility never treats an arbitrary requester as the legacy
owner and therefore cannot be selected by prompt text.

The in-memory guard remains a pure policy reference.  ``SQLiteT5EgressStore``
is the production boundary: it binds authenticated owners immutably and
reserves rolling budgets transactionally across workers and restarts.  Neither
identity nor provenance may be derived from prompt text or writable memory
metadata.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Literal


MemoryScope = Literal["private", "team", "shared", "public"]


def _identity(value: str | None) -> str:
    return str(value or "").strip().casefold()


@dataclass(frozen=True)
class MemoryProvenance:
    """Trusted, content-free provenance for one retrieved memory.

    ``owner`` is the human/service subject whose information the memory
    describes, not the agent that stored it.  ``trusted`` means the value came
    from the authenticated storage/session boundary.  A caller-controlled
    metadata field must never set it to true.
    """

    memory_id: str
    owner: str | None
    scope: str = "private"
    trusted: bool = False


@dataclass(frozen=True)
class BlockedMemory:
    memory_id: str
    reason: str


@dataclass(frozen=True)
class EgressDecision:
    allowed_ids: tuple[str, ...]
    blocked: tuple[BlockedMemory, ...]
    batch_denied: bool
    session_locked: bool
    reason: str

    @property
    def allowed(self) -> bool:
        return not self.batch_denied and bool(self.allowed_ids)


@dataclass(frozen=True)
class T5EgressPolicy:
    """Bounds for direct and gradual memory extraction."""

    window_seconds: float = 900.0
    lock_seconds: float = 300.0
    max_cross_owner_turns: int = 2
    max_shared_fragments_per_window: int = 8
    max_distinct_foreign_owners_per_window: int = 2
    max_session_states: int = 10_000
    max_provenance_bindings: int = 100_000
    strict_batch: bool = True
    legacy_single_owner: str | None = None

    def __post_init__(self) -> None:
        numeric = (
            self.window_seconds,
            self.lock_seconds,
            self.max_cross_owner_turns,
            self.max_shared_fragments_per_window,
            self.max_distinct_foreign_owners_per_window,
            self.max_session_states,
            self.max_provenance_bindings,
        )
        if any(isinstance(value, bool) or value <= 0 for value in numeric):
            raise ValueError("T5 egress limits must be positive")
        if self.legacy_single_owner is not None and not _identity(self.legacy_single_owner):
            raise ValueError("legacy_single_owner must be a non-empty identity")

    @classmethod
    def compatibility_single_owner(cls, owner: str, **kwargs: object) -> "T5EgressPolicy":
        """Explicit legacy mode for a genuinely single-owner installation."""

        return cls(legacy_single_owner=owner, **kwargs)


@dataclass
class _SessionState:
    cross_owner_turns: deque[float] = field(default_factory=deque)
    shared_disclosures: deque[tuple[float, int]] = field(default_factory=deque)
    foreign_owners: deque[tuple[float, str]] = field(default_factory=deque)
    locked_until: float = 0.0


class T5MemoryEgressGuard:
    """Stateful, thread-safe memory-egress guard.

    State is intentionally content-free.  It records timestamps, counts,
    normalized owner identifiers and stable memory IDs only.
    """

    def __init__(
        self,
        policy: T5EgressPolicy | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy or T5EgressPolicy()
        self._clock = clock
        self._sessions: dict[tuple[str, str], _SessionState] = {}
        self._provenance_bindings: dict[str, tuple[str, str]] = {}
        self._lock = threading.RLock()

    def evaluate(
        self,
        *,
        session_id: str,
        interlocutor: str,
        memories: Iterable[MemoryProvenance],
    ) -> EgressDecision:
        """Return the only memory IDs a caller may place in model context."""

        session = str(session_id or "").strip()
        subject = _identity(interlocutor)
        items = tuple(memories or ())
        if not session or not subject:
            return self._deny_all(items, "missing_verified_session_or_interlocutor")

        now = float(self._clock())
        key = (session, subject)
        with self._lock:
            state = self._sessions.get(key)
            if state is None:
                if len(self._sessions) >= self.policy.max_session_states:
                    return self._deny_all(items, "session_registry_full")
                state = _SessionState()
                self._sessions[key] = state
            self._prune(state, now)
            if state.locked_until > now:
                return self._deny_all(items, "session_memory_egress_locked", locked=True)

            seen_ids: set[str] = set()
            allowed: list[str] = []
            blocked: list[BlockedMemory] = []
            cross_owner_private = False
            shared_count = sum(count for _, count in state.shared_disclosures)
            foreign_owners = {owner for _, owner in state.foreign_owners}

            for item in items:
                memory_id = str(item.memory_id or "").strip()
                scope = str(item.scope or "").strip().casefold()
                owner = _identity(item.owner)

                if not memory_id or memory_id in seen_ids:
                    blocked.append(
                        BlockedMemory(
                            memory_id or "<missing>", "invalid_or_duplicate_memory_id"
                        )
                    )
                    continue
                seen_ids.add(memory_id)

                if not item.trusted:
                    blocked.append(BlockedMemory(memory_id, "untrusted_provenance"))
                    continue
                if scope not in {"private", "team", "shared", "public"}:
                    blocked.append(BlockedMemory(memory_id, "unknown_scope"))
                    continue
                if not owner and self.policy.legacy_single_owner is not None:
                    owner = _identity(self.policy.legacy_single_owner)
                if not owner:
                    blocked.append(BlockedMemory(memory_id, "unknown_owner"))
                    continue

                binding = (owner, scope)
                prior_binding = self._provenance_bindings.get(memory_id)
                if prior_binding is None:
                    if len(self._provenance_bindings) >= self.policy.max_provenance_bindings:
                        blocked.append(BlockedMemory(memory_id, "provenance_registry_full"))
                        continue
                    self._provenance_bindings[memory_id] = binding
                    prior_binding = binding
                if prior_binding != binding:
                    blocked.append(BlockedMemory(memory_id, "provenance_drift"))
                    continue

                if scope == "private" and owner != subject:
                    cross_owner_private = True
                    blocked.append(BlockedMemory(memory_id, "cross_owner_private"))
                    continue

                if scope in {"team", "shared"} and owner != subject:
                    projected_owners = foreign_owners | {owner}
                    if len(projected_owners) > self.policy.max_distinct_foreign_owners_per_window:
                        blocked.append(BlockedMemory(memory_id, "multi_turn_owner_aggregation"))
                        continue
                    if shared_count + 1 > self.policy.max_shared_fragments_per_window:
                        blocked.append(
                            BlockedMemory(
                                memory_id, "multi_turn_shared_budget_exhausted"
                            )
                        )
                        continue
                    shared_count += 1
                    foreign_owners.add(owner)

                allowed.append(memory_id)

            if cross_owner_private:
                state.cross_owner_turns.append(now)
            if len(state.cross_owner_turns) >= self.policy.max_cross_owner_turns:
                state.locked_until = max(state.locked_until, now + self.policy.lock_seconds)

            locked = state.locked_until > now
            batch_denied = locked or (self.policy.strict_batch and bool(blocked))
            if batch_denied:
                allowed = []
            else:
                # Charge only context that the caller is allowed to disclose.
                # A denied strict batch must not burn budget and become a DoS
                # primitive by mixing one unsafe fragment with safe shared data.
                previous_shared = sum(count for _, count in state.shared_disclosures)
                newly_shared = shared_count - previous_shared
                if newly_shared > 0:
                    state.shared_disclosures.append((now, newly_shared))
                    recorded_owners = {value for _, value in state.foreign_owners}
                    for owner in sorted(foreign_owners - recorded_owners):
                        state.foreign_owners.append((now, owner))
            reason = (
                "session_memory_egress_locked"
                if locked
                else "unsafe_memory_provenance"
                if blocked
                else "allowed"
            )
            return EgressDecision(tuple(allowed), tuple(blocked), batch_denied, locked, reason)

    def _prune(self, state: _SessionState, now: float) -> None:
        cutoff = now - self.policy.window_seconds
        while state.cross_owner_turns and state.cross_owner_turns[0] < cutoff:
            state.cross_owner_turns.popleft()
        while state.shared_disclosures and state.shared_disclosures[0][0] < cutoff:
            state.shared_disclosures.popleft()
        while state.foreign_owners and state.foreign_owners[0][0] < cutoff:
            state.foreign_owners.popleft()
        if state.locked_until <= now:
            state.locked_until = 0.0

    @staticmethod
    def _deny_all(
        items: Iterable[MemoryProvenance], reason: str, *, locked: bool = False
    ) -> EgressDecision:
        blocked = tuple(
            BlockedMemory(str(item.memory_id or "<missing>"), reason) for item in items
        )
        return EgressDecision((), blocked, True, locked, reason)


class T5ProvenanceConflict(RuntimeError):
    """A stable memory ID was presented with different trusted provenance."""


class SQLiteT5EgressStore:
    """Durable, atomic T5 provenance and rolling privacy-budget store.

    The store is intentionally content-free.  It persists only stable memory
    IDs, authenticated tenant/subject bindings, scopes and counters.  A caller
    never supplies provenance to :meth:`evaluate`; the transaction resolves it
    from the immutable binding table before reserving disclosure budget.

    ``BEGIN IMMEDIATE`` serializes reservations across async workers, OS
    processes and restarts.  A Core memory committed before its provenance
    binding is safe: it remains unbound and therefore cannot enter model
    context until an explicit trusted migration binds it.
    """

    _SCOPES = frozenset({"private", "team", "shared", "public"})

    def __init__(
        self,
        path: str | os.PathLike[str],
        policy: T5EgressPolicy | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.policy = policy or T5EgressPolicy()
        self._clock = clock

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _initialize_sync(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS t5_memory_provenance_v1 (
                    soul_id TEXT NOT NULL,
                    memory_id TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    owner_subject TEXT NOT NULL,
                    scope TEXT NOT NULL CHECK(scope IN ('private','team','shared','public')),
                    origin TEXT NOT NULL CHECK(origin IN ('authenticated-write','legacy-migration')),
                    created_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (soul_id, memory_id)
                );
                CREATE TABLE IF NOT EXISTS t5_sessions_v1 (
                    soul_id TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    interlocutor TEXT NOT NULL,
                    last_seen_unix_ms INTEGER NOT NULL,
                    locked_until_unix_ms INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (soul_id, tenant, session_id, interlocutor)
                );
                CREATE TABLE IF NOT EXISTS t5_budget_events_v1 (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    soul_id TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    interlocutor TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('cross-owner-turn','shared-fragment')),
                    foreign_owner TEXT NOT NULL DEFAULT '',
                    fragments INTEGER NOT NULL CHECK(fragments > 0),
                    created_unix_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS t5_budget_window_v1
                    ON t5_budget_events_v1(
                        soul_id, tenant, session_id, interlocutor, created_unix_ms
                    );
                """
            )
        finally:
            connection.close()
        if os.name != "nt":
            os.chmod(self.path, 0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{self.path}{suffix}")
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)

    async def bind_memory(
        self,
        *,
        soul_id: str,
        memory_id: str | int,
        tenant: str,
        owner_subject: str,
        scope: MemoryScope = "private",
        origin: Literal["authenticated-write", "legacy-migration"] = "authenticated-write",
    ) -> None:
        await asyncio.to_thread(
            self._bind_memory_sync,
            soul_id,
            str(memory_id),
            tenant,
            owner_subject,
            scope,
            origin,
        )

    def _bind_memory_sync(
        self,
        soul_id: str,
        memory_id: str,
        tenant: str,
        owner_subject: str,
        scope: str,
        origin: str,
    ) -> None:
        soul = str(soul_id or "").strip()
        memory = str(memory_id or "").strip()
        tenant_id = _identity(tenant)
        owner = _identity(owner_subject)
        normalized_scope = str(scope or "").strip().casefold()
        if (
            not soul
            or not memory
            or not tenant_id
            or not owner
            or normalized_scope not in self._SCOPES
            or origin not in {"authenticated-write", "legacy-migration"}
        ):
            raise ValueError("complete trusted provenance is required")
        now_ms = int(float(self._clock()) * 1000)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT tenant,owner_subject,scope,origin FROM t5_memory_provenance_v1 "
                "WHERE soul_id=? AND memory_id=?",
                (soul, memory),
            ).fetchone()
            binding = (tenant_id, owner, normalized_scope, origin)
            if row is not None:
                existing = tuple(str(row[key]) for key in ("tenant", "owner_subject", "scope", "origin"))
                if existing != binding:
                    raise T5ProvenanceConflict(
                        "memory provenance is immutable and does not match"
                    )
                connection.commit()
                return
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM t5_memory_provenance_v1"
                ).fetchone()[0]
            )
            if count >= self.policy.max_provenance_bindings:
                raise T5ProvenanceConflict("provenance registry is full")
            connection.execute(
                "INSERT INTO t5_memory_provenance_v1"
                "(soul_id,memory_id,tenant,owner_subject,scope,origin,created_unix_ms) "
                "VALUES(?,?,?,?,?,?,?)",
                (soul, memory, tenant_id, owner, normalized_scope, origin, now_ms),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def bind_legacy_memories(
        self,
        *,
        soul_id: str,
        memory_ids: Iterable[str | int],
        tenant: str,
        owner_subject: str,
    ) -> int:
        """Idempotently bind an explicitly single-owner legacy snapshot.

        This migration never updates Core or an existing provenance row.  A
        conflict aborts the transaction and leaves all prior bindings intact.
        """

        ids = tuple(dict.fromkeys(str(value).strip() for value in memory_ids if str(value).strip()))
        return await asyncio.to_thread(
            self._bind_legacy_memories_sync,
            soul_id,
            ids,
            tenant,
            owner_subject,
        )

    def _bind_legacy_memories_sync(
        self,
        soul_id: str,
        memory_ids: tuple[str, ...],
        tenant: str,
        owner_subject: str,
    ) -> int:
        soul = str(soul_id or "").strip()
        tenant_id = _identity(tenant)
        owner = _identity(owner_subject)
        if not soul or not tenant_id or not owner:
            raise ValueError("legacy migration requires soul, tenant and owner")
        now_ms = int(float(self._clock()) * 1000)
        connection = self._connect()
        inserted = 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM t5_memory_provenance_v1"
                ).fetchone()[0]
            )
            for memory_id in memory_ids:
                row = connection.execute(
                    "SELECT tenant,owner_subject,scope,origin FROM t5_memory_provenance_v1 "
                    "WHERE soul_id=? AND memory_id=?",
                    (soul, memory_id),
                ).fetchone()
                expected = (tenant_id, owner, "private", "legacy-migration")
                if row is not None:
                    existing = tuple(str(row[key]) for key in ("tenant", "owner_subject", "scope", "origin"))
                    authenticated = (tenant_id, owner, "private", "authenticated-write")
                    if existing not in {expected, authenticated}:
                        raise T5ProvenanceConflict(
                            f"legacy provenance conflict for memory {memory_id}"
                        )
                    continue
                if count >= self.policy.max_provenance_bindings:
                    raise T5ProvenanceConflict("provenance registry is full")
                connection.execute(
                    "INSERT INTO t5_memory_provenance_v1"
                    "(soul_id,memory_id,tenant,owner_subject,scope,origin,created_unix_ms) "
                    "VALUES(?,?,?,?,?,'legacy-migration',?)",
                    (soul, memory_id, tenant_id, owner, "private", now_ms),
                )
                inserted += 1
                count += 1
            connection.commit()
            return inserted
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def evaluate(
        self,
        *,
        soul_id: str,
        tenant: str,
        session_id: str,
        interlocutor: str,
        memory_ids: Iterable[str | int],
    ) -> EgressDecision:
        ids = tuple(str(value).strip() for value in memory_ids)
        return await asyncio.to_thread(
            self._evaluate_sync,
            soul_id,
            tenant,
            session_id,
            interlocutor,
            ids,
        )

    def _evaluate_sync(
        self,
        soul_id: str,
        tenant: str,
        session_id: str,
        interlocutor: str,
        memory_ids: tuple[str, ...],
    ) -> EgressDecision:
        soul = str(soul_id or "").strip()
        tenant_id = _identity(tenant)
        session = str(session_id or "").strip()
        subject = _identity(interlocutor)
        if not soul or not tenant_id or not session or not subject:
            return EgressDecision(
                (),
                tuple(
                    BlockedMemory(value or "<missing>", "missing_verified_session_or_interlocutor")
                    for value in memory_ids
                ),
                True,
                False,
                "missing_verified_session_or_interlocutor",
            )
        now_ms = int(float(self._clock()) * 1000)
        cutoff_ms = now_ms - int(self.policy.window_seconds * 1000)
        key = (soul, tenant_id, session, subject)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM t5_budget_events_v1 WHERE created_unix_ms < ?",
                (cutoff_ms,),
            )
            stale_before = now_ms - int(max(self.policy.window_seconds, self.policy.lock_seconds) * 1000)
            connection.execute(
                "DELETE FROM t5_sessions_v1 WHERE last_seen_unix_ms < ? "
                "AND locked_until_unix_ms <= ?",
                (stale_before, now_ms),
            )
            state = connection.execute(
                "SELECT locked_until_unix_ms FROM t5_sessions_v1 WHERE "
                "soul_id=? AND tenant=? AND session_id=? AND interlocutor=?",
                key,
            ).fetchone()
            if state is None:
                count = int(
                    connection.execute("SELECT COUNT(*) FROM t5_sessions_v1").fetchone()[0]
                )
                if count >= self.policy.max_session_states:
                    connection.rollback()
                    return EgressDecision(
                        (),
                        tuple(BlockedMemory(value or "<missing>", "session_registry_full") for value in memory_ids),
                        True,
                        False,
                        "session_registry_full",
                    )
                connection.execute(
                    "INSERT INTO t5_sessions_v1"
                    "(soul_id,tenant,session_id,interlocutor,last_seen_unix_ms,locked_until_unix_ms) "
                    "VALUES(?,?,?,?,?,0)",
                    (*key, now_ms),
                )
                locked_until_ms = 0
            else:
                locked_until_ms = int(state["locked_until_unix_ms"])
                connection.execute(
                    "UPDATE t5_sessions_v1 SET last_seen_unix_ms=? WHERE "
                    "soul_id=? AND tenant=? AND session_id=? AND interlocutor=?",
                    (now_ms, *key),
                )
            if locked_until_ms > now_ms:
                connection.commit()
                return EgressDecision(
                    (),
                    tuple(BlockedMemory(value or "<missing>", "session_memory_egress_locked") for value in memory_ids),
                    True,
                    True,
                    "session_memory_egress_locked",
                )

            current_shared = int(
                connection.execute(
                    "SELECT COALESCE(SUM(fragments),0) FROM t5_budget_events_v1 WHERE "
                    "soul_id=? AND tenant=? AND session_id=? AND interlocutor=? "
                    "AND kind='shared-fragment' AND created_unix_ms>=?",
                    (*key, cutoff_ms),
                ).fetchone()[0]
            )
            current_owners = {
                str(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT foreign_owner FROM t5_budget_events_v1 WHERE "
                    "soul_id=? AND tenant=? AND session_id=? AND interlocutor=? "
                    "AND kind='shared-fragment' AND created_unix_ms>=?",
                    (*key, cutoff_ms),
                )
            }
            seen: set[str] = set()
            allowed: list[str] = []
            blocked: list[BlockedMemory] = []
            cross_owner_private = False
            shared_reservations: list[str] = []
            projected_shared = current_shared
            projected_owners = set(current_owners)

            for memory_id in memory_ids:
                if not memory_id or memory_id in seen:
                    blocked.append(
                        BlockedMemory(memory_id or "<missing>", "invalid_or_duplicate_memory_id")
                    )
                    continue
                seen.add(memory_id)
                row = connection.execute(
                    "SELECT tenant,owner_subject,scope FROM t5_memory_provenance_v1 "
                    "WHERE soul_id=? AND memory_id=?",
                    (soul, memory_id),
                ).fetchone()
                if row is None:
                    blocked.append(BlockedMemory(memory_id, "untrusted_provenance"))
                    continue
                if _identity(row["tenant"]) != tenant_id:
                    blocked.append(BlockedMemory(memory_id, "cross_tenant_provenance"))
                    continue
                owner = _identity(row["owner_subject"])
                scope = str(row["scope"]).casefold()
                if not owner or scope not in self._SCOPES:
                    blocked.append(BlockedMemory(memory_id, "invalid_stored_provenance"))
                    continue
                if scope == "private" and owner != subject:
                    cross_owner_private = True
                    blocked.append(BlockedMemory(memory_id, "cross_owner_private"))
                    continue
                if scope in {"team", "shared"} and owner != subject:
                    owners = projected_owners | {owner}
                    if len(owners) > self.policy.max_distinct_foreign_owners_per_window:
                        blocked.append(BlockedMemory(memory_id, "multi_turn_owner_aggregation"))
                        continue
                    if projected_shared + 1 > self.policy.max_shared_fragments_per_window:
                        blocked.append(BlockedMemory(memory_id, "multi_turn_shared_budget_exhausted"))
                        continue
                    projected_shared += 1
                    projected_owners = owners
                    shared_reservations.append(owner)
                allowed.append(memory_id)

            if cross_owner_private:
                connection.execute(
                    "INSERT INTO t5_budget_events_v1"
                    "(soul_id,tenant,session_id,interlocutor,kind,foreign_owner,fragments,created_unix_ms) "
                    "VALUES(?,?,?,?,'cross-owner-turn','',1,?)",
                    (*key, now_ms),
                )
            cross_turns = int(
                connection.execute(
                    "SELECT COUNT(*) FROM t5_budget_events_v1 WHERE "
                    "soul_id=? AND tenant=? AND session_id=? AND interlocutor=? "
                    "AND kind='cross-owner-turn' AND created_unix_ms>=?",
                    (*key, cutoff_ms),
                ).fetchone()[0]
            )
            locked = cross_turns >= self.policy.max_cross_owner_turns
            if locked:
                locked_until_ms = now_ms + int(self.policy.lock_seconds * 1000)
                connection.execute(
                    "UPDATE t5_sessions_v1 SET locked_until_unix_ms=? WHERE "
                    "soul_id=? AND tenant=? AND session_id=? AND interlocutor=?",
                    (locked_until_ms, *key),
                )

            batch_denied = locked or (self.policy.strict_batch and bool(blocked))
            if batch_denied:
                allowed = []
            else:
                for owner in shared_reservations:
                    connection.execute(
                        "INSERT INTO t5_budget_events_v1"
                        "(soul_id,tenant,session_id,interlocutor,kind,foreign_owner,fragments,created_unix_ms) "
                        "VALUES(?,?,?,?,'shared-fragment',?,1,?)",
                        (*key, owner, now_ms),
                    )
            connection.commit()
            reason = (
                "session_memory_egress_locked"
                if locked
                else "unsafe_memory_provenance"
                if blocked
                else "allowed"
            )
            return EgressDecision(
                tuple(allowed), tuple(blocked), batch_denied, locked, reason
            )
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
