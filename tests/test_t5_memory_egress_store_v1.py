from __future__ import annotations

import asyncio

import pytest

from soul_platform.t5_memory_egress import (
    SQLiteT5EgressStore,
    T5EgressPolicy,
    T5ProvenanceConflict,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def _store(tmp_path, *, policy=None, clock=None):
    store = SQLiteT5EgressStore(
        tmp_path / "t5.sqlite3", policy=policy, clock=clock or Clock()
    )
    await store.initialize()
    return store


async def test_provenance_is_immutable_and_unknown_ids_fail_closed(tmp_path):
    store = await _store(tmp_path)
    await store.bind_memory(
        soul_id="soul", memory_id="m1", tenant="team", owner_subject="alice"
    )
    # Exact repeats are idempotent; any identity/scope/origin drift is rejected.
    await store.bind_memory(
        soul_id="soul", memory_id="m1", tenant="TEAM", owner_subject="ALICE"
    )
    with pytest.raises(T5ProvenanceConflict, match="immutable"):
        await store.bind_memory(
            soul_id="soul", memory_id="m1", tenant="team", owner_subject="mallory"
        )

    decision = await store.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="signed-session",
        interlocutor="alice",
        memory_ids=["not-bound"],
    )
    assert decision.allowed_ids == ()
    assert decision.blocked[0].reason == "untrusted_provenance"


async def test_budget_is_durable_across_store_instances_and_restart(tmp_path):
    clock = Clock()
    policy = T5EgressPolicy(max_shared_fragments_per_window=1)
    first = await _store(tmp_path, policy=policy, clock=clock)
    for memory_id in ("shared-1", "shared-2"):
        await first.bind_memory(
            soul_id="soul",
            memory_id=memory_id,
            tenant="team",
            owner_subject="bob",
            scope="shared",
        )
    allowed = await first.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="session-a",
        interlocutor="alice",
        memory_ids=["shared-1"],
    )
    restarted_worker = SQLiteT5EgressStore(
        tmp_path / "t5.sqlite3", policy=policy, clock=clock
    )
    await restarted_worker.initialize()
    denied = await restarted_worker.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="session-a",
        interlocutor="alice",
        memory_ids=["shared-2"],
    )
    assert allowed.allowed_ids == ("shared-1",)
    assert denied.allowed_ids == ()
    assert denied.blocked[0].reason == "multi_turn_shared_budget_exhausted"


async def test_concurrent_workers_reserve_one_shared_budget_atomically(tmp_path):
    clock = Clock()
    policy = T5EgressPolicy(max_shared_fragments_per_window=1)
    stores = [
        await _store(tmp_path, policy=policy, clock=clock),
        await _store(tmp_path, policy=policy, clock=clock),
    ]
    for memory_id in ("a", "b"):
        await stores[0].bind_memory(
            soul_id="soul",
            memory_id=memory_id,
            tenant="team",
            owner_subject="bob",
            scope="shared",
        )

    async def attempt(store, memory_id):
        return await store.evaluate(
            soul_id="soul",
            tenant="team",
            session_id="same-signed-session",
            interlocutor="alice",
            memory_ids=[memory_id],
        )

    decisions = await asyncio.gather(
        attempt(stores[0], "a"), attempt(stores[1], "b")
    )
    assert sum(decision.allowed for decision in decisions) == 1
    assert sorted(
        blocked.reason
        for decision in decisions
        for blocked in decision.blocked
    ) == ["multi_turn_shared_budget_exhausted"]


async def test_cross_owner_lock_survives_restart_and_is_session_scoped(tmp_path):
    clock = Clock()
    policy = T5EgressPolicy(max_cross_owner_turns=1, lock_seconds=60)
    first = await _store(tmp_path, policy=policy, clock=clock)
    await first.bind_memory(
        soul_id="soul", memory_id="foreign", tenant="team", owner_subject="bob"
    )
    await first.bind_memory(
        soul_id="soul", memory_id="own", tenant="team", owner_subject="alice"
    )
    locked = await first.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="s1",
        interlocutor="alice",
        memory_ids=["foreign"],
    )
    second = SQLiteT5EgressStore(tmp_path / "t5.sqlite3", policy=policy, clock=clock)
    await second.initialize()
    still_locked = await second.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="s1",
        interlocutor="alice",
        memory_ids=["own"],
    )
    other_session = await second.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="s2",
        interlocutor="alice",
        memory_ids=["own"],
    )
    assert locked.session_locked is True
    assert still_locked.reason == "session_memory_egress_locked"
    assert other_session.allowed_ids == ("own",)


async def test_legacy_migration_is_non_destructive_idempotent_and_atomic(tmp_path):
    store = await _store(tmp_path)
    assert await store.bind_legacy_memories(
        soul_id="soul", memory_ids=[1, 2], tenant="local", owner_subject="owner"
    ) == 2
    assert await store.bind_legacy_memories(
        soul_id="soul", memory_ids=[1, 2], tenant="local", owner_subject="owner"
    ) == 0
    await store.bind_memory(
        soul_id="soul",
        memory_id="conflict",
        tenant="local",
        owner_subject="different",
    )
    with pytest.raises(T5ProvenanceConflict, match="conflict"):
        await store.bind_legacy_memories(
            soul_id="soul",
            memory_ids=["new-before-conflict", "conflict"],
            tenant="local",
            owner_subject="owner",
        )
    # The failed transaction did not leave its earlier insert behind.
    decision = await store.evaluate(
        soul_id="soul",
        tenant="local",
        session_id="session",
        interlocutor="owner",
        memory_ids=["new-before-conflict"],
    )
    assert decision.blocked[0].reason == "untrusted_provenance"


async def test_missing_signed_session_fails_closed_without_persisting_budget(tmp_path):
    store = await _store(tmp_path)
    await store.bind_memory(
        soul_id="soul", memory_id="own", tenant="team", owner_subject="alice"
    )
    denied = await store.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="",
        interlocutor="alice",
        memory_ids=["own"],
    )
    allowed = await store.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="signed-session",
        interlocutor="alice",
        memory_ids=["own"],
    )
    assert denied.reason == "missing_verified_session_or_interlocutor"
    assert allowed.allowed_ids == ("own",)


async def test_window_expiry_releases_budget_and_lock(tmp_path):
    clock = Clock()
    policy = T5EgressPolicy(
        window_seconds=10,
        lock_seconds=5,
        max_cross_owner_turns=1,
        max_shared_fragments_per_window=1,
    )
    store = await _store(tmp_path, policy=policy, clock=clock)
    for memory_id, owner, scope in (
        ("own", "alice", "private"),
        ("foreign", "bob", "private"),
        ("shared-1", "bob", "shared"),
        ("shared-2", "bob", "shared"),
    ):
        await store.bind_memory(
            soul_id="soul",
            memory_id=memory_id,
            tenant="team",
            owner_subject=owner,
            scope=scope,
        )
    assert (
        await store.evaluate(
            soul_id="soul", tenant="team", session_id="budget",
            interlocutor="alice", memory_ids=["shared-1"]
        )
    ).allowed
    exhausted = await store.evaluate(
        soul_id="soul", tenant="team", session_id="budget",
        interlocutor="alice", memory_ids=["shared-2"]
    )
    locked = await store.evaluate(
        soul_id="soul", tenant="team", session_id="lock",
        interlocutor="alice", memory_ids=["foreign"]
    )
    assert exhausted.blocked[0].reason == "multi_turn_shared_budget_exhausted"
    assert locked.session_locked is True
    clock.advance(11)
    assert (
        await store.evaluate(
            soul_id="soul", tenant="team", session_id="budget",
            interlocutor="alice", memory_ids=["shared-2"]
        )
    ).allowed
    assert (
        await store.evaluate(
            soul_id="soul", tenant="team", session_id="lock",
            interlocutor="alice", memory_ids=["own"]
        )
    ).allowed


async def test_session_and_provenance_registries_fail_closed_at_exact_bounds(tmp_path):
    policy = T5EgressPolicy(max_session_states=1, max_provenance_bindings=1)
    store = await _store(tmp_path, policy=policy)
    await store.bind_memory(
        soul_id="soul", memory_id="first", tenant="team", owner_subject="alice"
    )
    with pytest.raises(T5ProvenanceConflict, match="full"):
        await store.bind_memory(
            soul_id="soul", memory_id="second", tenant="team", owner_subject="alice"
        )
    assert (
        await store.evaluate(
            soul_id="soul", tenant="team", session_id="s1",
            interlocutor="alice", memory_ids=["first"]
        )
    ).allowed
    denied = await store.evaluate(
        soul_id="soul", tenant="team", session_id="s2",
        interlocutor="alice", memory_ids=["first"]
    )
    assert denied.reason == "session_registry_full"


async def test_invalid_provenance_and_legacy_identity_fail_closed(tmp_path):
    store = await _store(tmp_path)
    with pytest.raises(ValueError, match="complete trusted provenance"):
        await store.bind_memory(
            soul_id="soul",
            memory_id="memory",
            tenant="team",
            owner_subject="alice",
            scope="unknown",
        )
    with pytest.raises(ValueError, match="legacy migration requires"):
        await store.bind_legacy_memories(
            soul_id="soul",
            memory_ids=["memory"],
            tenant="",
            owner_subject="alice",
        )


async def test_missing_and_duplicate_memory_ids_are_explicitly_blocked(tmp_path):
    store = await _store(tmp_path)
    await store.bind_memory(
        soul_id="soul", memory_id="own", tenant="team", owner_subject="alice"
    )
    decision = await store.evaluate(
        soul_id="soul",
        tenant="team",
        session_id="signed-session",
        interlocutor="alice",
        memory_ids=["", "own", "own"],
    )
    assert decision.allowed_ids == ()
    assert decision.batch_denied is True
    assert [blocked.reason for blocked in decision.blocked] == [
        "invalid_or_duplicate_memory_id",
        "invalid_or_duplicate_memory_id",
    ]
