from __future__ import annotations

import asyncio
import base64
import sqlite3
from dataclasses import replace

import pytest

from soul_platform.coordination import (
    ChannelService, CoordinationDenied, Coordinator, CoordinatorStore,
)
from soul_platform.receipts import ReceiptCheckpointStore, ReceiptSigner, ReceiptVerifier


async def setup_store(path):
    original = ReceiptSigner.generate("coordinator-test")
    signer = ReceiptSigner.from_private_bytes(original.private_bytes(), "coordinator-test")
    checkpoint = ReceiptCheckpointStore(str(path) + ".heads")
    store = CoordinatorStore(path, signer, checkpoint)
    await store.initialize()
    for agent, role in (
        ("ada", "lead"), ("alice", "worker"), ("nexus", "worker"),
        ("fable", "reviewer"),
    ):
        await store.add_member("team", agent, role)
    return store, signer


async def test_handoff_restart_idempotency_and_signed_chain(tmp_path):
    path = tmp_path / "coordination.db"
    store, signer = await setup_store(path)
    coordinator = Coordinator(store)
    task = await coordinator.create_task("team", "ada", "ship", "create-1")
    assert (await coordinator.create_task("team", "ada", "ship", "create-1")).task_id == task.task_id
    with pytest.raises(CoordinationDenied, match="idempotency"):
        await coordinator.claim(task.task_id, "alice", "create-1")
    claimed = await coordinator.claim(task.task_id, "alice", "claim-1")
    assert claimed.current_agent == "alice"
    handed = await coordinator.handoff(
        task.task_id, "alice", "nexus", "handoff-1", expected_version=claimed.version
    )
    assert handed.current_agent == "nexus" and handed.lease_until is not None
    completed = await coordinator.complete(
        task.task_id, "nexus", "complete-1", expected_version=handed.version
    )
    assert completed.state == "completed"
    replayed = await coordinator.handoff(
        task.task_id, "alice", "nexus", "handoff-1", expected_version=claimed.version
    )
    assert replayed.state == "claimed" and replayed.current_agent == "nexus"

    # Re-open with the same operator key bytes, as a process restart would.
    reopened_signer = ReceiptSigner.from_private_bytes(signer.private_bytes(), "coordinator-test")
    reopened = CoordinatorStore(
        path, reopened_signer, ReceiptCheckpointStore(str(path) + ".heads")
    )
    await reopened.initialize()
    events = await reopened.events("team", task.task_id, "ada")
    payloads = await reopened.event_payloads("team", task.task_id, "ada")
    verifier = ReceiptVerifier({"coordinator-test": signer.public_key()})
    head = reopened.checkpoint_store.head("team", task.task_id)
    assert verifier.verify_chain(
        events, payloads, expected_head=head,
        expected_tenant="team", expected_task_id=task.task_id,
    )
    assert not verifier.verify_chain(
        events[:-1], payloads[:-1], expected_head=head,
        expected_tenant="team", expected_task_id=task.task_id,
    )
    assert not verifier.verify(replace(events[-1], actor="mallory"))
    assert not verifier.verify_payload(events[-1], {"state": "forged"})
    forged_b64 = replace(events[-1], signature=events[-1].signature + "AAAA")
    assert not verifier.verify(forged_b64)
    assert not ReceiptVerifier({}).verify(events[-1])


async def test_concurrent_claim_has_one_winner_and_reviewer_cannot_execute(tmp_path):
    store, _ = await setup_store(tmp_path / "race.db")
    coordinator = Coordinator(store)
    task = await coordinator.create_task("team", "ada", "race", "create-race")
    with pytest.raises(CoordinationDenied, match="reviewers"):
        await coordinator.claim(task.task_id, "fable", "reviewer-claim")
    results = await asyncio.gather(
        coordinator.claim(task.task_id, "alice", "alice-claim"),
        coordinator.claim(task.task_id, "nexus", "nexus-claim"),
        return_exceptions=True,
    )
    assert sum(not isinstance(item, Exception) for item in results) == 1
    assert sum(isinstance(item, CoordinationDenied) for item in results) == 1


async def test_lease_duration_is_bounded_and_expired_claim_can_be_recovered(tmp_path):
    path = tmp_path / "bounded-lease.db"
    store, _ = await setup_store(path)
    coordinator = Coordinator(store)
    task = await coordinator.create_task("team", "ada", "bounded", "create-bounded")

    for invalid in (3601, 1_000_000_000):
        with pytest.raises(ValueError, match="between 1 and 3600"):
            await coordinator.claim(
                task.task_id, "alice", f"claim-{invalid}", lease_seconds=invalid
            )

    claimed = await coordinator.claim(
        task.task_id, "alice", "claim-maximum", lease_seconds=3600
    )
    assert claimed.current_agent == "alice"

    for invalid in (3601, 1_000_000_000):
        with pytest.raises(ValueError, match="between 1 and 3600"):
            await coordinator.handoff(
                task.task_id,
                "alice",
                "nexus",
                f"handoff-{invalid}",
                expected_version=claimed.version,
                lease_seconds=invalid,
            )

    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "UPDATE tasks SET lease_until='2000-01-01T00:00:00+00:00' "
            "WHERE task_id=?",
            (task.task_id,),
        )
        conn.commit()
    finally:
        conn.close()

    recovered = await coordinator.claim(
        task.task_id, "nexus", "claim-after-expiry", lease_seconds=3600
    )
    handed = await coordinator.handoff(
        task.task_id,
        "nexus",
        "alice",
        "handoff-maximum",
        expected_version=recovered.version,
        lease_seconds=3600,
    )
    assert handed.current_agent == "alice"


async def test_roles_owner_and_expired_lease_fail_closed(tmp_path):
    path = tmp_path / "roles.db"
    store, _ = await setup_store(path)
    coordinator = Coordinator(store)
    with pytest.raises(CoordinationDenied, match="lead"):
        await coordinator.create_task("team", "alice", "forbidden", "bad-create")
    task = await coordinator.create_task("team", "ada", "owned", "good-create")
    await coordinator.claim(task.task_id, "alice", "claim")
    with pytest.raises(CoordinationDenied, match="current claimant"):
        await coordinator.complete(
            task.task_id, "nexus", "bad-complete", expected_version=1
        )
    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE tasks SET lease_until='2000-01-01T00:00:00+00:00' WHERE task_id=?", (task.task_id,))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(CoordinationDenied, match="expired"):
        await coordinator.complete(
            task.task_id, "alice", "expired-complete", expected_version=1
        )
    with pytest.raises(CoordinationDenied, match="expired"):
        await coordinator.handoff(
            task.task_id, "alice", "nexus", "expired-handoff", expected_version=1
        )


async def test_idempotency_key_is_bound_to_full_request_and_task(tmp_path):
    store, _ = await setup_store(tmp_path / "idempotency.db")
    coordinator = Coordinator(store)
    first = await coordinator.create_task("team", "ada", "first", "create-first")
    with pytest.raises(CoordinationDenied, match="payload"):
        await coordinator.create_task("team", "ada", "changed", "create-first")

    second = await coordinator.create_task("team", "ada", "second", "create-second")
    await coordinator.claim(first.task_id, "alice", "claim-shared", lease_seconds=60)
    with pytest.raises(CoordinationDenied, match="another task"):
        await coordinator.claim(second.task_id, "alice", "claim-shared", lease_seconds=60)
    with pytest.raises(CoordinationDenied, match="payload"):
        await coordinator.claim(first.task_id, "alice", "claim-shared", lease_seconds=30)

    await coordinator.handoff(
        first.task_id, "alice", "nexus", "handoff-bound", expected_version=1
    )
    with pytest.raises(CoordinationDenied, match="payload"):
        await coordinator.handoff(
            first.task_id, "alice", "ada", "handoff-bound", expected_version=1
        )


async def test_events_require_tenant_scope(tmp_path):
    store, _ = await setup_store(tmp_path / "tenant.db")
    coordinator = Coordinator(store)
    task = await coordinator.create_task("team", "ada", "secret", "create")
    assert len(await store.events("team", task.task_id, "alice")) == 1
    with pytest.raises(CoordinationDenied, match="member"):
        await store.events("other", task.task_id, "alice")


async def test_fencing_revocation_and_legacy_schema_migration(tmp_path):
    path = tmp_path / "fencing.db"
    store, _ = await setup_store(path)
    coordinator = Coordinator(store)
    task = await coordinator.create_task("team", "ada", "fence", "create")
    lease1 = await coordinator.claim(task.task_id, "alice", "claim-1")
    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE tasks SET lease_until='2000-01-01T00:00:00+00:00' WHERE task_id=?", (task.task_id,))
        conn.commit()
    finally:
        conn.close()
    lease2 = await coordinator.claim(task.task_id, "alice", "claim-2")
    with pytest.raises(CoordinationDenied, match="fencing"):
        await coordinator.complete(
            task.task_id, "alice", "stale", expected_version=lease1.version
        )
    await store.add_member("team", "alice", "reviewer")
    with pytest.raises(CoordinationDenied, match="execution role"):
        await coordinator.complete(
            task.task_id, "alice", "revoked", expected_version=lease2.version
        )

    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    try:
        conn.executescript(
            "CREATE TABLE events(event_id INTEGER PRIMARY KEY, tenant TEXT, task_id TEXT, "
            "actor TEXT,event TEXT,idempotency_key TEXT,receipt_json TEXT,"
            "receipt_sha256 TEXT,created_at TEXT);"
        )
        conn.commit()
    finally:
        conn.close()
    migrated = CoordinatorStore(
        legacy, ReceiptSigner.generate("legacy"),
        ReceiptCheckpointStore(str(legacy) + ".heads"),
    )
    await migrated.initialize()
    conn = sqlite3.connect(legacy)
    try:
        assert "payload_json" in {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    finally:
        conn.close()


async def test_private_channels_enforce_membership_and_idempotency(tmp_path):
    store, _ = await setup_store(tmp_path / "channels.db")
    channels = ChannelService(store)
    await channels.create_channel("team", "ada", "general", kind="team")
    await channels.create_channel(
        "team", "ada", "dm:ada:alice", kind="dm", participants={"alice"}
    )
    first = await channels.send("team", "dm:ada:alice", "alice", "hola", "m1")
    replay = await channels.send("team", "dm:ada:alice", "alice", "hola", "m1")
    assert replay.message_id == first.message_id
    with pytest.raises(CoordinationDenied, match="payload"):
        await channels.send("team", "dm:ada:alice", "alice", "cambiado", "m1")
    with pytest.raises(CoordinationDenied, match="DM"):
        await channels.read("team", "dm:ada:alice", "nexus")
    assert [message.content for message in await channels.read(
        "team", "dm:ada:alice", "ada"
    )] == ["hola"]


def test_receipt_chain_rejects_mixed_tenant_or_task():
    signer = ReceiptSigner.generate("mixed")
    first_payload = {"step": 1}
    first = signer.sign(
        receipt_id="1", tenant="a", task_id="one", actor="ada",
        event="x", payload=first_payload,
    )
    second_payload = {"step": 2}
    second = signer.sign(
        receipt_id="2", tenant="b", task_id="two", actor="ada",
        event="y", payload=second_payload, previous_sha256=first.sha256(),
    )
    verifier = ReceiptVerifier({"mixed": signer.public_key()})
    assert not verifier.verify_chain([first, second], [first_payload, second_payload])


async def test_checkpoint_outbox_reports_commit_and_blocks_next_mutation(tmp_path, monkeypatch):
    path = tmp_path / "outbox.db"
    store, _ = await setup_store(path)
    coordinator = Coordinator(store)
    original = store.checkpoint_store.record
    monkeypatch.setattr(
        store.checkpoint_store, "record",
        lambda _receipt: (_ for _ in ()).throw(OSError("sidecar unavailable")),
    )
    # The authoritative event/outbox commit succeeds and is not misreported as absent.
    task = await coordinator.create_task("team", "ada", "durable", "create-outbox")
    assert task.state == "pending" and await store.checkpoint_pending_count() == 1
    # Forward mutation is fail-closed until the durable head can catch up.
    with pytest.raises(OSError, match="sidecar"):
        await coordinator.claim(task.task_id, "alice", "claim-blocked")
    monkeypatch.setattr(store.checkpoint_store, "record", original)
    assert await store.reconcile_checkpoints() == 1
    assert await store.checkpoint_pending_count() == 0
    assert (await coordinator.claim(task.task_id, "alice", "claim-ok")).state == "claimed"


async def test_outbox_migration_accepts_historical_sidecar_already_at_head(tmp_path):
    path = tmp_path / "historical.db"
    store, signer = await setup_store(path)
    coordinator = Coordinator(store)
    task = await coordinator.create_task("team", "ada", "history", "create-history")
    await coordinator.claim(task.task_id, "alice", "claim-history")
    expected_head = store.checkpoint_store.head("team", task.task_id)
    conn = sqlite3.connect(path)
    try:
        conn.execute("DROP TABLE receipt_checkpoint_outbox")
        conn.commit()
    finally:
        conn.close()
    reopened = CoordinatorStore(
        path, ReceiptSigner.from_private_bytes(signer.private_bytes(), "coordinator-test"),
        ReceiptCheckpointStore(str(path) + ".heads"),
    )
    await reopened.initialize()
    assert await reopened.checkpoint_pending_count() == 0
    assert reopened.checkpoint_store.head("team", task.task_id) == expected_head
