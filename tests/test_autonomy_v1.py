from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone

import pytest

from soul_platform.autonomy import AutonomyController
from soul_platform.coordination import CoordinationDenied, Coordinator, CoordinatorStore
from soul_platform.receipts import ReceiptCheckpointStore, ReceiptSigner


async def store_for(path):
    store = CoordinatorStore(
        path, ReceiptSigner.generate("scheduler"),
        ReceiptCheckpointStore(str(path) + ".heads"),
    )
    await store.initialize()
    await store.add_member("team", "ada", "lead")
    await store.add_member("team", "alice", "worker")
    return store


async def test_schedule_emits_one_pending_task_and_never_executes_directly(tmp_path):
    store = await store_for(tmp_path / "autonomy.db")
    controller = AutonomyController(store)
    when = datetime(2026, 1, 1, tzinfo=UTC)
    await controller.create_schedule(
        "team", "ada", "health", "inspect service health",
        interval_seconds=60, first_run=when, idempotency_key="schedule-health",
    )
    results = await asyncio.gather(
        controller.tick("team", "ada", now=when),
        controller.tick("team", "ada", now=when),
    )
    tasks = [task for batch in results for task in batch]
    assert len(tasks) == 1 and tasks[0].state == "pending"
    # The monitor produces work only; a separate contained runtime must claim it.
    claimed = await Coordinator(store).claim(tasks[0].task_id, "alice", "claim")
    assert claimed.current_agent == "alice"
    assert store.checkpoint_store.head("team", tasks[0].task_id) is not None


async def test_worker_cannot_create_or_tick_schedules(tmp_path):
    store = await store_for(tmp_path / "denied.db")
    controller = AutonomyController(store)
    with pytest.raises(CoordinationDenied, match="lead"):
        await controller.create_schedule(
            "team", "alice", "bad", "unsafe", interval_seconds=60,
            idempotency_key="schedule-bad",
        )
    with pytest.raises(CoordinationDenied, match="lead"):
        await controller.tick("team", "alice")


async def test_schedule_bounds_timezone_and_idempotency(tmp_path):
    store = await store_for(tmp_path / "bounds.db")
    controller = AutonomyController(store)
    with pytest.raises(ValueError, match="timezone"):
        await controller.create_schedule(
            "team", "ada", "naive", "bad", interval_seconds=60,
            idempotency_key="naive", first_run=datetime(2026, 1, 1),
        )
    when = datetime(2026, 1, 1, tzinfo=UTC)
    await controller.create_schedule(
        "team", "ada", "one", "bounded", interval_seconds=60,
        idempotency_key="one", first_run=when,
    )
    await controller.create_schedule(
        "team", "ada", "one", "bounded", interval_seconds=60,
        idempotency_key="one", first_run=when,
    )
    with pytest.raises(CoordinationDenied, match="payload"):
        await controller.create_schedule(
            "team", "ada", "one", "changed", interval_seconds=60,
            idempotency_key="one", first_run=when,
        )
    with pytest.raises(ValueError, match="max_runs"):
        await controller.tick("team", "ada", now=when, max_runs=0)
    assert store.checkpoint_store.head("team", "schedule:one") is not None


async def test_schedule_normalizes_offsets_before_sql_comparison(tmp_path):
    store = await store_for(tmp_path / "offset.db")
    controller = AutonomyController(store)
    plus_two = timezone(timedelta(hours=2))
    await controller.create_schedule(
        "team", "ada", "offset", "due in UTC", interval_seconds=60,
        idempotency_key="offset", first_run=datetime(2026, 1, 1, 1, 0, tzinfo=plus_two),
    )
    tasks = await controller.tick(
        "team", "ada", now=datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    )
    assert len(tasks) == 1
