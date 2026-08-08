"""Bounded autonomy: durable schedules emit tasks, never raw host effects."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from soul_platform.coordination import CoordinationDenied, CoordinatorStore, TaskRecord
from soul_platform.receipts import SignedReceipt


class AutonomyController:
    """Turn due monitors into auditable coordinator work.

    A schedule cannot run a command. It only creates a pending task. Execution
    still requires a claim, fencing token, explicit ``Limit`` and DockerTool.
    """

    def __init__(self, store: CoordinatorStore) -> None:
        self.store = store

    async def create_schedule(
        self,
        tenant: str,
        actor: str,
        schedule_id: str,
        objective: str,
        *,
        interval_seconds: int,
        idempotency_key: str,
        first_run: datetime | None = None,
    ) -> None:
        if (
            not schedule_id or not idempotency_key or not objective
            or len(objective.encode("utf-8")) > 4096
            or not 1 <= interval_seconds <= 2_592_000
        ):
            raise ValueError("invalid schedule")
        first_run = first_run or datetime.now(UTC)
        if first_run.tzinfo is None or first_run.utcoffset() is None:
            raise ValueError("first_run must be timezone-aware")
        first_run = first_run.astimezone(UTC)
        request = {
            "schedule_id": schedule_id,
            "objective": objective,
            "interval_seconds": interval_seconds,
            "first_run": first_run.isoformat(),
        }

        def create_sync() -> None:
            conn = self.store._connect()
            try:
                self.store._reconcile_pending_sync(conn)
                conn.execute("BEGIN IMMEDIATE")
                if self.store._member_role(conn, tenant, actor) != "lead":
                    raise CoordinationDenied("only a lead can create schedules")
                prior = conn.execute(
                    "SELECT payload_json FROM schedule_events WHERE tenant=? AND idempotency_key=?",
                    (tenant, idempotency_key),
                ).fetchone()
                if prior is not None:
                    if json.loads(prior["payload_json"])["request"] != request:
                        raise CoordinationDenied("schedule idempotency key payload mismatch")
                    conn.commit()
                    return
                count = int(conn.execute(
                    "SELECT count(*) FROM schedules WHERE tenant=?", (tenant,)
                ).fetchone()[0])
                if count >= 1000:
                    raise CoordinationDenied("tenant schedule limit reached")
                conn.execute(
                    "INSERT INTO schedules VALUES(?,?,?,?,?,?,?)",
                    (
                        tenant, schedule_id, objective, interval_seconds,
                        first_run.isoformat(), 1, actor,
                    ),
                )
                payload = {"request": request, "schedule": {"enabled": True}}
                receipt = self.store.signer.sign(
                    receipt_id=str(uuid.uuid4()), tenant=tenant,
                    task_id=f"schedule:{schedule_id}", actor=actor,
                    event="schedule_created", payload=payload,
                )
                cursor = conn.execute(
                    "INSERT INTO schedule_events(tenant,schedule_id,actor,event,idempotency_key,"
                    "payload_json,receipt_json,receipt_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        tenant, schedule_id, actor, "schedule_created", idempotency_key,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        json.dumps(asdict(receipt), sort_keys=True), receipt.sha256(),
                        receipt.created_at,
                    ),
                )
                conn.execute(
                    "INSERT INTO receipt_checkpoint_outbox VALUES('schedule',?,?,0)",
                    (cursor.lastrowid, json.dumps(asdict(receipt), sort_keys=True)),
                )
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()

        await asyncio.to_thread(create_sync)
        try:
            await self.store.reconcile_checkpoints()
        except Exception:
            pass

    async def tick(
        self, tenant: str, actor: str, *, now: datetime | None = None,
        max_runs: int = 100,
    ) -> list[TaskRecord]:
        observed = now or datetime.now(UTC)
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        observed = observed.astimezone(UTC)
        if not 1 <= max_runs <= 1000:
            raise ValueError("max_runs must be between 1 and 1000")

        def tick_sync() -> tuple[list[TaskRecord], list[SignedReceipt]]:
            conn = self.store._connect()
            tasks: list[TaskRecord] = []
            receipts: list[SignedReceipt] = []
            try:
                conn.execute("BEGIN IMMEDIATE")
                self.store._reconcile_pending_sync(conn)
                if self.store._member_role(conn, tenant, actor) != "lead":
                    raise CoordinationDenied("only a lead can tick schedules")
                rows = conn.execute(
                    "SELECT * FROM schedules WHERE tenant=? AND enabled=1 AND next_run<=? "
                    "ORDER BY next_run,schedule_id LIMIT ?",
                    (tenant, observed.isoformat(), max_runs),
                ).fetchall()
                for row in rows:
                    scheduled_for = str(row["next_run"])
                    existing = conn.execute(
                        "SELECT task_id FROM schedule_runs WHERE tenant=? AND schedule_id=? "
                        "AND scheduled_for=?", (tenant, row["schedule_id"], scheduled_for),
                    ).fetchone()
                    if existing is None:
                        now_text = observed.isoformat()
                        task = TaskRecord(
                            str(uuid.uuid4()), tenant, str(row["objective"]),
                            "pending", None, None, 0,
                        )
                        conn.execute(
                            "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?)",
                            (
                                task.task_id, tenant, task.objective, task.state,
                                None, None, 0, now_text, now_text,
                            ),
                        )
                        key = f"schedule:{row['schedule_id']}:{scheduled_for}"
                        payload = {
                            "request": {
                                "schedule_id": row["schedule_id"],
                                "scheduled_for": scheduled_for,
                            },
                            "task": asdict(task),
                        }
                        receipts.append(
                            self.store._append_event(
                                conn, task, actor, "scheduled", key, payload
                            )
                        )
                        conn.execute(
                            "INSERT INTO schedule_runs VALUES(?,?,?,?)",
                            (tenant, row["schedule_id"], scheduled_for, task.task_id),
                        )
                        tasks.append(task)
                    next_run = datetime.fromisoformat(scheduled_for)
                    interval = timedelta(seconds=int(row["interval_seconds"]))
                    while next_run <= observed:
                        next_run += interval
                    conn.execute(
                        "UPDATE schedules SET next_run=? WHERE tenant=? AND schedule_id=?",
                        (next_run.isoformat(), tenant, row["schedule_id"]),
                    )
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()
            return tasks, receipts

        tasks, receipts = await asyncio.to_thread(tick_sync)
        try:
            await self.store.reconcile_checkpoints()
        except Exception:
            pass
        return tasks
