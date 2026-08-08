"""Contained tool execution for SOUL Platform.

Every tool, including nominally pure tools, crosses the sealed external Docker
boundary.  A Python allowlist is authorization metadata, not an OS sandbox.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping, Protocol

from soul_platform.sandbox import DockerTool


class CapabilityDenied(RuntimeError):
    """The requested capability is outside the active limit."""


class ToolExecutionError(RuntimeError):
    """A tool failed without exposing its arguments or internal exception."""


class IndeterminateEffect(ToolExecutionError):
    """The external effect may have happened and MUST NOT be retried blindly."""


HIGH_RISK_SCOPES = frozenset({"filesystem", "network", "process", "database_write"})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executor: DockerTool
    effect_scopes: frozenset[str]

    def __post_init__(self) -> None:
        if not self.name or not self.effect_scopes:
            raise ValueError("tool name and effect_scopes are required")
        if type(self.executor) is not DockerTool:
            raise TypeError("tools must use the built-in external DockerTool adapter")


@dataclass(frozen=True)
class Limit:
    max_tool_calls: int
    allowed_tools: frozenset[str]
    allowed_scopes: frozenset[str] = frozenset({"pure"})
    timeout_seconds: float = 10.0
    max_output_bytes: int = 65_536

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_tool_calls, int)
            or isinstance(self.max_tool_calls, bool)
            or self.max_tool_calls < 0
        ):
            raise ValueError("max_tool_calls cannot be negative")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if (
            not isinstance(self.max_output_bytes, int)
            or isinstance(self.max_output_bytes, bool)
            or self.max_output_bytes <= 0
        ):
            raise ValueError("max_output_bytes must be positive")


@dataclass(frozen=True)
class AuditEvent:
    tenant: str
    task_id: str
    actor: str
    tool: str
    status: str
    call_number: int | None
    args_sha256: str
    policy_sha256: str
    result_sha256: str | None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class AuditSink(Protocol):
    async def append(self, event: AuditEvent) -> None: ...


class BudgetStore(Protocol):
    async def reserve(
        self, tenant: str, task_id: str, actor: str, policy_sha256: str, maximum: int
    ) -> int | None: ...


class InMemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._lock = asyncio.Lock()

    async def append(self, event: AuditEvent) -> None:
        async with self._lock:
            self.events.append(event)


class InMemoryBudgetStore:
    """Atomic within one process; durable coordinators provide a persistent store."""

    def __init__(self) -> None:
        self._used: dict[tuple[str, str, str, str], int] = {}
        self._lock = asyncio.Lock()

    async def reserve(
        self, tenant: str, task_id: str, actor: str, policy_sha256: str, maximum: int
    ) -> int | None:
        async with self._lock:
            key = (tenant, task_id, actor, policy_sha256)
            used = self._used.get(key, 0)
            if used >= maximum:
                return None
            used += 1
            self._used[key] = used
            return used


class SqliteBudgetStore:
    """Durable atomic budget shared by retries, processes and runtime restarts."""

    def __init__(self, path: str) -> None:
        self.path = path

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _initialize_sync(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS agency_budgets_v2 ("
                "tenant TEXT NOT NULL, task_id TEXT NOT NULL, actor TEXT NOT NULL, "
                "policy_sha256 TEXT NOT NULL, used INTEGER NOT NULL, "
                "PRIMARY KEY(tenant, task_id, actor, policy_sha256))"
            )
        finally:
            conn.close()

    async def reserve(
        self, tenant: str, task_id: str, actor: str, policy_sha256: str, maximum: int
    ) -> int | None:
        return await asyncio.to_thread(
            self._reserve_sync, tenant, task_id, actor, policy_sha256, maximum
        )

    def _reserve_sync(
        self, tenant: str, task_id: str, actor: str, policy_sha256: str, maximum: int
    ) -> int | None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT used FROM agency_budgets_v2 "
                "WHERE tenant=? AND task_id=? AND actor=? AND policy_sha256=?",
                (tenant, task_id, actor, policy_sha256),
            ).fetchone()
            used = int(row[0]) if row else 0
            if used >= maximum:
                conn.rollback()
                return None
            used += 1
            conn.execute(
                "INSERT INTO agency_budgets_v2(tenant,task_id,actor,policy_sha256,used) "
                "VALUES(?,?,?,?,?) ON CONFLICT(tenant,task_id,actor,policy_sha256) "
                "DO UPDATE SET used=excluded.used",
                (tenant, task_id, actor, policy_sha256, used),
            )
            conn.commit()
            return used
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


class SqliteAuditSink:
    """Append-only durable audit trail for attempted and completed effects."""

    def __init__(self, path: str) -> None:
        self.path = path

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _initialize_sync(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS agency_audit ("
                "event_id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, "
                "task_id TEXT NOT NULL, actor TEXT NOT NULL, tool TEXT NOT NULL, "
                "status TEXT NOT NULL, call_number INTEGER, args_sha256 TEXT NOT NULL, "
                "policy_sha256 TEXT NOT NULL, result_sha256 TEXT, created_at TEXT NOT NULL)"
            )
        finally:
            conn.close()

    async def append(self, event: AuditEvent) -> None:
        await asyncio.to_thread(self._append_sync, event)

    def _append_sync(self, event: AuditEvent) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO agency_audit(tenant,task_id,actor,tool,status,call_number,"
                "args_sha256,policy_sha256,result_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    event.tenant, event.task_id, event.actor, event.tool, event.status,
                    event.call_number, event.args_sha256, event.policy_sha256,
                    event.result_sha256, event.created_at,
                ),
            )
        finally:
            conn.close()

@dataclass
class AgencyModule:
    registry: Mapping[str, ToolSpec]
    limit: Limit
    task_id: str
    actor: str
    tenant: str
    budget_store: BudgetStore
    audit_sink: AuditSink

    def __post_init__(self) -> None:
        if not isinstance(self.limit, Limit):
            raise CapabilityDenied("agency cannot start without a valid Limit")
        if not self.tenant or not self.task_id or not self.actor:
            raise CapabilityDenied("tenant, task_id and verified actor are required")

    @property
    def policy_sha256(self) -> str:
        policy = {
            "allowed_scopes": sorted(self.limit.allowed_scopes),
            "allowed_tools": sorted(self.limit.allowed_tools),
            "max_output_bytes": self.limit.max_output_bytes,
            "max_tool_calls": self.limit.max_tool_calls,
            "timeout_seconds": self.limit.timeout_seconds,
        }
        return hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    async def call(self, tool: str, args: dict[str, Any] | None = None) -> str:
        args = {} if args is None else args
        try:
            if not isinstance(args, dict):
                raise TypeError("args must be an object")
            args_bytes = json.dumps(
                args, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        except (TypeError, ValueError):
            args_sha256 = hashlib.sha256(b"invalid-strict-json-args").hexdigest()
            await self._audit(tool, "invalid_args", None, args_sha256, None)
            raise CapabilityDenied("tool args must be a strict JSON object") from None
        args_sha256 = hashlib.sha256(args_bytes).hexdigest()
        spec = self.registry.get(tool)
        if tool not in self.limit.allowed_tools:
            await self._audit(tool, "denied_tool", None, args_sha256, None)
            raise CapabilityDenied(f"tool {tool!r} is outside the allowlist")
        if spec is None:
            await self._audit(tool, "missing_tool", None, args_sha256, None)
            raise CapabilityDenied(f"tool {tool!r} is not registered")
        if not spec.effect_scopes <= self.limit.allowed_scopes:
            await self._audit(tool, "denied_scope", None, args_sha256, None)
            raise CapabilityDenied("tool effect scope is outside the active limit")

        call_number = await self.budget_store.reserve(
            self.tenant, self.task_id, self.actor, self.policy_sha256,
            self.limit.max_tool_calls,
        )
        if call_number is None:
            await self._audit(tool, "budget_exhausted", None, args_sha256, None)
            raise CapabilityDenied("tool-call budget exhausted")

        # If durable audit is unavailable, fail before the external effect.
        await self._audit(tool, "reserved", call_number, args_sha256, None)

        failure: ToolExecutionError | None = None
        result: Any = None
        try:
            result = await asyncio.wait_for(
                spec.executor.run(args), timeout=self.limit.timeout_seconds
            )
        except TimeoutError:
            await self._audit(tool, "timeout", call_number, args_sha256, None)
            failure = ToolExecutionError("tool timed out inside its policy budget")
        except Exception as exc:
            await self._audit(tool, "error", call_number, args_sha256, None)
            failure = ToolExecutionError(
                f"tool failed ({type(exc).__name__}); details redacted"
            )
        if failure is not None:
            raise failure

        try:
            rendered = (
                result
                if isinstance(result, str)
                else json.dumps(result, sort_keys=True, allow_nan=False)
            )
        except (TypeError, ValueError):
            await self._audit(tool, "invalid_output", call_number, args_sha256, None)
            raise ToolExecutionError("tool output was not strict JSON serializable") from None
        encoded = rendered.encode("utf-8")
        if len(encoded) > self.limit.max_output_bytes:
            await self._audit(tool, "output_too_large", call_number, args_sha256, None)
            raise ToolExecutionError("tool output exceeded its policy limit")
        digest = hashlib.sha256(encoded).hexdigest()
        audit_failed = False
        try:
            await self._audit(tool, "ok", call_number, args_sha256, digest)
        except Exception:
            audit_failed = True
        if audit_failed:
            raise IndeterminateEffect(
                "tool effect completed but audit finalization failed; outcome indeterminate"
            )
        return rendered

    async def _audit(
        self, tool: str, status: str, call_number: int | None,
        args_sha256: str, digest: str | None,
    ) -> None:
        await self.audit_sink.append(
            AuditEvent(
                self.tenant, self.task_id, self.actor, tool, status, call_number,
                args_sha256, self.policy_sha256, digest,
            )
        )


def load_capability(
    registry: Mapping[str, ToolSpec],
    limit: Limit | None,
    *,
    task_id: str,
    actor: str,
    tenant: str,
    budget_store: BudgetStore | None = None,
    audit_sink: AuditSink | None = None,
) -> AgencyModule:
    if limit is None:
        raise CapabilityDenied("agency cannot start without a Limit")
    if budget_store is None or audit_sink is None:
        raise CapabilityDenied("explicit budget and audit stores are required")
    return AgencyModule(
        registry=registry,
        limit=limit,
        task_id=task_id,
        actor=actor,
        tenant=tenant,
        budget_store=budget_store,
        audit_sink=audit_sink,
    )
