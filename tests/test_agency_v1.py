from __future__ import annotations

import asyncio
import sqlite3

import pytest

from soul_platform.agency import (
    CapabilityDenied,
    InMemoryAuditSink,
    InMemoryBudgetStore,
    IndeterminateEffect,
    Limit,
    SqliteAuditSink,
    SqliteBudgetStore,
    ToolExecutionError,
    ToolSpec,
    load_capability,
)
from soul_platform.sandbox import DockerSandbox, DockerTool, ImageTrustStore, SandboxPolicy


BUSYBOX = "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d"


@pytest.fixture
def trust_store(tmp_path):
    path = tmp_path / "trusted-images.txt"
    path.write_text(BUSYBOX + "\n")
    path.chmod(0o600)
    return ImageTrustStore.from_file(str(path))


def docker_tool(script: str, trust_store: ImageTrustStore, *, timeout: float = 3) -> DockerTool:
    policy = SandboxPolicy(BUSYBOX, trust_store, timeout_seconds=timeout)
    return DockerTool(DockerSandbox(policy), ("sh", "-c", script, "soul-tool"))


def agency(registry, limit, *, task_id="t", budget=None, audit=None):
    return load_capability(
        registry, limit, tenant="team", task_id=task_id, actor="ada",
        budget_store=budget or InMemoryBudgetStore(),
        audit_sink=audit or InMemoryAuditSink(),
    )


def test_agency_requires_limit_stores_and_external_adapter():
    with pytest.raises(CapabilityDenied):
        load_capability({}, None, tenant="team", task_id="t", actor="ada")
    with pytest.raises(CapabilityDenied, match="explicit"):
        load_capability(
            {}, Limit(0, frozenset()), tenant="team", task_id="t", actor="ada"
        )
    with pytest.raises(TypeError, match="DockerTool"):
        ToolSpec("net", object(), frozenset({"network"}))  # type: ignore[arg-type]


async def test_concurrent_budget_is_atomic_and_audited(trust_store):
    audit = InMemoryAuditSink()
    module = agency(
        {"echo": ToolSpec("echo", docker_tool('printf "%s" "$1"', trust_store), frozenset({"pure"}))},
        Limit(3, frozenset({"echo"})), task_id="task-1", audit=audit,
    )
    results = await asyncio.gather(
        *(module.call("echo", {"value": index}) for index in range(6)),
        return_exceptions=True,
    )
    assert sum(isinstance(result, str) for result in results) == 3
    assert sum(isinstance(result, CapabilityDenied) for result in results) == 3
    assert sum(event.status == "reserved" for event in audit.events) == 3
    assert sum(event.status == "ok" for event in audit.events) == 3
    assert sum(event.status == "budget_exhausted" for event in audit.events) == 3
    assert all(event.tenant == "team" and len(event.policy_sha256) == 64 for event in audit.events)


async def test_timeout_output_and_scope_fail_closed(trust_store):
    slow = agency(
        {"slow": ToolSpec("slow", docker_tool("sleep 1", trust_store), frozenset({"pure"}))},
        Limit(1, frozenset({"slow"}), timeout_seconds=0.05), task_id="slow",
    )
    with pytest.raises(ToolExecutionError, match="timed out"):
        await slow.call("slow")

    large = agency(
        {"large": ToolSpec("large", docker_tool("printf 12345678901234567890", trust_store), frozenset({"pure"}))},
        Limit(1, frozenset({"large"}), max_output_bytes=10), task_id="large",
    )
    with pytest.raises(ToolExecutionError, match="output"):
        await large.call("large")

    denied = agency(
        {"network": ToolSpec("network", docker_tool("printf ok", trust_store), frozenset({"network"}))},
        Limit(1, frozenset({"network"})), task_id="scope",
    )
    with pytest.raises(CapabilityDenied, match="scope"):
        await denied.call("network")


async def test_budget_and_audit_survive_runtime_restart(tmp_path, trust_store):
    path = str(tmp_path / "agency.db")
    first_store, first_audit = SqliteBudgetStore(path), SqliteAuditSink(path)
    await first_store.initialize()
    await first_audit.initialize()
    tool = ToolSpec("echo", docker_tool("printf ok", trust_store), frozenset({"pure"}))
    first = agency(
        {"echo": tool}, Limit(2, frozenset({"echo"})), task_id="durable",
        budget=first_store, audit=first_audit,
    )
    assert await first.call("echo") == "ok"

    reopened_store, reopened_audit = SqliteBudgetStore(path), SqliteAuditSink(path)
    await reopened_store.initialize()
    await reopened_audit.initialize()
    reopened = agency(
        {"echo": tool}, Limit(2, frozenset({"echo"})), task_id="durable",
        budget=reopened_store, audit=reopened_audit,
    )
    assert await reopened.call("echo") == "ok"
    with pytest.raises(CapabilityDenied, match="budget"):
        await reopened.call("echo")
    conn = sqlite3.connect(path)
    try:
        statuses = [row[0] for row in conn.execute("SELECT status FROM agency_audit")]
    finally:
        conn.close()
    assert statuses.count("reserved") == 2 and statuses.count("ok") == 2
    assert statuses.count("budget_exhausted") == 1


async def test_tool_exception_context_is_redacted(trust_store):
    secret = "DO-NOT-LEAK-SECRET"
    module = agency(
        {"fail": ToolSpec(
            "fail", docker_tool(f"echo {secret} >&2; exit 9", trust_store), frozenset({"pure"})
        )},
        Limit(1, frozenset({"fail"})), task_id="redact",
    )
    with pytest.raises(ToolExecutionError) as caught:
        await module.call("fail")
    assert secret not in str(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


async def test_budget_is_tenant_and_policy_scoped():
    store = InMemoryBudgetStore()
    policy_a = "a" * 64
    policy_b = "b" * 64
    assert await store.reserve("tenant-a", "same", "ada", policy_a, 1) == 1
    assert await store.reserve("tenant-a", "same", "ada", policy_a, 1) is None
    assert await store.reserve("tenant-b", "same", "ada", policy_a, 1) == 1
    assert await store.reserve("tenant-a", "same", "ada", policy_b, 1) == 1


async def test_post_effect_audit_failure_is_explicitly_indeterminate(trust_store):
    class FailingFinalAudit(InMemoryAuditSink):
        async def append(self, event):
            if event.status == "ok":
                raise OSError("audit disk failed")
            await super().append(event)

    module = agency(
        {"echo": ToolSpec("echo", docker_tool("printf done", trust_store), frozenset({"pure"}))},
        Limit(1, frozenset({"echo"})), audit=FailingFinalAudit(), task_id="indeterminate",
    )
    with pytest.raises(IndeterminateEffect, match="indeterminate") as caught:
        await module.call("echo")
    assert caught.value.__context__ is None
