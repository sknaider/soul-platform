from __future__ import annotations

import os
import sys
import time

import pytest

from soul_platform.agency import (
    InMemoryAuditSink, InMemoryBudgetStore, Limit, ToolSpec, load_capability,
)
from soul_platform.runtime import (
    AgentRuntime, ProtocolViolation, SubprocessLLMProvider, parse_action,
)
from soul_platform.sandbox import DockerSandbox, DockerTool, ImageTrustStore, SandboxPolicy


BUSYBOX = "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d"


class Memory:
    def __init__(self): self.stored = []
    async def search(self, _query): return []
    async def store(self, content, importance): self.stored.append((content, importance))


class Soul:
    def __init__(self): self.memory = Memory()
    async def boot(self): return "IDENTITY: ADA"


def module(registry=None, calls=0):
    return load_capability(
        registry or {}, Limit(calls, frozenset((registry or {}).keys())),
        tenant="team", task_id="task", actor="ada",
        budget_store=InMemoryBudgetStore(), audit_sink=InMemoryAuditSink(),
    )


def provider(code: str, *, max_output_bytes: int = 65_536):
    return SubprocessLLMProvider(
        (sys.executable, "-c", code), max_output_bytes=max_output_bytes
    )


def test_protocol_is_exact_not_regex_salvaged():
    assert parse_action('{"answer":"ok"}') == {"answer": "ok"}
    for invalid in (
        'prefix {"answer":"unsafe salvage"}', '{"answer":"x","tool":"echo"}',
        '{"answer":"x","override":true}', '{"answer":42}',
        '{"tool":"echo","args":{},"override":true}',
        '{"answer":"safe","answer":"evil"}',
        '{"tool":"echo","args":{"value":NaN}}',
    ):
        with pytest.raises(ProtocolViolation): parse_action(invalid)


async def test_runtime_calls_contained_tool_then_learns_complete_turn(tmp_path):
    llm = provider(
        "import json,sys; d=json.load(sys.stdin); "
        "print('{\"answer\":\"listo\"}' if 'tool echo:' in d['transcript'] "
        "else '{\"tool\":\"echo\",\"args\":{\"text\":\"hola\"}}')"
    )
    trust_file = tmp_path / "trusted-images.txt"
    trust_file.write_text(BUSYBOX + "\n")
    trust_file.chmod(0o600)
    sandbox = DockerSandbox(SandboxPolicy(BUSYBOX, ImageTrustStore.from_file(str(trust_file))))
    tool = ToolSpec(
        "echo", DockerTool(sandbox, ("sh", "-c", 'printf "%s" "$1"', "tool")),
        frozenset({"pure"}),
    )
    soul = Soul()
    runtime = AgentRuntime(soul, module({"echo": tool}, 1), llm, {"echo": "echo"})
    result = await runtime.turn("saluda")
    assert result["answer"] == "listo"
    assert result["tools_used"] == [{"tool": "echo", "status": "ok"}]
    assert "answer='listo'" in soul.memory.stored[0][0]


async def test_runtime_rejects_uncontained_provider_and_non_protocol_output():
    async def uncontained(_s, _u): return "plain text"
    with pytest.raises(TypeError, match="SubprocessLLMProvider"):
        AgentRuntime(Soul(), module(), uncontained, {})  # type: ignore[arg-type]
    with pytest.raises(ProtocolViolation):
        await AgentRuntime(
            Soul(), module(), provider("print('plain text')"), {}
        ).turn("hello")


async def test_runtime_timeout_kills_and_reaps_provider_process(tmp_path):
    pid_file = tmp_path / "provider.pid"
    slow = provider(
        f"import os,time; open({str(pid_file)!r},'w').write(str(os.getpid())); time.sleep(10)"
    )
    runtime = AgentRuntime(Soul(), module(), slow, {}, llm_timeout_seconds=0.1)
    started = time.monotonic()
    with pytest.raises(ProtocolViolation, match="timeout"):
        await runtime.turn("hello")
    assert time.monotonic() - started < 0.5
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_runtime_bounds_model_output_and_provider_failure():
    with pytest.raises(ProtocolViolation, match="size"):
        await AgentRuntime(
            Soul(), module(), provider("print('x'*100)", max_output_bytes=8), {},
            max_model_output_bytes=8,
        ).turn("hello")
    with pytest.raises(ProtocolViolation, match="failed"):
        await AgentRuntime(
            Soul(), module(), provider("raise SystemExit(3)"), {}
        ).turn("hello")
