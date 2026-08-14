"""Model-agnostic perceive/decide/act loop with strict tool protocol."""

from __future__ import annotations

import asyncio
import json
import math
import os
import signal
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from soul_platform.agency import (
    AgencyModule, CapabilityDenied, IndeterminateEffect, ToolExecutionError,
)


class ProtocolViolation(RuntimeError):
    """The model output did not match the single-object action protocol."""


@dataclass(frozen=True)
class SubprocessLLMProvider:
    """Hard-cancelable model adapter using canonical JSON over stdin/stdout."""

    command: tuple[str, ...]
    max_output_bytes: int = 65_536
    allow_host_execution: bool = False

    def __post_init__(self) -> None:
        if not self.command or any("\x00" in part for part in self.command):
            raise ValueError("provider command must be a static non-empty argv tuple")
        if self.max_output_bytes <= 0:
            raise ValueError("provider max_output_bytes must be positive")
        if not self.allow_host_execution:
            raise ValueError(
                "host subprocess providers are disabled by default; use a contained adapter "
                "or explicitly set allow_host_execution=True"
            )

    async def __call__(self, system: str, transcript: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        )
        assert proc.stdin is not None and proc.stdout is not None
        payload = json.dumps(
            {"system": system, "transcript": transcript},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        try:
            proc.stdin.write(payload)
            try:
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                # A provider may finish without consuming the entire request.
                # Its exit code/output remain the authoritative protocol result.
                pass
            proc.stdin.close()
            output = await proc.stdout.read(self.max_output_bytes + 1)
            if len(output) > self.max_output_bytes:
                await self._kill(proc)
                raise ProtocolViolation("model output exceeded its size limit")
            if await proc.wait() != 0:
                raise ProtocolViolation("model provider process failed")
            return output.decode("utf-8")
        except asyncio.CancelledError:
            await self._kill(proc)
            raise

    @staticmethod
    async def _kill(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()


def parse_action(raw: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        action = json.loads(
            raw.strip(), object_pairs_hook=unique_object, parse_constant=reject_constant
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProtocolViolation("model output must be exactly one JSON object") from exc
    if not isinstance(action, dict) or (set(action) & {"answer", "tool"}) == set():
        raise ProtocolViolation("action must contain exactly one of answer or tool")
    if ("answer" in action) == ("tool" in action):
        raise ProtocolViolation("action cannot contain both answer and tool")
    if "answer" in action:
        if set(action) != {"answer"} or not isinstance(action["answer"], str):
            raise ProtocolViolation("answer action must contain only a string answer")
    else:
        if not set(action) <= {"tool", "args"} or not isinstance(action["tool"], str):
            raise ProtocolViolation("tool action contains unsupported fields or types")
        if not action["tool"]:
            raise ProtocolViolation("tool name cannot be empty")
        if not isinstance(action.get("args", {}), dict):
            raise ProtocolViolation("tool args must be an object")
    return action


@dataclass
class AgentRuntime:
    soul: Any
    agency: AgencyModule
    llm: SubprocessLLMProvider
    tool_specs: dict[str, str]
    max_steps: int = 6
    llm_timeout_seconds: float = 30.0
    max_model_output_bytes: int = 65_536
    turn_recorder: Callable[[dict[str, Any]], Awaitable[None]] | None = None
    allow_uncontained_model: bool = False

    def __post_init__(self) -> None:
        if self.max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if not math.isfinite(self.llm_timeout_seconds) or self.llm_timeout_seconds <= 0:
            raise ValueError("llm_timeout_seconds must be positive")
        if self.max_model_output_bytes <= 0:
            raise ValueError("max_model_output_bytes must be positive")
        if type(self.llm) is not SubprocessLLMProvider:
            raise TypeError("llm must use the built-in hard-cancelable SubprocessLLMProvider")
        if self.llm.allow_host_execution and not self.allow_uncontained_model:
            raise TypeError(
                "uncontained host model is outside the release profile; "
                "use a contained adapter or explicitly acknowledge the experimental boundary"
            )

    async def _call_llm(self, system: str, transcript: str) -> str:
        started = time.monotonic()
        task = asyncio.create_task(self.llm(system, transcript))
        done, _ = await asyncio.wait({task}, timeout=self.llm_timeout_seconds)
        if not done:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            raise ProtocolViolation("model call exceeded its timeout")
        raw = task.result()
        if time.monotonic() - started > self.llm_timeout_seconds:
            raise ProtocolViolation("model call exceeded its timeout")
        if not isinstance(raw, str):
            raise ProtocolViolation("model output must be text")
        if len(raw.encode("utf-8")) > self.max_model_output_bytes:
            raise ProtocolViolation("model output exceeded its size limit")
        return raw

    async def turn(self, user_message: str) -> dict[str, Any]:
        boot = await self.soul.boot()
        hits = await self.soul.memory.search(user_message)
        memory = "\n".join(f"- {hit.memory.content}" for hit in hits[:5]) or "(none)"
        tools = "\n".join(f"- {name}: {desc}" for name, desc in self.tool_specs.items())
        system = (
            f"{boot}\n\nRelevant memory:\n{memory}\n\nTools:\n{tools}\n\n"
            'Return exactly one JSON object: {"tool":"name","args":{}} or '
            '{"answer":"text"}. No markdown or surrounding text.'
        )
        transcript = [f"user: {user_message}"]
        trace: list[dict[str, Any]] = []

        for _ in range(self.max_steps):
            action = parse_action(await self._call_llm(system, "\n".join(transcript)))
            if "answer" in action:
                answer = str(action["answer"])
                if self.turn_recorder is not None:
                    await self.turn_recorder(
                        {"user": user_message, "answer": answer, "tools_used": list(trace)}
                    )
                return {"answer": answer, "tools_used": trace, "protocol": "json"}

            tool = str(action["tool"])
            args = action.get("args", {})
            try:
                result = await self.agency.call(tool, args)
                trace.append({"tool": tool, "status": "ok"})
            except IndeterminateEffect:
                # Retrying could duplicate a real external effect. Reconciliation
                # by idempotency receipt is required before another attempt.
                raise
            except CapabilityDenied as exc:
                result = f"DENIED: {exc}"
                trace.append({"tool": tool, "status": "denied"})
            except ToolExecutionError as exc:
                result = f"ERROR: {exc}"
                trace.append({"tool": tool, "status": "error"})
            transcript.append(f"tool {tool}: {result}")

        raise ProtocolViolation("model exhausted max_steps without a final answer")
