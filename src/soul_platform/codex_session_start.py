"""Codex SessionStart hook that eagerly attaches the local MachineSoul.

The hook does not read the SOUL database directly.  It drives the enrolled
``soul-mcp-stdio`` child over MCP so the same executable/hash/session checks
used by normal tool calls remain authoritative.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, TextIO


PROTOCOL_VERSION = "2025-06-18"
MAX_BOOT_CONTEXT_CHARS = 16_000


def _requests() -> str:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "soul-codex-session-start", "version": "0.5.6"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "soul_boot_context", "arguments": {}},
        },
    ]
    return "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in messages)


def _extract_boot_context(stdout: str) -> str:
    responses: dict[int, dict[str, Any]] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict) and isinstance(payload.get("id"), int):
            responses[payload["id"]] = payload
    response = responses.get(2)
    if response is None:
        raise RuntimeError("SOUL MCP returned no boot response")
    if isinstance(response.get("error"), dict):
        raise RuntimeError("SOUL MCP rejected the boot request")
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("SOUL MCP returned an invalid boot result")
    content = result.get("content")
    if not isinstance(content, list):
        raise RuntimeError("SOUL MCP boot content is missing")
    text = "\n".join(
        item["text"]
        for item in content
        if isinstance(item, dict)
        and item.get("type") == "text"
        and isinstance(item.get("text"), str)
    ).strip()
    if not text:
        raise RuntimeError("SOUL MCP boot context is empty")
    if len(text) > MAX_BOOT_CONTEXT_CHARS:
        raise RuntimeError("SOUL MCP boot context exceeds the safe hook limit")
    return text


def _invoke_mcp(server: Path, config: Path, client_id: str, timeout: float) -> str:
    command = [
        str(server),
        "--config",
        str(config),
        "--client-id",
        client_id,
    ]
    completed = subprocess.run(
        command,
        input=_requests(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        stderr_lines = [line.strip() for line in completed.stderr.splitlines() if line.strip()]
        detail = stderr_lines[-1][-500:] if stderr_lines else "no stderr"
        raise RuntimeError(f"SOUL MCP startup failed: {detail}")
    return _extract_boot_context(completed.stdout)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _hook_output(context: str) -> dict[str, Any]:
    return {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": (
                "SOUL LOCAL AUTO-ATTACHED before the first model response. "
                "Do not search for soul_boot_context or run alternate Codex clients; "
                "the persistent MachineSoul context is already loaded below.\n\n"
                + context
            ),
        },
    }


def run_hook(
    *,
    server: Path,
    config: Path,
    client_id: str,
    stdin: TextIO,
    stdout: TextIO,
    timeout: float = 20.0,
) -> int:
    event = json.load(stdin)
    if not isinstance(event, dict) or event.get("hook_event_name") != "SessionStart":
        raise RuntimeError("SOUL hook received an unexpected event")
    status = config.parent / f"session-start-{client_id}.json"
    try:
        context = _invoke_mcp(server, config, client_id, timeout)
        output = _hook_output(context)
        _atomic_json(
            status,
            {
                "client_id": client_id,
                "context_chars": len(context),
                "session_id": str(event.get("session_id") or ""),
                "source": str(event.get("source") or ""),
                "status": "attached",
                "unix_ms": int(time.time() * 1000),
            },
        )
    except Exception as exc:
        _atomic_json(
            status,
            {
                "client_id": client_id,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "session_id": str(event.get("session_id") or ""),
                "source": str(event.get("source") or ""),
                "status": "error",
                "unix_ms": int(time.time() * 1000),
            },
        )
        output = {
            "continue": True,
            "systemMessage": "SOUL local auto-attach failed; persistent context is unavailable.",
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    "SOUL local auto-attach failed. Do not search the filesystem, invoke "
                    "alternate Codex installations, or claim that memory is connected."
                ),
            },
        }
    json.dump(output, stdout, ensure_ascii=False, separators=(",", ":"))
    stdout.write("\n")
    stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-codex-session-start")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--server-executable", type=Path, required=True)
    parser.add_argument("--client-id", choices=("codex",), default="codex")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args(argv)
    return run_hook(
        server=args.server_executable.expanduser().resolve(),
        config=args.config.expanduser().resolve(),
        client_id=args.client_id,
        stdin=sys.stdin,
        stdout=sys.stdout,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
