from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from soul_platform import codex_session_start as hook


def _event() -> io.StringIO:
    return io.StringIO(
        json.dumps(
            {
                "hook_event_name": "SessionStart",
                "session_id": "session-123",
                "source": "startup",
            }
        )
    )


def test_protocol_requests_boot_context_directly():
    messages = [json.loads(line) for line in hook._requests().splitlines()]
    assert [message["method"] for message in messages] == [
        "initialize",
        "notifications/initialized",
        "tools/call",
    ]
    assert messages[-1]["params"] == {"name": "soul_boot_context", "arguments": {}}


def test_extract_boot_context_rejects_missing_or_empty_response():
    with pytest.raises(RuntimeError, match="no boot response"):
        hook._extract_boot_context('{"jsonrpc":"2.0","id":1,"result":{}}\n')
    with pytest.raises(RuntimeError, match="empty"):
        hook._extract_boot_context(
            '{"jsonrpc":"2.0","id":2,"result":{"content":[]}}\n'
        )

def test_session_start_injects_context_and_writes_safe_receipt(tmp_path, monkeypatch):
    config = tmp_path / "proxy.toml"
    config.write_text("test")
    monkeypatch.setattr(hook, "_invoke_mcp", lambda *args, **kwargs: "IDENTITY: Valeria")
    output = io.StringIO()
    assert hook.run_hook(
        server=tmp_path / "soul-mcp-stdio.exe",
        config=config,
        client_id="codex",
        stdin=_event(),
        stdout=output,
    ) == 0
    payload = json.loads(output.getvalue())
    context = payload["hookSpecificOutput"]["additionalContext"]
    assert "AUTO-ATTACHED" in context
    assert "IDENTITY: Valeria" in context
    receipt = json.loads((tmp_path / "session-start-codex.json").read_text())
    assert receipt == {
        "client_id": "codex",
        "context_chars": 17,
        "session_id": "session-123",
        "source": "startup",
        "status": "attached",
        "unix_ms": receipt["unix_ms"],
    }
    assert "IDENTITY: Valeria" not in json.dumps(receipt)


def test_session_start_fails_loud_without_triggering_model_search(tmp_path, monkeypatch):
    config = tmp_path / "proxy.toml"
    config.write_text("test")

    def fail(*args, **kwargs):
        raise RuntimeError("parent mismatch")

    monkeypatch.setattr(hook, "_invoke_mcp", fail)
    output = io.StringIO()
    assert hook.run_hook(
        server=tmp_path / "soul-mcp-stdio.exe",
        config=config,
        client_id="codex",
        stdin=_event(),
        stdout=output,
    ) == 0
    payload = json.loads(output.getvalue())
    assert payload["continue"] is True
    assert "unavailable" in payload["systemMessage"]
    assert "Do not search" in payload["hookSpecificOutput"]["additionalContext"]
    receipt = json.loads((tmp_path / "session-start-codex.json").read_text())
    assert receipt["status"] == "error"
    assert receipt["error_type"] == "RuntimeError"


def test_session_start_rejects_wrong_hook_event(tmp_path):
    with pytest.raises(RuntimeError, match="unexpected event"):
        hook.run_hook(
            server=tmp_path / "server",
            config=tmp_path / "proxy.toml",
            client_id="codex",
            stdin=io.StringIO('{"hook_event_name":"Stop"}'),
            stdout=io.StringIO(),
        )
