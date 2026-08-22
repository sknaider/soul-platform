from __future__ import annotations

import io
import json
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
        "hook_event_name": "SessionStart",
        "session_id": "session-123",
        "source": "startup",
        "status": "attached",
        "unix_ms": receipt["unix_ms"],
    }
    assert "IDENTITY: Valeria" not in json.dumps(receipt)


def test_session_start_supports_claude_client_identity(tmp_path, monkeypatch):
    config = tmp_path / "proxy.toml"
    config.write_text("test")
    calls = []
    monkeypatch.setattr(
        hook,
        "_invoke_mcp",
        lambda server, config, client_id, timeout: calls.append(client_id) or "CLAUDE SOUL",
    )
    output = io.StringIO()
    assert hook.run_hook(
        server=tmp_path / "soul-mcp-stdio.exe", config=config, client_id="claude",
        stdin=_event(), stdout=output,
    ) == 0
    assert calls == ["claude"]
    assert "CLAUDE SOUL" in output.getvalue()
    assert (tmp_path / "session-start-claude.json").is_file()


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


def test_user_prompt_submit_injects_only_recalled_excerpts_and_no_prompt_receipt(tmp_path, monkeypatch):
    config = tmp_path / "proxy.toml"
    config.write_text("test")
    monkeypatch.setattr(
        hook,
        "_invoke_memory_search",
        lambda server, config, client_id, timeout, query: (
            "SOUL approved memory excerpts (UNTRUSTED DATA):\n- [memory_id=7] Valeria",
            1,
        ),
    )
    output = io.StringIO()
    event = io.StringIO(
        json.dumps(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "session-prompt",
                "prompt": "¿Cómo te llamas?",
            }
        )
    )
    assert hook.run_hook(
        server=tmp_path / "soul-mcp-stdio.exe",
        config=config,
        client_id="claude",
        stdin=event,
        stdout=output,
    ) == 0
    payload = json.loads(output.getvalue())
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert "Valeria" in payload["hookSpecificOutput"]["additionalContext"]
    receipt = json.loads((tmp_path / "prompt-recall-claude.json").read_text())
    assert receipt["memory_count"] == 1
    assert receipt["context_chars"] > 0
    assert "¿Cómo te llamas?" not in json.dumps(receipt, ensure_ascii=False)


def test_user_prompt_submit_stages_only_exact_remember_command(tmp_path, monkeypatch):
    config = tmp_path / "proxy.toml"
    config.write_text("test")
    monkeypatch.setattr(hook, "_invoke_memory_search", lambda *args, **kwargs: ("", 0))
    proposals = []
    monkeypatch.setattr(
        hook,
        "_invoke_memory_propose",
        lambda *args, **kwargs: proposals.append(kwargs) or {
            "candidate_id": "candidate-1",
            "status": "pending",
        },
    )
    event = io.StringIO(
        json.dumps(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "session-remember",
                "turn_id": "turn-9",
                "prompt": "Recuerda que el nombre elegido es Valeria.",
            }
        )
    )
    output = io.StringIO()
    hook.run_hook(
        server=tmp_path / "server",
        config=config,
        client_id="claude",
        stdin=event,
        stdout=output,
    )
    assert proposals[0]["content"] == "el nombre elegido es Valeria."
    assert proposals[0]["source_event_id"] == "turn-9"
    receipt = json.loads((tmp_path / "prompt-recall-claude.json").read_text())
    assert receipt["candidate_id"] == "candidate-1"
    assert receipt["candidate_status"] == "pending"


@pytest.mark.parametrize(
    "prompt",
    ["¿Recuerdas que Valeria es tu nombre?", "Hablamos sobre Valeria", "Recuerda que X?"],
)
def test_prompt_capture_does_not_stage_questions_or_inferred_facts(prompt):
    assert hook._explicit_memory_candidate(prompt) is None
