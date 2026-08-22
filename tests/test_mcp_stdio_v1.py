from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from soul_platform.bootstrap import initialize
from soul_platform.mcp_stdio import (
    MCPStdioServer,
    ProcessIdentity,
    _current_server_executable,
    _select_windows_client_ancestor,
    enroll_client,
    ensure_client_grants,
    sync_claude_app_grants,
    sync_claude_desktop_mcp_config,
    sync_claude_session_start_hook,
    sync_codex_app_grants,
    verify_client_grant,
)
from soul_platform.proxy import ProxySettings


async def test_mcp_handshake_lists_scoped_tools_and_calls_runner():
    calls = []

    async def runner(name, arguments):
        calls.append((name, arguments))
        return {"content": [{"type": "text", "text": "ok"}]}

    server = MCPStdioServer(
        runner, scopes={"boot.public", "memory.search.private", "memory.propose"}
    )
    initialized = await server.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    listing = await server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    called = await server.handle(
        {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "soul_memory_search", "arguments": {"query": "Valeria"}},
        }
    )
    assert initialized["result"]["serverInfo"]["name"] == "soul-local"
    tools = {item["name"]: item for item in listing["result"]["tools"]}
    assert set(tools) == {"soul_boot_context", "soul_memory_search", "soul_memory_propose"}
    assert tools["soul_memory_propose"]["annotations"]["readOnlyHint"] is False
    assert called["result"]["content"][0]["text"] == "ok"
    assert calls == [("soul_memory_search", {"query": "Valeria"})]


async def test_mcp_rejects_unknown_method_and_invalid_request():
    async def runner(_name, _arguments):
        raise AssertionError("runner should not be called")

    server = MCPStdioServer(runner, scopes=set())
    missing = await server.handle({"jsonrpc": "2.0", "id": 9, "method": "unknown"})
    assert missing["error"]["code"] == -32601
    with pytest.raises(ValueError, match="JSON-RPC"):
        await server.handle({"id": 1, "method": "ping"})


async def test_mcp_tools_require_fresh_initialize_session():
    async def runner(_name, _arguments):
        return {}

    server = MCPStdioServer(runner, scopes={"boot.public"})
    with pytest.raises(ValueError, match="session"):
        await server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    initialized = await server.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
    )
    assert initialized["result"]["_meta"]["soulAttachSession"]
    listing = await server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert [tool["name"] for tool in listing["result"]["tools"]] == ["soul_boot_context"]


async def test_mcp_revalidates_private_scope_after_async_tool_interleaving():
    live_scopes = {"memory.search.private"}

    async def runner(_name, _arguments):
        # Models the exact consent-snapshot race: authorization succeeded, a
        # private write invalidated it, then the runner produced new bytes.
        live_scopes.clear()
        return {"content": [{"type": "text", "text": "CANARIO NUEVO"}]}

    server = MCPStdioServer(
        runner,
        scopes=set(),
        scope_resolver=lambda: frozenset(live_scopes),
    )
    await server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    with pytest.raises(PermissionError, match="changed during call"):
        await server.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "soul_memory_search",
                    "arguments": {"query": "canario"},
                },
            }
        )


async def test_boot_only_scope_hides_and_denies_memory_tools():
    calls = []

    async def runner(name, arguments):
        calls.append((name, arguments))
        return {}

    server = MCPStdioServer(runner, scopes={"boot.public"})
    await server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    listing = await server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert [tool["name"] for tool in listing["result"]["tools"]] == ["soul_boot_context"]
    with pytest.raises(PermissionError, match="scope denied"):
        await server.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "soul_memory_search", "arguments": {"query": "x"}},
            }
        )
    assert calls == []


def test_client_grant_is_machine_bound_and_fail_closed(tmp_path):
    result = initialize(
        root=tmp_path / "soul", upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1", upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    grant = ensure_client_grants(settings)
    parent = tmp_path / "codex.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    parent.write_bytes(b"approved-codex")
    server.write_bytes(b"approved-mcp")
    enroll_client(
        settings,
        "codex",
        parent_executable=parent,
        server_executable=server,
        config_path=result.config,
    )
    identity = ProcessIdentity(
        executable=str(parent.resolve()),
        executable_sha256=hashlib.sha256(parent.read_bytes()).hexdigest(),
        owner=f"uid:{__import__('os').getuid()}",
    )
    verify_client_grant(
        settings,
        "codex",
        config_path=result.config,
        server_executable=server,
        process_identity=identity,
    )
    # Exact re-enrollment is idempotent, but a different executable cannot
    # seize the existing client id.
    enroll_client(
        settings,
        "codex",
        parent_executable=parent,
        server_executable=server,
        config_path=result.config,
    )
    evil = tmp_path / "evil.exe"
    evil.write_bytes(b"same-user-impostor")
    with pytest.raises(ValueError, match="immutable binding"):
        enroll_client(
            settings,
            "codex",
            parent_executable=evil,
            server_executable=server,
            config_path=result.config,
        )
    with pytest.raises(ValueError, match="parent"):
        verify_client_grant(
            settings,
            "codex",
            config_path=result.config,
            server_executable=server,
            process_identity=ProcessIdentity(
                executable=str(tmp_path / "fake.exe"),
                executable_sha256="0" * 64,
                owner=identity.owner,
            ),
        )
    with pytest.raises(ValueError, match="not granted"):
        verify_client_grant(
            settings,
            "claude",
            config_path=result.config,
            server_executable=server,
            process_identity=identity,
        )
    raw = json.loads(grant.read_text())
    raw["machine_soul_id"] = "other"
    grant.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="differs"):
        verify_client_grant(
            settings,
            "codex",
            config_path=result.config,
            server_executable=server,
            process_identity=identity,
        )
    with pytest.raises(ValueError, match="unsupported"):
        verify_client_grant(settings, "unknown")


def test_codex_cli_and_app_have_distinct_exact_parent_bindings(tmp_path):
    result = initialize(
        root=tmp_path / "soul", upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1", upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    cli = tmp_path / "npm" / "codex.exe"
    app = tmp_path / "app" / "codex.exe"
    cached = tmp_path / "cache" / "codex.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    for path, content in (
        (cli, b"codex-cli"), (app, b"codex-app"),
        (cached, b"codex-app"), (server, b"mcp-v1"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    enroll_client(
        settings, "codex", parent_executable=cli,
        server_executable=server, config_path=result.config,
    )
    assert sync_codex_app_grants(
        settings, config_path=result.config, server_executable=server,
        parents=[app, cached],
    ) == 2
    assert sync_codex_app_grants(
        settings, config_path=result.config, server_executable=server,
        parents=[app, cached],
    ) == 0
    entry = json.loads((result.root / "client-grants.json").read_text())["clients"]["codex"]
    assert len(entry["parent_bindings"]) == 3
    owner = f"uid:{__import__('os').getuid()}"
    for parent in (cli, app, cached):
        verify_client_grant(
            settings, "codex", config_path=result.config,
            server_executable=server,
            process_identity=ProcessIdentity(
                executable=str(parent.resolve()),
                executable_sha256=hashlib.sha256(parent.read_bytes()).hexdigest(),
                owner=owner,
            ),
        )
    impostor = tmp_path / "impostor" / "codex.exe"
    impostor.parent.mkdir()
    impostor.write_bytes(app.read_bytes())
    with pytest.raises(ValueError, match="parent executable"):
        verify_client_grant(
            settings, "codex", config_path=result.config,
            server_executable=server,
            process_identity=ProcessIdentity(
                executable=str(impostor.resolve()),
                executable_sha256=hashlib.sha256(impostor.read_bytes()).hexdigest(),
                owner=owner,
            ),
        )
    server.write_bytes(b"mcp-v2")
    assert sync_codex_app_grants(
        settings, config_path=result.config, server_executable=server,
        parents=[app, cached],
    ) == 0
    rotated = json.loads((result.root / "client-grants.json").read_text())["clients"]["codex"]
    assert len(rotated["parent_bindings"]) == 3
    assert rotated["server_sha256"] == hashlib.sha256(b"mcp-v2").hexdigest()


def test_claude_cli_desktop_and_runtime_have_exact_parent_bindings(tmp_path):
    result = initialize(
        root=tmp_path / "soul", upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1", upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    cli = tmp_path / "npm" / "claude.exe"
    desktop = tmp_path / "WindowsApps" / "Claude.exe"
    runtime = tmp_path / "Roaming" / "Claude" / "claude-code" / "2.1.219" / "claude.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    for path, content in (
        (cli, b"claude-cli"), (desktop, b"claude-desktop"),
        (runtime, b"claude-runtime"), (server, b"mcp-v1"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    enroll_client(
        settings, "claude", parent_executable=cli,
        server_executable=server, config_path=result.config,
    )
    assert sync_claude_app_grants(
        settings, config_path=result.config, server_executable=server,
        parents=[desktop, runtime],
    ) == 2
    assert sync_claude_app_grants(
        settings, config_path=result.config, server_executable=server,
        parents=[desktop, runtime],
    ) == 0
    entry = json.loads((result.root / "client-grants.json").read_text())["clients"]["claude"]
    assert len(entry["parent_bindings"]) == 3
    owner = f"uid:{__import__('os').getuid()}"
    for parent in (cli, desktop, runtime):
        verify_client_grant(
            settings, "claude", config_path=result.config,
            server_executable=server,
            process_identity=ProcessIdentity(
                executable=str(parent.resolve()),
                executable_sha256=hashlib.sha256(parent.read_bytes()).hexdigest(),
                owner=owner,
            ),
        )
    runtime.write_bytes(b"tampered-runtime")
    with pytest.raises(ValueError, match="parent hash"):
        verify_client_grant(
            settings, "claude", config_path=result.config,
            server_executable=server,
            process_identity=ProcessIdentity(
                executable=str(runtime.resolve()),
                executable_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
                owner=owner,
            ),
        )


def test_claude_desktop_config_preserves_other_servers_and_is_idempotent(tmp_path):
    config = tmp_path / "SOUL" / "proxy.toml"
    server = tmp_path / "SOUL" / "soul-mcp-stdio.exe"
    desktop = tmp_path / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("machine_soul_id = 'test'\n")
    server.write_bytes(b"mcp")
    desktop.parent.mkdir()
    desktop.write_text(json.dumps({"mcpServers": {"github": {"command": "github-mcp"}}}))
    assert sync_claude_desktop_mcp_config(
        config_path=config,
        server_executable=server,
        desktop_config_path=desktop,
    )
    payload = json.loads(desktop.read_text())
    assert payload["mcpServers"]["github"] == {"command": "github-mcp"}
    assert payload["mcpServers"]["soul-local"] == {
        "command": str(server.resolve()),
        "args": ["--config", str(config.resolve()), "--client-id", "claude"],
    }
    assert not sync_claude_desktop_mcp_config(
        config_path=config,
        server_executable=server,
        desktop_config_path=desktop,
    )


def test_claude_desktop_config_rejects_invalid_shape_without_overwrite(tmp_path):
    config = tmp_path / "proxy.toml"
    server = tmp_path / "soul-mcp-stdio.exe"
    desktop = tmp_path / "claude_desktop_config.json"
    config.write_text("ok")
    server.write_bytes(b"mcp")
    desktop.write_text('{"mcpServers": []}')
    before = desktop.read_bytes()
    with pytest.raises(ValueError, match="mcpServers"):
        sync_claude_desktop_mcp_config(
            config_path=config,
            server_executable=server,
            desktop_config_path=desktop,
        )
    assert desktop.read_bytes() == before


def test_claude_session_start_hook_preserves_existing_and_is_idempotent(tmp_path):
    config = tmp_path / "SOUL" / "proxy.toml"
    server = tmp_path / "SOUL" / "soul-mcp-stdio.exe"
    hook = tmp_path / "SOUL" / "soul-codex-session-start.exe"
    settings = tmp_path / ".claude" / "settings.json"
    config.parent.mkdir(parents=True)
    config.write_text("ok")
    server.write_bytes(b"mcp")
    hook.write_bytes(b"hook")
    settings.parent.mkdir()
    existing = {"matcher": "", "hooks": [{"type": "http", "url": "http://127.0.0.1/hook"}]}
    settings.write_text(json.dumps({"hooks": {"SessionStart": [existing]}}))
    assert sync_claude_session_start_hook(
        config_path=config, server_executable=server, hook_executable=hook,
        settings_path=settings,
    )
    payload = json.loads(settings.read_text())
    groups = payload["hooks"]["SessionStart"]
    assert groups[0] == existing
    owned = [
        handler for group in groups for handler in group["hooks"]
        if handler.get("type") == "command" and "--client-id claude" in handler.get("command", "")
    ]
    assert len(owned) == 1
    assert str(hook.resolve()) in owned[0]["command"]
    assert groups[-1]["matcher"].endswith("|fork)$")
    assert not sync_claude_session_start_hook(
        config_path=config, server_executable=server, hook_executable=hook,
        settings_path=settings,
    )


def test_compact_v2_parent_binding_is_normalized_during_rotation(tmp_path):
    result = initialize(
        root=tmp_path / "soul", upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1", upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    parent = tmp_path / "codex.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    parent.write_bytes(b"codex")
    server.write_bytes(b"mcp")
    entry = enroll_client(
        settings, "codex", parent_executable=parent,
        server_executable=server, config_path=result.config,
    )
    grants = result.root / "client-grants.json"
    raw = json.loads(grants.read_text())
    raw["clients"]["codex"]["parent_bindings"] = [{
        "executable": entry["parent_executable"],
        "sha256": entry["parent_sha256"],
    }]
    grants.write_text(json.dumps(raw))
    server.write_bytes(b"mcp-rotated")
    rotated = enroll_client(
        settings, "codex", parent_executable=parent,
        server_executable=server, config_path=result.config, rotate_existing=True,
    )
    binding = rotated["parent_bindings"][0]
    assert binding["owner"] == entry["owner"]
    assert binding["enrolled_unix_ms"] >= entry["enrolled_unix_ms"]


def test_windows_console_launcher_resolves_hidden_exe_suffix(tmp_path, monkeypatch):
    launcher = tmp_path / "soul-mcp-stdio.exe"
    launcher.write_bytes(b"launcher")
    monkeypatch.setattr("sys.argv", [str(tmp_path / "soul-mcp-stdio")])
    assert _current_server_executable() == launcher.resolve()


def test_windows_distlib_chain_resolves_real_client_and_rejects_only_intermediates():
    server = Path(r"C:\Users\Dadito\AppData\Local\SOUL\venv\Scripts\soul-mcp-stdio.exe")
    base_python = Path(r"C:\Users\Dadito\AppData\Local\Programs\Python\Python313\python.exe")
    chain = [
        {"path": str(base_python)},
        {"path": r"C:\Users\Dadito\AppData\Local\SOUL\venv\Scripts\soul-codex-session-start.exe"},
        {"path": r"C:\Users\Dadito\AppData\Local\SOUL\venv\Scripts\python.exe"},
        {"path": str(server)},
        {"path": r"C:\Windows\System32\cmd.exe"},
        {"path": r"C:\Users\Dadito\AppData\Roaming\npm\claude.exe", "sid": "owner"},
    ]
    assert _select_windows_client_ancestor(chain, server, base_python) == chain[-1]
    with pytest.raises(ValueError, match="launcher chain"):
        _select_windows_client_ancestor(chain[:5], server, base_python)


def test_windows_claude_hook_skips_exact_git_bash_but_not_lookalike(monkeypatch):
    monkeypatch.setenv("ProgramFiles", r"C:\Users\Dadito\Downloads")
    monkeypatch.setenv("ProgramFiles(x86)", r"C:\Users\Dadito\Downloads")
    monkeypatch.setenv("SystemRoot", r"C:\Users\Dadito\Downloads\FakeWindows")
    server = Path(r"C:\Users\Dadito\AppData\Local\SOUL\venv\Scripts\soul-mcp-stdio.exe")
    base_python = Path(r"C:\Users\Dadito\AppData\Local\Programs\Python\Python313\python.exe")
    claude = {
        "path": r"C:\Users\Dadito\AppData\Roaming\Claude\claude-code\2.1.219\claude.exe",
        "sid": "owner",
    }
    trusted_chain = [
        {"path": str(base_python)},
        {"path": r"C:\Users\Dadito\AppData\Local\SOUL\venv\Scripts\soul-codex-session-start.exe"},
        {"path": str(server)},
        {"path": r"C:\Program Files\Git\usr\bin\bash.exe"},
        claude,
    ]
    assert _select_windows_client_ancestor(trusted_chain, server, base_python) == claude

    lookalike = {"path": r"C:\Users\Dadito\Downloads\bash.exe", "sid": "owner"}
    untrusted_chain = trusted_chain[:3] + [lookalike, claude]
    assert _select_windows_client_ancestor(untrusted_chain, server, base_python) == lookalike

    user_writable_git = {
        "path": r"C:\Users\Dadito\AppData\Local\Programs\Git\usr\bin\bash.exe",
        "sid": "owner",
    }
    user_writable_chain = trusted_chain[:3] + [user_writable_git, claude]
    assert (
        _select_windows_client_ancestor(user_writable_chain, server, base_python)
        == user_writable_git
    )

    fake_cmd = {
        "path": r"C:\Users\Dadito\Downloads\FakeWindows\System32\cmd.exe",
        "sid": "owner",
    }
    fake_cmd_chain = trusted_chain[:3] + [fake_cmd, claude]
    assert _select_windows_client_ancestor(fake_cmd_chain, server, base_python) == fake_cmd


def test_explicit_rotation_updates_hashes_only_for_same_binding(tmp_path):
    result = initialize(
        root=tmp_path / "soul", upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1", upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    parent = tmp_path / "codex.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    parent.write_bytes(b"codex-v1")
    server.write_bytes(b"mcp-v1")
    original = enroll_client(
        settings, "codex", parent_executable=parent,
        server_executable=server, config_path=result.config,
    )

    server.write_bytes(b"mcp-v2")
    with pytest.raises(ValueError, match="immutable binding"):
        enroll_client(
            settings, "codex", parent_executable=parent,
            server_executable=server, config_path=result.config,
        )
    rotated = enroll_client(
        settings, "codex", parent_executable=parent,
        server_executable=server, config_path=result.config,
        rotate_existing=True,
    )
    assert rotated["server_sha256"] == hashlib.sha256(b"mcp-v2").hexdigest()
    assert rotated["previous_server_sha256"] == original["server_sha256"]

    other = tmp_path / "other.exe"
    other.write_bytes(parent.read_bytes())
    with pytest.raises(ValueError, match="immutable binding"):
        enroll_client(
            settings, "codex", parent_executable=other,
            server_executable=server, config_path=result.config,
            rotate_existing=True,
        )


@pytest.mark.parametrize(
    "old_scopes",
    [
        ["boot", "memory.search", "memory.store"],
        ["boot.public", "boot.private", "memory.search.private", "memory.propose"],
    ],
)
def test_owner_controlled_reinstall_upgrades_exact_prior_scope_sets(tmp_path, old_scopes):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    parent = tmp_path / "claude.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    parent.write_bytes(b"claude")
    server.write_bytes(b"mcp")
    enroll_client(
        settings,
        "claude",
        parent_executable=parent,
        server_executable=server,
        config_path=result.config,
    )
    grants = result.root / "client-grants.json"
    payload = json.loads(grants.read_text())
    payload["clients"]["claude"]["scopes"] = old_scopes
    before = (json.dumps(payload) + "\n").encode()
    grants.write_bytes(before)

    rotated = enroll_client(
        settings,
        "claude",
        parent_executable=parent,
        server_executable=server,
        config_path=result.config,
        rotate_existing=True,
    )
    assert rotated["scopes"] == [
        "boot.public",
        "boot.private",
        "memory.search.private",
        "memory.propose",
        "profile.propose",
    ]
    live = json.loads(grants.read_text())["clients"]["claude"]
    assert live["scopes"] == rotated["scopes"]
    assert "memory.store" not in live["scopes"]
    assert live["previous_scopes"] == old_scopes
    backups = list(grants.parent.glob("client-grants.json.scopes.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == before


def test_explicit_enrollment_migrates_legacy_grants_with_exact_backup(tmp_path):
    result = initialize(
        root=tmp_path / "soul", upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1", upstream_model="brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)
    grant = settings.soul_db.parent / "client-grants.json"
    legacy = (
        json.dumps(
            {
                "schema": "soul.client-grants.v1",
                "machine_soul_id": settings.machine_soul_id,
                "clients": {"codex": {"enabled": True}, "claude": {"enabled": True}},
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()
    grant.write_bytes(legacy)
    parent = tmp_path / "node.exe"
    server = tmp_path / "soul-mcp-stdio.exe"
    parent.write_bytes(b"approved-node")
    server.write_bytes(b"approved-mcp")

    with pytest.raises(ValueError, match="differs"):
        ensure_client_grants(settings)
    enroll_client(
        settings,
        "codex",
        parent_executable=parent,
        server_executable=server,
        config_path=result.config,
    )

    migrated = json.loads(grant.read_text())
    assert migrated["schema"] == "soul.client-grants.v2"
    assert set(migrated["clients"]) == {"codex"}
    backups = list(grant.parent.glob("client-grants.json.v1.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == legacy
