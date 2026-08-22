from __future__ import annotations

import io
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from soul_platform.autowire.discovery import (
    discover_all,
    discover_ollama,
    discover_openai_loopback,
)
from soul_platform.autowire.manager import ActivationDenied, AutoWireManager
from soul_platform.autowire.probe import ProbeError, get_json, strict_json
from soul_platform.autowire.registry import ProviderRegistry, RegistryConflict
from soul_platform.autowire.service import (
    _windows_register_script,
    install_autowire_autostart,
)
from soul_platform.autowire.types import ProviderCandidate, ProviderState
from soul_platform.bootstrap import initialize, upgrade_config
from soul_platform.proxy import ProxySettings


@pytest.fixture(autouse=True)
def _trusted_runtime_stub(monkeypatch):
    monkeypatch.setattr(
        "soul_platform.autowire.manager.verify_runtime_attestation", lambda _settings: True
    )


class Response(io.BytesIO):
    def __init__(self, payload: object, status: int = 200):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        super().__init__(raw)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _initialized(tmp_path: Path):
    return initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="qwen:4b",
        enable_autostart=False,
    )


def _candidate(model: str = "qwen:4b", *, source: str = "ollama") -> ProviderCandidate:
    port = 11434 if source == "ollama" else 1234
    return ProviderCandidate(
        source=source,
        kind=source,
        protocol="openai-chat",
        origin=f"http://127.0.0.1:{port}",
        base_url=f"http://127.0.0.1:{port}/v1",
        model=model,
        attestation=(
            "ollama-native-loopback-v1"
            if source == "ollama"
            else "unattested-openai-loopback-v1"
        ),
    )


def test_strict_json_and_http_probe_are_bounded_no_proxy_no_redirect(monkeypatch):
    with pytest.raises(ValueError, match="duplicate"):
        strict_json(b'{"a":1,"a":2}')
    with pytest.raises(ProbeError, match="literal loopback"):
        get_json("https://example.com/models", opener=lambda *_a, **_k: None)
    with pytest.raises(ProbeError, match="1 MiB"):
        get_json(
            "http://127.0.0.1:1234/v1/models",
            opener=lambda *_a, **_k: Response(b"x" * (1_048_576 + 1)),
        )


def test_discovery_attests_only_native_ollama_and_preserves_cjk():
    def fetch(url: str):
        if url.endswith("/api/version"):
            return {"version": "0.11.4"}
        if url.endswith("/api/tags"):
            return {
                "models": [
                    {"name": "千问:4b", "details": {"family": "qwen"}},
                    {"name": "bge-m3:latest", "details": {"family": "bert"}},
                    {"name": "bad\nmodel"},
                ]
            }
        if url.endswith("/v1/models"):
            return {"data": [{"id": "glm-4"}]}
        return {"status": "ok"}

    ollama = discover_ollama(fetch=fetch)
    generic = discover_openai_loopback("lmstudio", 1234, fetch=fetch)
    assert [item.model for item in ollama] == ["千问:4b"]
    assert ollama[0].identity_attested is True
    assert generic[0].identity_attested is False


def test_registry_locks_machine_identity_and_embedding_profile(tmp_path):
    path = tmp_path / "registry.sqlite3"
    registry = ProviderRegistry(
        path, machine_soul_id="machine-a", embedding_identity=("bge-m3", 1024, "bge-m3")
    )
    provider = _candidate()
    registry.upsert(provider, state=ProviderState.IDENTITY_ATTESTED, memory_allowed=True)
    assert registry.rows()[0]["memory_allowed"] == 1
    with pytest.raises(RegistryConflict, match="machine_soul_id"):
        ProviderRegistry(
            path, machine_soul_id="machine-b", embedding_identity=("bge-m3", 1024, "bge-m3")
        )
    with pytest.raises(RegistryConflict, match="embedding_identity"):
        ProviderRegistry(
            path, machine_soul_id="machine-a", embedding_identity=("other", 768, "other")
        )


def test_reconcile_is_idempotent_keeps_current_and_blocks_unattested_memory(
    tmp_path, monkeypatch
):
    result = _initialized(tmp_path)
    ollama, lm = _candidate(), _candidate("glm-4", source="lmstudio")
    monkeypatch.setattr(
        "soul_platform.autowire.manager.discover_all",
        lambda: ([ollama, lm], {"llamacpp": "ProbeError"}),
    )
    manager = AutoWireManager(result.root)
    first = manager.reconcile()
    second = manager.reconcile()
    assert first["generation"] == second["generation"] == 1
    rows = {row["provider_id"]: row for row in second["providers"]}
    assert rows[ollama.provider_id]["state"] == "ACTIVE"
    assert rows[ollama.provider_id]["memory_allowed"] == 1
    assert rows[lm.provider_id]["state"] == "DISCOVERED"
    assert rows[lm.provider_id]["memory_allowed"] == 0
    with pytest.raises(ActivationDenied, match="not identity-attested"):
        manager.activate(lm.provider_id, expected_generation=1)


def test_windows_reconcile_syncs_codex_app_grants_without_blocking_discovery(
    tmp_path, monkeypatch
):
    result = _initialized(tmp_path)
    current = _candidate()
    calls = []
    monkeypatch.setattr("soul_platform.autowire.manager._is_windows", lambda: True)
    monkeypatch.setattr(
        "soul_platform.autowire.manager.discover_all", lambda: ([current], {})
    )
    monkeypatch.setattr(
        "soul_platform.autowire.manager.sync_codex_app_grants",
        lambda settings, **kwargs: calls.append((settings, kwargs)) or 2,
    )
    claude_calls = []
    monkeypatch.setattr(
        "soul_platform.autowire.manager.sync_claude_app_grants",
        lambda settings, **kwargs: claude_calls.append((settings, kwargs)) or 2,
    )
    claude_config_calls = []
    monkeypatch.setattr(
        "soul_platform.autowire.manager.sync_claude_desktop_mcp_config",
        lambda **kwargs: claude_config_calls.append(kwargs) or True,
    )
    manager = AutoWireManager(result.root)
    status = manager.reconcile()
    assert len(calls) == 1
    assert len(claude_calls) == 1
    assert len(claude_config_calls) == 1
    assert calls[0][1]["config_path"] == result.config
    assert calls[0][1]["server_executable"] == (
        result.root / "venv" / "Scripts" / "soul-mcp-stdio.exe"
    )
    assert claude_calls[0][1] == calls[0][1]
    assert claude_config_calls[0] == calls[0][1]
    assert status["discovery_errors"] == {}
    assert status["providers"][0]["state"] == "ACTIVE"

    def fail_sync(*_args, **_kwargs):
        raise ValueError("stale App grant")

    monkeypatch.setattr(
        "soul_platform.autowire.manager.sync_codex_app_grants", fail_sync
    )
    monkeypatch.setattr(
        "soul_platform.autowire.manager.sync_claude_app_grants", fail_sync
    )
    monkeypatch.setattr(
        "soul_platform.autowire.manager.sync_claude_desktop_mcp_config",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("nope")),
    )
    degraded = manager.reconcile()
    assert degraded["discovery_errors"]["codex-app-grant"] == "ValueError"
    assert degraded["discovery_errors"]["claude-app-grant"] == "ValueError"
    assert degraded["discovery_errors"]["claude-desktop-config"] == "ValueError"
    assert degraded["providers"][0]["state"] == "ACTIVE"


def test_activation_preserves_embedding_and_uses_generation_fence(
    tmp_path, monkeypatch
):
    result = _initialized(tmp_path)
    old, new = _candidate(), _candidate("gemma:4b")
    monkeypatch.setattr(
        "soul_platform.autowire.manager.discover_all", lambda: ([old, new], {})
    )
    manager = AutoWireManager(result.root)
    manager.reconcile()
    before = ProxySettings.from_toml(result.config)

    def fake_switch(config, **kwargs):
        settings = ProxySettings.from_toml(config)
        from dataclasses import replace
        from soul_platform.bootstrap import _atomic_config, render_config

        changed = replace(
            settings,
            upstream_kind=kwargs["upstream_kind"],
            upstream_base_url=kwargs["upstream_base_url"],
            upstream_model=kwargs["upstream_model"],
        )
        _atomic_config(config, render_config(changed))
        return changed

    monkeypatch.setattr("soul_platform.autowire.manager.switch_upstream", fake_switch)
    monkeypatch.setattr(AutoWireManager, "_verify_proxy", lambda *_a: None)
    status = manager.activate(new.provider_id, expected_generation=1)
    after = ProxySettings.from_toml(result.config)
    assert status["generation"] == 2
    assert after.upstream_model == "gemma:4b"
    assert (after.embedding_provider, after.embedding_dimensions, after.embedding_model) == (
        before.embedding_provider,before.embedding_dimensions,before.embedding_model,
    )
    with pytest.raises(RegistryConflict, match="generation changed"):
        manager.registry.commit_binding(old.provider_id, expected_generation=1)


def test_activation_lock_checks_generation_before_any_side_effect(tmp_path, monkeypatch):
    result = _initialized(tmp_path)
    old, new = _candidate(), _candidate("gemma:4b")
    monkeypatch.setattr(
        "soul_platform.autowire.manager.discover_all", lambda: ([old, new], {})
    )
    manager = AutoWireManager(result.root)
    manager.reconcile()
    calls = 0
    calls_lock = threading.Lock()

    def fake_switch(config, **kwargs):
        nonlocal calls
        with calls_lock:
            calls += 1
        settings = ProxySettings.from_toml(config)
        from dataclasses import replace
        from soul_platform.bootstrap import _atomic_config, render_config

        changed = replace(settings, upstream_model=kwargs["upstream_model"])
        _atomic_config(config, render_config(changed))
        time.sleep(0.1)
        return changed

    monkeypatch.setattr("soul_platform.autowire.manager.switch_upstream", fake_switch)
    monkeypatch.setattr(AutoWireManager, "_verify_proxy", lambda *_a: None)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(manager.activate, new.provider_id, expected_generation=1)
            for _ in range(2)
        ]
    results, errors = [], []
    for future in futures:
        try:
            results.append(future.result())
        except Exception as exc:
            errors.append(exc)
    assert len(results) == len(errors) == 1
    assert isinstance(errors[0], RegistryConflict)
    assert calls == 1
    assert ProxySettings.from_toml(result.config).upstream_model == "gemma:4b"
    assert manager.registry.binding() == (new.provider_id, 2)


def test_active_provider_becomes_unreachable_without_changing_binding(tmp_path, monkeypatch):
    result = _initialized(tmp_path)
    current = _candidate()
    monkeypatch.setattr(
        "soul_platform.autowire.manager.discover_all", lambda: ([current], {})
    )
    manager = AutoWireManager(result.root)
    manager.reconcile()
    binding = manager.registry.binding()
    monkeypatch.setattr("soul_platform.autowire.manager.discover_all", lambda: ([], {}))
    status = manager.reconcile()
    row = next(item for item in status["providers"] if item["provider_id"] == current.provider_id)
    assert row["state"] == "ACTIVE_UNREACHABLE"
    assert row["memory_allowed"] == 0
    assert manager.registry.binding() == binding
    assert ProxySettings.from_toml(result.config).upstream_model == current.model


def test_windows_runtime_receipt_binds_owner_process_and_executable(tmp_path, monkeypatch):
    import soul_platform.runtime_attestation as attestation

    result = _initialized(tmp_path)
    executable = tmp_path / "ollama.exe"
    executable.write_bytes(b"pinned-ollama-binary")
    listener = {
        "pid": 42,
        "path": str(executable),
        "created": "20260821010101.000000-300",
        "owner": "DADITO\\Dadito",
    }
    monkeypatch.setattr(attestation, "_is_windows", lambda: True)
    monkeypatch.setattr(attestation, "_windows_listener", lambda: dict(listener))
    monkeypatch.setattr(attestation, "_current_windows_owner", lambda: "DADITO\\Dadito")
    settings = ProxySettings.from_toml(result.config)
    receipt = attestation.trust_current_ollama(
        result.root, machine_soul_id=settings.machine_soul_id
    )
    assert receipt["executable_sha256"]
    assert attestation.verify_runtime_attestation(settings) is True
    executable.write_bytes(b"impostor")
    assert attestation.verify_runtime_attestation(settings) is False


def test_legacy_config_upgrade_adds_t5_with_backup_and_preserves_bytes_invariants(tmp_path):
    result = _initialized(tmp_path)
    text = result.config.read_text()
    start, end = text.index("[memory_egress]"), text.index("[upstream]")
    result.config.write_text(text[:start] + text[end:])
    before = ProxySettings.from_toml(result.config)
    changed = upgrade_config(result.config)
    assert changed.t5_mode == "compatibility-single-owner"
    assert changed.machine_soul_id == before.machine_soul_id
    assert changed.soul_db == before.soul_db
    assert changed.embedding_dimensions == before.embedding_dimensions == 1024
    assert list(result.root.glob("proxy.toml.pre-t5-*.bak"))
    assert upgrade_config(result.config) == changed


def test_windows_autowire_task_is_current_user_limited_and_rollback_capable(
    tmp_path, monkeypatch
):
    result = _initialized(tmp_path)
    python = tmp_path / "venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(kwargs.get("input_text", ""))
        return SimpleNamespace(
            returncode=0,
            stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
        )

    monkeypatch.setattr("soul_platform.autowire.service._run", fake_run)
    target = install_autowire_autostart(
        root=result.root,
        platform="windows",
        home=tmp_path / "home",
        python=python,
    )
    script = calls[1]
    assert "SOUL AutoWire" in script
    assert "-RunLevel Limited" in script and "S-1-5-18" in script
    assert "MultipleInstances IgnoreNew" in script
    assert "Register-ScheduledTask" in script and "$oldXml" in script
    assert json.loads(target.read_text())["run_level"] == "LeastPrivilege"


async def test_unattested_loopback_never_receives_private_context(tmp_path):
    import httpx
    from soul_platform.proxy import create_app

    result = _initialized(tmp_path)
    base = ProxySettings.from_toml(result.config)
    from dataclasses import replace

    settings = replace(
        base,
        upstream_kind="lmstudio",
        upstream_base_url="http://127.0.0.1:1234/v1",
    )
    captured = []

    def handler(request: httpx.Request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": settings.upstream_model}]})
        captured.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "x", "object": "chat.completion", "model": settings.upstream_model,
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            },
        )

    app = create_app(settings, upstream_transport=httpx.MockTransport(handler))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.read_token()}"},
                json={"messages": [{"role": "user", "content": "¿Qué recuerdo?"}]},
            )
    assert response.status_code == 200
    assert response.headers["X-Soul-Egress"] == "blocked-unattested-upstream"
    assert response.headers["X-Soul-Memories"] == "0"
    system = captured[0]["messages"][0]["content"]
    assert "no está atestado" in system and "Memorias relevantes" not in system
