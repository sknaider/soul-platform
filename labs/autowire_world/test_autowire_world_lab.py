"""Hermetic contract tests for the containerized worldwide Auto-Wire lab."""

from __future__ import annotations

import json
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))

from autowire_lab import (  # noqa: E402
    LabError,
    Provider,
    Registry,
    _models,
    _models_path,
    _request_for,
    _text_from,
    http_json,
    load_config,
    providers_from,
    strict_json,
)
from run_lab import project_resources  # noqa: E402


def _config() -> dict:
    return load_config(LAB / "providers.json")


def test_world_matrix_has_unique_profiles_and_all_protocol_families() -> None:
    config = _config()
    providers = providers_from(config)
    by_id = {provider.provider_id: provider for provider in providers}

    assert len(providers) == 14
    assert len(by_id) == 14
    assert {provider.protocol for provider in providers} == {
        "openai-chat",
        "openai-responses",
        "anthropic-messages",
        "gemini-native",
        "ollama-native",
    }
    assert {"qwen", "deepseek", "glm", "kimi", "ernie", "hunyuan", "doubao", "minimax"} <= set(by_id)
    assert config["initial_provider_id"] == "qwen"
    assert config["allowed_clients"] == ["codex", "claude", "generic-openai"]


@pytest.mark.parametrize(
    ("protocol", "models_path", "request_path"),
    [
        ("openai-chat", "/v1/models", "/v1/chat/completions"),
        ("openai-responses", "/v1/models", "/v1/responses"),
        ("anthropic-messages", "/v1/models", "/v1/messages"),
        ("gemini-native", "/v1beta/models", "/v1beta/models/model:generateContent"),
        ("ollama-native", "/api/tags", "/api/chat"),
    ],
)
def test_protocol_adapters_build_and_parse_exact_contracts(
    protocol: str,
    models_path: str,
    request_path: str,
) -> None:
    provider = Provider("test", "model", protocol, "http://test:8000", "synthetic")
    messages = [
        {"role": "system", "content": "SOUL_ID=00000000-0000-0000-0000-000000000000"},
        {"role": "user", "content": "hello"},
    ]
    path, payload = _request_for(provider, messages)

    assert _models_path(provider) == models_path
    assert path == request_path
    if protocol == "gemini-native":
        assert "model" in path
    else:
        assert payload["model"] == "model"

    listings = {
        "openai-chat": {"data": [{"id": "model"}]},
        "openai-responses": {"data": [{"id": "model"}]},
        "anthropic-messages": {"data": [{"id": "model"}]},
        "gemini-native": {"models": [{"name": "models/model"}]},
        "ollama-native": {"models": [{"name": "model"}]},
    }
    responses = {
        "openai-chat": {"choices": [{"message": {"content": "ok"}}]},
        "openai-responses": {"output_text": "ok"},
        "anthropic-messages": {"content": [{"text": "ok"}]},
        "gemini-native": {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
        "ollama-native": {"message": {"content": "ok"}},
    }
    assert _models(listings[protocol], protocol) == {"model"}
    assert _text_from(provider, responses[protocol]) == "ok"


def test_strict_json_rejects_ambiguous_and_nonfinite_input() -> None:
    assert strict_json(b'{"ok":true}') == {"ok": True}
    with pytest.raises(ValueError, match="duplicate JSON key"):
        strict_json(b'{"model":"safe","model":"attacker"}')
    with pytest.raises(ValueError, match="non-finite JSON"):
        strict_json(b'{"score":NaN}')


def test_invalid_provider_config_fails_closed(tmp_path: Path) -> None:
    raw = _config()
    raw["providers"][1]["provider_id"] = raw["providers"][0]["provider_id"]
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(LabError, match="unique"):
        load_config(duplicate)

    with pytest.raises(LabError, match="unsupported protocol"):
        Provider.from_dict(
            {
                "provider_id": "unknown",
                "model": "unknown",
                "protocol": "vendor-magic",
                "origin": "http://unknown:8000",
                "region": "synthetic",
            }
        )

    for origin in (
        "https://provider:8000",
        "http://user:password@provider:8000",
        "http://provider:8000/base",
        "http://provider:8000?model=attacker",
        "http://provider:8000#fragment",
    ):
        with pytest.raises(LabError, match="non-canonical provider origin"):
            Provider.from_dict(
                {
                    "provider_id": "invalid-origin",
                    "model": "model",
                    "protocol": "openai-chat",
                    "origin": origin,
                    "region": "synthetic",
                }
            )

    missing_initial = _config()
    missing_initial["initial_provider_id"] = "absent"
    bad_initial = tmp_path / "bad-initial.json"
    bad_initial.write_text(json.dumps(missing_initial), encoding="utf-8")
    with pytest.raises(LabError, match="initial provider must exist"):
        load_config(bad_initial)


def test_registry_preserves_identity_memory_and_session_policy(tmp_path: Path) -> None:
    config = _config()
    path = tmp_path / "registry.sqlite3"
    registry = Registry(path, config)

    assert registry.machine_soul_id() == config["machine_soul_id"]
    assert registry.memory() == "VALERIA-RECUERDA-AYER"
    session = registry.issue_session("codex")
    assert registry.valid_session(session)
    with pytest.raises(LabError, match="not allowlisted"):
        registry.issue_session("unknown-app")

    reopened = Registry(path, config)
    assert reopened.machine_soul_id() == config["machine_soul_id"]
    assert reopened.memory() == "VALERIA-RECUERDA-AYER"
    assert reopened.valid_session(session)


def test_registry_rejects_machine_soul_identity_drift(tmp_path: Path) -> None:
    config = _config()
    path = tmp_path / "registry.sqlite3"
    Registry(path, config)
    changed = json.loads(json.dumps(config))
    changed["machine_soul_id"] = "00000000-0000-0000-0000-000000000000"

    with pytest.raises(LabError, match="invariant changed"):
        Registry(path, changed)


def test_resource_inventory_is_bound_to_exact_compose_project(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_check_output(command: list[str], *, text: bool) -> str:
        assert text is True
        seen.append(command)
        return "resource-one\n"

    monkeypatch.setattr("run_lab.subprocess.check_output", fake_check_output)
    resources = project_resources("soul-autowire-ada-123")

    assert resources == {
        "containers": ["resource-one"],
        "volumes": ["resource-one"],
        "networks": ["resource-one"],
    }
    assert all(
        "label=com.docker.compose.project=soul-autowire-ada-123" in command
        for command in seen
    )


def test_attach_session_expiry_and_revocation_fail_closed(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry.sqlite3", _config())

    revoked = registry.issue_session("codex")
    assert registry.revoke_session(revoked) is True
    assert registry.valid_session(revoked) is False
    assert registry.revoke_session(revoked) is False

    expired = registry.issue_session("claude")
    with sqlite3.connect(registry.path) as db:
        db.execute("UPDATE sessions SET expires_at=0 WHERE session_id=?", (expired,))
    assert registry.valid_session(expired) is False


def test_concurrent_switches_have_one_cas_winner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    registry = Registry(tmp_path / "registry.sqlite3", config)
    candidates = {provider.provider_id: provider for provider in providers_from(config)}
    for provider_id in ("qwen", "deepseek", "glm"):
        registry.upsert_provider(candidates[provider_id], "CANARY_PASSED", "unit")

    monkeypatch.setattr("autowire_lab.probe", lambda _provider: None)
    monkeypatch.setattr("autowire_lab.http_json", lambda *_args, **_kwargs: {"ok": True})
    assert registry.activate(candidates["qwen"], expected_generation=0) is True
    generation = registry.generation()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda provider_id: registry.activate(
                    candidates[provider_id], expected_generation=generation
                ),
                ("deepseek", "glm"),
            )
        )

    assert sorted(results) == [False, True]
    assert registry.generation() == generation + 1
    assert registry.active_provider_id() in {"deepseek", "glm"}
    assert registry.audit_counts()["BINDING_CAS_REJECTED"] == 1


def test_http_client_refuses_redirect_instead_of_following_it() -> None:
    class RedirectHandler(BaseHTTPRequestHandler):
        escaped = False

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/escape":
                type(self).escaped = True
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return
            self.send_response(302)
            self.send_header("Location", "/escape")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(LabError, match="request failed"):
            http_json("GET", f"http://127.0.0.1:{server.server_port}/start")
        assert RedirectHandler.escaped is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_stale_failed_activation_cannot_rollback_newer_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    registry = Registry(tmp_path / "registry.sqlite3", config)
    provider = Provider("same", "same-model", "openai-chat", "http://same:8000", "lab")
    registry.upsert_provider(provider, "CANARY_PASSED", "unit")

    failed_committed = threading.Event()
    winner_active = threading.Event()
    health_lock = threading.Lock()
    health_calls = 0

    monkeypatch.setattr("autowire_lab.probe", lambda _provider: None)

    def controlled_health(_method: str, url: str, _payload: object | None = None) -> dict:
        nonlocal health_calls
        assert url == provider.origin + "/health"
        with health_lock:
            health_calls += 1
            call_number = health_calls
        if call_number == 1:
            failed_committed.set()
            assert winner_active.wait(timeout=3)
            raise LabError("synthetic post-commit failure")
        return {"ok": True}

    monkeypatch.setattr("autowire_lab.http_json", controlled_health)
    with ThreadPoolExecutor(max_workers=1) as pool:
        failed_future = pool.submit(registry.activate, provider)
        assert failed_committed.wait(timeout=3)
        assert registry.activate(provider) is True
        winner_active.set()
        assert failed_future.result(timeout=3) is False

    assert registry.active_provider_id() == "same"
    assert registry.generation() == 2
    counts = registry.audit_counts()
    assert counts["ROLLBACK_FENCED"] == 1
    assert counts.get("BINDING_ROLLED_BACK", 0) == 0
