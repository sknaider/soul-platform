from __future__ import annotations

import json
import http.server
import base64
import sqlite3
import sys
import threading
import types
import uuid
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from soul_framework import Soul
from soul_framework.config import SoulConfig

from soul_platform.proxy import ProxySettings, create_app, run_proxy
from soul_platform.auth import PrincipalTokenIssuer


@pytest.fixture(autouse=True)
def _local_bge_stub(monkeypatch):
    """Exercise the 1024-d/portable ANN path without depending on a live Ollama daemon."""
    async def embed_batch(_self, texts):
        vectors = []
        for text in texts:
            vector = [0.0] * 1024
            vector[sum(text.encode("utf-8")) % 1024] = 1.0
            vectors.append(vector)
        return vectors

    monkeypatch.setattr(
        "soul_framework.embedding.bge_m3.BgeM3Embedding.embed_batch", embed_batch
    )
    monkeypatch.setattr(
        "soul_platform.local_embedding.LocalBgeM3Embedding.embed_batch", embed_batch
    )
    # Most proxy unit tests exercise T5 and persistence, not OS process
    # identity.  Dedicated negative tests below keep the real default closed.
    monkeypatch.setattr(
        "soul_platform.proxy.verify_runtime_attestation", lambda _settings: True
    )


async def test_private_context_is_blocked_when_live_runtime_attestation_fails(tmp_path):
    settings = _settings(tmp_path)
    captured = []
    app = create_app(
        settings,
        upstream_transport=_transport(captured),
        upstream_attestor=lambda _settings: False,
    )
    response = await _request(
        app,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {settings.read_token()}"},
        json={"messages": [{"role": "user", "content": "¿Qué recuerdo?"}]},
    )
    assert response.status_code == 200
    assert response.headers["X-Soul-Egress"] == "blocked-unattested-upstream"
    assert response.headers["X-Soul-Memories"] == "0"
    assert "Memorias relevantes" not in captured[0]["messages"][0]["content"]


def _settings(tmp_path: Path, model: str = "brain-a") -> ProxySettings:
    token = tmp_path / "proxy.token"
    token.write_text("t" * 40)
    token.chmod(0o600)
    return ProxySettings(
        soul_name="MachineSoul",
        soul_db=tmp_path / "MachineSoul.db",
        machine_soul_id=str(uuid.uuid4()),
        host="127.0.0.1",
        port=11435,
        require_auth=True,
        token_file=token,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model=model,
        t5_mode="compatibility-single-owner",
        t5_tenant="local-machine",
        t5_owner_subject="local-owner",
        t5_state_db=tmp_path / "MachineSoul.t5-egress.sqlite3",
    )


def _enforce_settings(tmp_path: Path, model: str = "brain-a"):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keys = tmp_path / "principal-keys.json"
    keys.write_text(json.dumps({"principal-1": base64.b64encode(public).decode()}))
    keys.chmod(0o600)
    base = _settings(tmp_path, model)
    settings = ProxySettings(
        **{
            **base.__dict__,
            "t5_mode": "enforce",
            "t5_tenant": "team",
            "t5_owner_subject": "alice",
            "t5_principal_keys_file": keys,
        }
    )
    return settings, PrincipalTokenIssuer(private, "principal-1")


def test_pythonw_without_stdio_disables_uvicorn_console_logging(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    class FakeConfig:
        def __init__(self, app, **kwargs):
            captured["kwargs"] = kwargs

    class FakeServer:
        def __init__(self, _config):
            self.should_exit = False

        def run(self):
            captured["ran"] = True

    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        types.SimpleNamespace(Config=FakeConfig, Server=FakeServer),
    )
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    run_proxy(_settings(tmp_path))
    assert captured["kwargs"] == {
        "host": "127.0.0.1",
        "port": 11435,
        "log_config": None,
        "access_log": False,
    }
    assert captured["ran"] is True


def _transport(captured: list[dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(
                200,
                json={"data": [
                    {"id": name}
                    for name in ("brain-a", "gemma-test", "qwen-test", "brain")
                ]},
            )
        body = json.loads(request.content)
        captured.append(body)
        system = body["messages"][0]["content"]
        answer = "ORQUIDEA-127387" if "ORQUIDEA-127387" in system else "NO_MEMORY"
        return httpx.Response(
            200,
            json={
                "id": "test",
                "object": "chat.completion",
                "model": body["model"],
                "choices": [{"message": {"role": "assistant", "content": answer}}],
            },
        )

    return httpx.MockTransport(handler)


async def _seed(settings: ProxySettings):
    config = SoulConfig(
        backend="sqlite",
        backend_url=str(settings.soul_db),
        embedding_provider="bge-m3",
        embedding_dimensions=1024,
        memory_vector_index="auto",
    )
    async with Soul.create(settings.soul_name, config=config) as soul:
        await soul.memory.store("La clave de continuidad es ORQUIDEA-127387.", importance=10)


def _soul_config(settings: ProxySettings) -> SoulConfig:
    return SoulConfig(
        backend="sqlite",
        backend_url=str(settings.soul_db),
        embedding_provider="bge-m3",
        embedding_dimensions=1024,
        memory_vector_index="auto",
    )


async def _request(app, method: str, path: str, **kwargs):
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.request(method, path, **kwargs)


async def test_auth_health_ready_and_no_secret_leak(tmp_path):
    settings = _settings(tmp_path)
    app = create_app(settings, upstream_transport=_transport([]))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            denied = await client.get("/v1/models")
            health = await client.get("/health")
            ready = await client.get("/ready")
    assert denied.status_code == 401
    assert health.status_code == 200
    assert health.json() == {
        "ok": True,
        "machine_soul_id": settings.machine_soul_id,
        "baseline_hash": settings.baseline_hash,
    }
    assert settings.upstream_base_url not in health.text
    assert settings.read_token() not in health.text
    assert ready.status_code == 200 and ready.json() == {
        "ready": True,
        "soul_loaded": True,
        "brain_reachable": True,
    }


async def test_ready_rejects_reachable_upstream_without_configured_model(tmp_path):
    settings = _settings(tmp_path, model="missing-model")
    app = create_app(settings, upstream_transport=_transport([]))
    response = await _request(app, "GET", "/ready")
    assert response.status_code == 503
    assert response.json() == {
        "ready": False,
        "soul_loaded": True,
        "brain_reachable": False,
    }


async def test_upstream_ignores_environment_proxy_and_does_not_leak_key(
    tmp_path, monkeypatch
):
    observed: list[tuple[str, str | None]] = []

    class ProxyTrap(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append((self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data":[{"id":"brain-a"}]}')

        def log_message(self, _format, *args):
            pass

    trap = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProxyTrap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    try:
        proxy_url = f"http://127.0.0.1:{trap.server_port}"
        monkeypatch.setenv("HTTP_PROXY", proxy_url)
        monkeypatch.setenv("ALL_PROXY", proxy_url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.setenv("SOUL_PROXY_UPSTREAM_API_KEY", "TOPSECRET")
        settings = ProxySettings(
            **{**_settings(tmp_path).__dict__, "upstream_base_url": "http://127.0.0.1:9/v1"}
        )
        response = await _request(create_app(settings), "GET", "/ready")
    finally:
        trap.shutdown()
        thread.join(timeout=2)
        trap.server_close()
    assert response.status_code == 503
    assert observed == []


async def test_same_soul_survives_model_switch_and_process_restart(tmp_path):
    first = _settings(tmp_path, "gemma-test")
    await _seed(first)
    captured_a: list[dict] = []
    app_a = create_app(first, upstream_transport=_transport(captured_a))
    payload = {"messages": [{"role": "user", "content": "clave de continuidad"}]}
    response_a = await _request(
        app_a,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {first.read_token()}"},
        json=payload,
    )
    second = ProxySettings(**{**first.__dict__, "upstream_model": "qwen-test"})
    captured_b: list[dict] = []
    app_b = create_app(second, upstream_transport=_transport(captured_b))
    response_b = await _request(
        app_b,
        "POST",
        "/v1/chat/completions",
        headers={"X-Soul-Token": second.read_token()},
        json=payload,
    )
    assert response_a.json()["choices"][0]["message"]["content"] == "ORQUIDEA-127387"
    assert response_b.json()["choices"][0]["message"]["content"] == "ORQUIDEA-127387"
    assert captured_a[0]["model"] == "gemma-test"
    assert captured_b[0]["model"] == "qwen-test"
    assert response_a.headers["X-Soul-Id"] == response_b.headers["X-Soul-Id"]
    assert response_a.headers["X-Soul-Baseline"] == response_b.headers["X-Soul-Baseline"]
    assert int(response_a.headers["X-Soul-Memories"]) >= 1
    assert response_a.headers["X-Soul-Memory-Ids"] == response_b.headers["X-Soul-Memory-Ids"]
    assert response_a.headers["X-Soul-Memory-SHA256"] == response_b.headers["X-Soul-Memory-SHA256"]


async def test_different_soul_is_negative_control(tmp_path):
    settings = _settings(tmp_path)
    captured: list[dict] = []
    response = await _request(
        create_app(settings, upstream_transport=_transport(captured)),
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {settings.read_token()}"},
        json={"messages": [{"role": "user", "content": "clave de continuidad"}]},
    )
    assert response.json()["choices"][0]["message"]["content"] == "NO_MEMORY"
    assert int(response.headers["X-Soul-Memories"]) == 0


async def test_explicit_remember_header_uses_ledger_not_semantic_memory(tmp_path):
    settings = _settings(tmp_path)
    captured: list[dict] = []
    app = create_app(settings, upstream_transport=_transport(captured))
    auth = {"Authorization": f"Bearer {settings.read_token()}"}
    stored = await _request(
        app,
        "POST",
        "/v1/chat/completions",
        headers={**auth, "X-Soul-Remember": "true"},
        json={"messages": [{"role": "user", "content": "LUCERO-127469"}]},
    )
    assert stored.headers["X-Soul-Store"] == "ledger"
    async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
        assert await soul.memory.search("LUCERO-127469") == []
    with sqlite3.connect(settings.conversation_ledger) as connection:
        rows = connection.execute(
            "SELECT content, previous_sha256, entry_sha256 FROM conversation_events"
        ).fetchall()
    assert rows[0][0] == "LUCERO-127469"
    assert rows[0][1] == "0" * 64 and len(rows[0][2]) == 64


async def test_tampered_conversation_ledger_fails_closed_on_restart(tmp_path):
    settings = _settings(tmp_path)
    auth = {"Authorization": f"Bearer {settings.read_token()}", "X-Soul-Remember": "true"}
    await _request(
        create_app(settings, upstream_transport=_transport([])),
        "POST", "/v1/chat/completions", headers=auth,
        json={"messages": [{"role": "user", "content": "original"}]},
    )
    with sqlite3.connect(settings.conversation_ledger) as connection:
        connection.execute("UPDATE conversation_events SET content='alterado' WHERE id=1")
    restarted = create_app(settings, upstream_transport=_transport([]))
    with pytest.raises(ValueError, match="hash chain"):
        async with restarted.router.lifespan_context(restarted):
            pass


async def test_conversation_ledger_head_detects_suffix_deletion(tmp_path):
    settings = _settings(tmp_path)
    auth = {"Authorization": f"Bearer {settings.read_token()}", "X-Soul-Remember": "true"}
    app = create_app(settings, upstream_transport=_transport([]))
    for content in ("uno", "dos"):
        await _request(
            app, "POST", "/v1/chat/completions", headers=auth,
            json={"messages": [{"role": "user", "content": content}]},
        )
    with sqlite3.connect(settings.conversation_ledger) as connection:
        connection.execute(
            "DELETE FROM conversation_events WHERE id=(SELECT MAX(id) FROM conversation_events)"
        )
    restarted = create_app(settings, upstream_transport=_transport([]))
    with pytest.raises(ValueError, match="head witness"):
        async with restarted.router.lifespan_context(restarted):
            pass


async def test_explicit_fact_is_promoted_but_question_is_never_a_fact(tmp_path):
    settings = _settings(tmp_path)
    auth = {"Authorization": f"Bearer {settings.read_token()}"}
    app = create_app(settings, upstream_transport=_transport([]))
    stored = await _request(
        app,
        "POST",
        "/v1/chat/completions",
        headers={**auth, "X-Soul-Remember": "true"},
        json={
            "messages": [{"role": "user", "content": "¿Cómo me llamo?"}],
            "soul_memory": {"content": "El usuario se llama William.", "importance": 10},
        },
    )
    assert stored.headers["X-Soul-Store"] == "ledger+fact"
    async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
        hits = await soul.memory.search("nombre del usuario", limit=10)
    assert any(hit.memory.content == "El usuario se llama William." for hit in hits)
    assert all("¿Cómo me llamo?" not in hit.memory.content for hit in hits)


async def test_question_cannot_be_promoted_as_fact(tmp_path):
    settings = _settings(tmp_path)
    response = await _request(
        create_app(settings, upstream_transport=_transport([])),
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {settings.read_token()}"},
        json={
            "messages": [{"role": "user", "content": "hola"}],
            "soul_memory": {"content": "¿Vivo en México?", "importance": 9},
        },
    )
    assert response.status_code == 422


async def test_fact_success_reports_partial_ledger_failure_honestly(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "soul_platform.proxy.ConversationLedger.append",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("full")),
    )
    response = await _request(
        create_app(settings, upstream_transport=_transport([])),
        "POST",
        "/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {settings.read_token()}",
            "X-Soul-Remember": "true",
        },
        json={
            "messages": [{"role": "user", "content": "dato"}],
            "soul_memory": {"content": "El código revisado es LUNA-42.", "importance": 8},
        },
    )
    assert response.status_code == 200
    assert response.headers["X-Soul-Store"] == "ledger-failed+fact-stored"


async def test_ledger_success_reports_partial_fact_failure_honestly(tmp_path, monkeypatch):
    settings = _settings(tmp_path)

    async def fail_store(*_args, **_kwargs):
        raise sqlite3.OperationalError("semantic store unavailable")

    monkeypatch.setattr("soul_framework.memory.store.MemoryStore.store", fail_store)
    response = await _request(
        create_app(settings, upstream_transport=_transport([])),
        "POST", "/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {settings.read_token()}",
            "X-Soul-Remember": "true",
        },
        json={
            "messages": [{"role": "user", "content": "dato"}],
            "soul_memory": {"content": "El código revisado es SOL-43.", "importance": 8},
        },
    )
    assert response.status_code == 200
    assert response.headers["X-Soul-Store"] == "ledger+fact-failed"
    with sqlite3.connect(settings.conversation_ledger) as connection:
        assert connection.execute("SELECT COUNT(*) FROM conversation_events").fetchone()[0] == 1


async def test_invalid_remember_header_fails_closed(tmp_path):
    settings = _settings(tmp_path)
    response = await _request(
        create_app(settings, upstream_transport=_transport([])),
        "POST",
        "/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {settings.read_token()}",
            "X-Soul-Remember": "yes",
        },
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 422


async def test_streaming_sse_is_bounded_and_preserves_soul_headers(tmp_path):
    settings = _settings(tmp_path)
    captured: list[dict] = []

    def streaming_transport(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.append(body)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream; charset=utf-8"},
            content=(
                b'data: {"choices":[{"delta":{"content":"GROK-SOUL-OK"}}]}\n\n'
                b"data: [DONE]\n\n"
            ),
        )

    app = create_app(settings, upstream_transport=httpx.MockTransport(streaming_transport))
    headers = {"Authorization": f"Bearer {settings.read_token()}"}
    streamed = await _request(
        app,
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={"stream": True, "messages": [{"role": "user", "content": "hi"}]},
    )
    assert streamed.status_code == 200
    assert streamed.headers["content-type"].startswith("text/event-stream")
    assert streamed.headers["X-Soul-Id"] == settings.machine_soul_id
    assert streamed.headers["X-Soul-Store"] == "disabled"
    assert b"GROK-SOUL-OK" in streamed.content and b"[DONE]" in streamed.content
    assert captured[0]["stream"] is True
    assert captured[0]["model"] == settings.upstream_model
    assert captured[0]["messages"][0]["role"] == "system"


async def test_invalid_stream_and_oversized_requests_fail_closed(tmp_path):
    settings = _settings(tmp_path)
    app = create_app(settings, upstream_transport=_transport([]))
    headers = {"Authorization": f"Bearer {settings.read_token()}"}
    invalid_stream = await _request(
        app,
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={"stream": "true", "messages": [{"role": "user", "content": "hi"}]},
    )
    tiny = ProxySettings(**{**settings.__dict__, "max_request_bytes": 4096})
    oversized = await _request(
        create_app(tiny, upstream_transport=_transport([])),
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={"messages": [{"role": "user", "content": "x" * 5000}]},
    )
    assert invalid_stream.status_code == 422
    assert oversized.status_code == 413


async def test_streaming_response_type_and_size_fail_closed(tmp_path):
    settings = ProxySettings(**{**_settings(tmp_path).__dict__, "max_response_bytes": 4096})
    headers = {
        "Authorization": f"Bearer {settings.read_token()}",
        "X-Soul-Remember": "true",
    }
    payload = {"stream": True, "messages": [{"role": "user", "content": "hi"}]}

    not_sse = await _request(
        create_app(
            settings,
            upstream_transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json={"unexpected": True})
            ),
        ),
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json=payload,
    )
    malformed_sse = await _request(
        create_app(
            settings,
            upstream_transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    content=b'data: {"choices": []}\n\n',
                )
            ),
        ),
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json=payload,
    )
    non_finite_sse = await _request(
        create_app(
            settings,
            upstream_transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    content=b'data: {"choices":[{"score":NaN}]}\n\ndata: [DONE]\n\n',
                )
            ),
        ),
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json=payload,
    )
    too_large = await _request(
        create_app(
            settings,
            upstream_transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    content=b"x" * 5000,
                )
            ),
        ),
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json=payload,
    )
    assert not_sse.status_code == 502
    assert not_sse.json()["error"] == "upstream streaming response is not event-stream"
    assert not_sse.headers["X-Soul-Store"] == "disabled"
    assert malformed_sse.status_code == 502
    assert malformed_sse.json()["error"] == "upstream streaming response is invalid"
    assert malformed_sse.headers["X-Soul-Store"] == "disabled"
    assert non_finite_sse.status_code == 502
    assert non_finite_sse.json()["error"] == "upstream streaming response is invalid"
    assert non_finite_sse.headers["X-Soul-Store"] == "disabled"
    assert too_large.status_code == 502
    assert too_large.json()["error"] == "upstream response too large"
    async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
        assert await soul.memory.search("hi") == []


@pytest.mark.parametrize(
    "bad_content",
    [b"not-json", b'{"choices":[{"score":NaN}]}', b'{"score":Infinity}'],
)
async def test_invalid_success_response_never_mutates_memory(tmp_path, bad_content):
    settings = _settings(tmp_path)
    headers = {
        "Authorization": f"Bearer {settings.read_token()}",
        "X-Soul-Remember": "true",
    }
    response = await _request(
        create_app(
            settings,
            upstream_transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=bad_content,
                )
            ),
        ),
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={"messages": [{"role": "user", "content": "PHANTOM-STORE-127469"}]},
    )
    assert response.status_code == 502
    assert response.headers["X-Soul-Store"] == "disabled"
    async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
        assert await soul.memory.search("PHANTOM-STORE-127469") == []


async def test_upstream_response_limit_and_authenticated_shutdown(tmp_path):
    settings = ProxySettings(**{**_settings(tmp_path).__dict__, "max_response_bytes": 4096})

    def oversized(_request):
        return httpx.Response(200, content=b"x" * 5000)

    app = create_app(settings, upstream_transport=httpx.MockTransport(oversized))
    called = []
    app.state.request_shutdown = lambda: called.append(True)
    headers = {"Authorization": f"Bearer {settings.read_token()}"}
    response = await _request(
        app,
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    stopped = await _request(app, "POST", "/admin/shutdown", headers=headers)
    assert response.status_code == 502 and response.json()["error"] == "upstream response too large"
    assert stopped.status_code == 200 and called == [True]


def test_settings_reject_public_bind_remote_without_opt_in_and_weak_token(tmp_path):
    settings = _settings(tmp_path)
    with pytest.raises(ValueError, match="loopback"):
        ProxySettings(**{**settings.__dict__, "host": "0.0.0.0"}).validate()
    with pytest.raises(ValueError, match="loopback"):
        ProxySettings(**{**settings.__dict__, "host": "localhost"}).validate()
    with pytest.raises(ValueError, match="disabled"):
        ProxySettings(
            **{**settings.__dict__, "upstream_base_url": "https://example.com/v1"}
        ).validate()
    with pytest.raises(ValueError, match="disabled"):
        ProxySettings(
            **{**settings.__dict__, "upstream_base_url": "http://localhost:11434/v1"}
        ).validate()
    settings.token_file.write_text("weak")
    with pytest.raises(ValueError, match="32 bytes"):
        settings.validate()
    settings.token_file.write_text("t" * 40)
    with pytest.raises(ValueError, match="api_key_env"):
        ProxySettings(**{**settings.__dict__, "upstream_api_key_env": "AWS_SECRET_ACCESS_KEY"}).validate()


def test_config_and_soul_paths_must_be_private_and_canonical(tmp_path):
    settings = _settings(tmp_path)
    config = tmp_path / "proxy.toml"
    config.write_text(
        "[soul]\n"
            f'name="MachineSoul"\ndb="{settings.soul_db}"\n'
            f'machine_soul_id="{settings.machine_soul_id}"\n'
            '[embedding]\nprovider="bge-m3"\ndimensions=1024\nmodel="bge-m3"\n'
            'url="http://127.0.0.1:11434/api/embed"\ntimeout_seconds=60\n'
            'vector_index="auto"\n'
            "[proxy]\n"
        f'host="127.0.0.1"\nport=11435\nrequire_auth=true\ntoken_file="{settings.token_file}"\n'
        '[upstream]\nkind="ollama"\nbase_url="http://127.0.0.1:11434/v1"\nmodel="brain"\n'
    )
    config.chmod(0o666)
    with pytest.raises(ValueError, match="group/other"):
        ProxySettings.from_toml(config)
    config.chmod(0o600)
    outside = tmp_path.parent / "outside.db"
    config.write_text(config.read_text().replace(str(settings.soul_db), str(outside)))
    with pytest.raises(ValueError, match="canonical SOUL root"):
        ProxySettings.from_toml(config)
