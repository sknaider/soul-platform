from __future__ import annotations

import json
import asyncio
import os
import sqlite3
import struct
import threading
import tomllib
import urllib.parse
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import httpx

from soul_platform import doctor
from soul_platform.autostart import AutostartContract, install_descriptor
from soul_platform.bootstrap import initialize, render_config
from soul_platform.proxy import ProxySettings, create_app

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
PLATFORM_VERSION = str(PROJECT["version"])
CORE_VERSION = next(
    item.split("==", 1)[1]
    for item in PROJECT["dependencies"]
    if item.lower().startswith("soul-framework") and "==" in item
)


def _exact_versions(
    monkeypatch, *, platform: str = PLATFORM_VERSION, core: str = CORE_VERSION
):
    versions = {"soul-platform": platform, "soul-framework": core}
    monkeypatch.setattr(doctor.metadata, "version", lambda name: versions[name])
    monkeypatch.setattr(
        doctor.metadata,
        "requires",
        lambda name: [f"soul-framework[ann]=={CORE_VERSION}"]
        if name == "soul-platform"
        else [],
    )


def _database(path: Path, dimensions: int = 1024) -> None:
    embedding = struct.pack(f"<{dimensions}f", *([0.25] * dimensions))
    # The product initializer now creates a live Core profile immediately.
    # Doctor's fixture intentionally uses a minimal synthetic schema, so reset
    # only this temporary test database before constructing that fixture.
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            "CREATE TABLE memories(id INTEGER PRIMARY KEY, embedding BLOB);"
            "CREATE TABLE procedural_memories(id INTEGER PRIMARY KEY, embedding BLOB);"
        )
        connection.execute("INSERT INTO memories(embedding) VALUES(?)", (embedding,))
        connection.commit()
    finally:
        connection.close()
    if os.name != "nt":
        path.chmod(0o600)


class _ProbeHandler(BaseHTTPRequestHandler):
    token = ""
    machine_soul_id = ""
    baseline_hash = ""
    model = ""
    ready = True
    accept_invalid = False
    bge_digest = doctor.APPROVED_BGE_M3_DIGEST

    def do_GET(self):  # noqa: N802 - stdlib handler contract
        if self.path == "/api/tags":
            payload = {
                "models": [
                    {
                        "name": "bge-m3:latest",
                        "model": "bge-m3:latest",
                        "digest": self.bge_digest,
                    }
                ],
                "debug_that_must_not_leak": self.token,
            }
        elif (
            not self.accept_invalid
            and self.headers.get("Authorization") != f"Bearer {self.token}"
        ):
            self.send_response(401)
            self.end_headers()
            return
        elif self.path == "/health":
            payload = {
                "ok": True,
                "machine_soul_id": self.machine_soul_id,
                "baseline_hash": self.baseline_hash,
                "debug_that_must_not_leak": self.token,
            }
        elif self.path == "/ready":
            payload = {
                "ready": self.ready,
                "soul_loaded": True,
                "brain_reachable": self.ready,
            }
        elif self.path == "/v1/models":
            payload = {"object": "list", "data": [{"id": self.model}]}
        else:
            self.send_response(404)
            self.end_headers()
            return
        encoded = json.dumps(payload).encode()
        self.send_response(200 if self.ready or self.path != "/ready" else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


@contextmanager
def _probe(
    settings: ProxySettings,
    token: str,
    *,
    ready: bool = True,
    accept_invalid: bool = False,
    bge_digest: str = doctor.APPROVED_BGE_M3_DIGEST,
):
    class Handler(_ProbeHandler):
        pass

    Handler.token = token
    Handler.machine_soul_id = settings.machine_soul_id
    Handler.baseline_hash = settings.baseline_hash
    Handler.model = settings.upstream_model
    Handler.ready = ready
    Handler.accept_invalid = accept_invalid
    Handler.bge_digest = bge_digest
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _runtime(tmp_path: Path, port: int) -> tuple[Path, Path, str]:
    root, home = tmp_path / "SOUL", tmp_path / "home"
    result = initialize(
        root=root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="doctor-brain",
        enable_autostart=False,
    )
    current = ProxySettings.from_toml(result.config)
    settings = replace(current, port=port)
    result.config.write_text(render_config(settings), encoding="utf-8")
    if os.name != "nt":
        result.config.chmod(0o600)
    _database(result.soul_db)
    install_descriptor(
        AutostartContract.load(result.config), "linux", home=home
    )
    return result.config, home, result.token_file.read_text().strip()


def _with_probe_port(settings: ProxySettings, port: int) -> ProxySettings:
    return replace(
        settings,
        port=port,
        embedding_url=f"http://127.0.0.1:{port}/api/embed",
    )


def test_doctor_green_is_json_and_never_leaks_token(tmp_path, monkeypatch):
    _exact_versions(monkeypatch)
    # Bootstrap first with a placeholder port, then bind the probe and rewrite it.
    config, home, token = _runtime(tmp_path, 11436)
    initial = ProxySettings.from_toml(config)
    with _probe(initial, token) as port:
        settings = _with_probe_port(initial, port)
        config.write_text(render_config(settings), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        install_descriptor(AutostartContract.load(config), "linux", home=home)
        report = doctor.run_doctor(config, platform="linux", home=home)
    encoded = json.dumps(report, sort_keys=True)
    assert report["ok"] is True
    assert [item["name"] for item in report["checks"]] == [
        "versions",
        "config",
        "database",
        "embedding_model",
        "runtime",
        "autostart",
    ]
    assert token not in encoded
    embedding = next(
        item for item in report["checks"] if item["name"] == "embedding_model"
    )
    assert embedding["ok"] is True
    assert embedding["details"]["installed_digest"] == doctor.APPROVED_BGE_M3_DIGEST


def test_version_drift_fails_closed(monkeypatch):
    _exact_versions(monkeypatch, core="999.0.0")
    check = doctor._check_versions()
    assert check.ok is False
    assert check.details["expected_core"] == CORE_VERSION
    assert check.details["installed_core"] == "999.0.0"


def test_repeated_exact_core_pins_from_extras_are_one_contract(monkeypatch):
    monkeypatch.setattr(
        doctor.metadata,
        "requires",
        lambda _name: [
            f"soul-framework[ann]=={CORE_VERSION}",
            f"soul-framework[ann,postgres]=={CORE_VERSION}; extra == 'postgres'",
        ],
    )
    assert doctor._expected_core_version() == CORE_VERSION


def test_database_dimension_drift_is_detected(tmp_path, monkeypatch):
    _exact_versions(monkeypatch)
    config, home, token = _runtime(tmp_path, 11436)
    settings = ProxySettings.from_toml(config)
    with sqlite3.connect(settings.soul_db) as connection:
        connection.execute(
            "UPDATE memories SET embedding=?", (struct.pack("<128f", *([0.5] * 128)),)
        )
    with _probe(settings, token) as port:
        changed = _with_probe_port(settings, port)
        config.write_text(render_config(changed), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        install_descriptor(AutostartContract.load(config), "linux", home=home)
        report = doctor.run_doctor(config, platform="linux", home=home)
    check = next(item for item in report["checks"] if item["name"] == "database")
    assert report["ok"] is False
    assert check["details"]["tables"]["memories"]["wrong_dimensions"] == 1


def test_database_missing_embedding_fails_closed(tmp_path, monkeypatch):
    _exact_versions(monkeypatch)
    config, home, token = _runtime(tmp_path, 11436)
    settings = ProxySettings.from_toml(config)
    with sqlite3.connect(settings.soul_db) as connection:
        connection.execute("INSERT INTO memories(embedding) VALUES(NULL)")
    with _probe(settings, token) as port:
        changed = _with_probe_port(settings, port)
        config.write_text(render_config(changed), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        install_descriptor(AutostartContract.load(config), "linux", home=home)
        report = doctor.run_doctor(config, platform="linux", home=home)
    check = next(item for item in report["checks"] if item["name"] == "database")
    memories = check["details"]["tables"]["memories"]
    assert report["ok"] is False and check["ok"] is False
    assert memories == {
        "total": 2,
        "embedded": 1,
        "missing_embeddings": 1,
        "wrong_dimensions": 0,
    }


def test_private_config_and_descriptor_drift_are_detected(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX mode contract")
    _exact_versions(monkeypatch)
    config, home, _token = _runtime(tmp_path, 11436)
    config.chmod(0o644)
    report = doctor.run_doctor(config, platform="linux", home=home, timeout_seconds=0.1)
    assert report["ok"] is False
    assert report["checks"][1]["name"] == "config"
    assert report["checks"][1]["ok"] is False
    assert all(item["ok"] is False for item in report["checks"][2:])


def test_not_ready_and_stale_autostart_fail_without_secret(tmp_path, monkeypatch):
    _exact_versions(monkeypatch)
    config, home, token = _runtime(tmp_path, 11436)
    settings = ProxySettings.from_toml(config)
    with _probe(settings, token, ready=False) as port:
        changed = _with_probe_port(settings, port)
        config.write_text(render_config(changed), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        target = doctor.descriptor_path("linux", home)
        target.write_bytes(target.read_bytes() + b"\n# stale\n")
        report = doctor.run_doctor(config, platform="linux", home=home)
    assert report["ok"] is False
    by_name = {item["name"]: item for item in report["checks"]}
    assert by_name["runtime"]["ok"] is False
    assert by_name["autostart"]["ok"] is False
    assert token not in json.dumps(report)


def test_auth_control_is_non_vacuous_and_payload_fields_stay_private(
    tmp_path, monkeypatch
):
    _exact_versions(monkeypatch)
    config, home, token = _runtime(tmp_path, 11436)
    settings = ProxySettings.from_toml(config)
    with _probe(settings, token, accept_invalid=True) as port:
        changed = _with_probe_port(settings, port)
        config.write_text(render_config(changed), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        install_descriptor(AutostartContract.load(config), "linux", home=home)
        report = doctor.run_doctor(config, platform="linux", home=home)
    runtime = next(item for item in report["checks"] if item["name"] == "runtime")
    assert report["ok"] is False and runtime["ok"] is False
    assert runtime["details"]["no_token_rejected"] is False
    assert runtime["details"]["wrong_token_rejected"] is False
    encoded = json.dumps(report)
    assert token not in encoded
    assert "debug_that_must_not_leak" not in encoded


def test_bge_m3_digest_drift_fails_closed_without_leaking_payload(
    tmp_path, monkeypatch
):
    _exact_versions(monkeypatch)
    config, home, token = _runtime(tmp_path, 11436)
    settings = ProxySettings.from_toml(config)
    unexpected_digest = "f" * 64
    with _probe(settings, token, bge_digest=unexpected_digest) as port:
        changed = _with_probe_port(settings, port)
        config.write_text(render_config(changed), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        install_descriptor(AutostartContract.load(config), "linux", home=home)
        report = doctor.run_doctor(config, platform="linux", home=home)
    embedding = next(
        item for item in report["checks"] if item["name"] == "embedding_model"
    )
    encoded = json.dumps(report, sort_keys=True)
    assert report["ok"] is False and embedding["ok"] is False
    assert embedding["details"]["expected_digest"] == doctor.APPROVED_BGE_M3_DIGEST
    assert embedding["details"]["installed_digest"] == unexpected_digest
    assert embedding["details"]["digest_matches"] is False
    assert token not in encoded
    assert "debug_that_must_not_leak" not in encoded


def test_no_autostart_is_an_explicit_non_drift_mode(tmp_path, monkeypatch):
    _exact_versions(monkeypatch)
    config, _home, token = _runtime(tmp_path, 11436)
    settings = ProxySettings.from_toml(config)
    with _probe(settings, token) as port:
        changed = _with_probe_port(settings, port)
        config.write_text(render_config(changed), encoding="utf-8")
        if os.name != "nt":
            config.chmod(0o600)
        report = doctor.run_doctor(
            config,
            platform="linux",
            home=tmp_path / "different-home",
            expect_autostart=False,
        )
    assert report["ok"] is True
    assert report["checks"][-1]["details"]["status"] == "not-required"


def test_cli_returns_nonzero_json_on_drift(tmp_path, monkeypatch, capsys):
    _exact_versions(monkeypatch, platform="999.0.0")
    rc = doctor.main(
        ["--config", str(tmp_path / "missing.toml"), "--no-autostart", "--timeout", "0.1"]
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert report["ok"] is False
    assert report["schema"] == doctor.REPORT_SCHEMA


def test_doctor_loopback_probes_ignore_proxy_environment(monkeypatch):
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"ok": true}'

    class Opener:
        def open(self, request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return Response()

    def build_opener(*handlers):
        captured["handlers"] = handlers
        return Opener()

    monkeypatch.setenv("HTTP_PROXY", "http://attacker.invalid:8080")
    monkeypatch.setattr(doctor.urllib.request, "build_opener", build_opener)
    value = doctor._request_json("http://127.0.0.1:11435/health", None, 1.0)
    assert value == {"ok": True}
    assert captured["url"] == "http://127.0.0.1:11435/health"
    assert captured["timeout"] == 1.0
    assert any(
        isinstance(handler, doctor.urllib.request.ProxyHandler)
        and handler.proxies == {}
        for handler in captured["handlers"]
    )


def test_doctor_runtime_contract_matches_real_proxy_endpoints(tmp_path, monkeypatch):
    """Prevent a synthetic probe from drifting away from the shipped proxy."""
    result = initialize(
        root=tmp_path / "real-proxy",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="doctor-brain",
        enable_autostart=False,
    )
    settings = ProxySettings.from_toml(result.config)

    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(200, json={"data": [{"id": settings.upstream_model}]})

    async def collect():
        app = create_app(settings, upstream_transport=httpx.MockTransport(upstream))
        headers = {"Authorization": f"Bearer {settings.read_token()}"}
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://real-proxy"
            ) as client:
                health = await client.get("/health", headers=headers)
                ready = await client.get("/ready", headers=headers)
                models = await client.get("/v1/models", headers=headers)
                no_token = await client.get("/v1/models")
                wrong = await client.get(
                    "/v1/models", headers={"Authorization": "Bearer wrong"}
                )
        return {
            "/health": health.json(),
            "/ready": ready.json(),
            "/v1/models": models.json(),
        }, no_token.status_code, wrong.status_code

    payloads, no_token_status, wrong_status = asyncio.run(collect())
    monkeypatch.setattr(
        doctor,
        "_request_json",
        lambda url, _token, _timeout: payloads[urllib.parse.urlsplit(url).path],
    )
    statuses = iter((no_token_status, wrong_status))
    monkeypatch.setattr(doctor, "_request_status", lambda *_args: next(statuses))

    check = doctor._check_runtime(settings, 1.0)
    assert check.ok is True
    assert check.details == {
        "origin": "http://127.0.0.1:11435",
        "health": True,
        "ready": True,
        "soul_loaded": True,
        "brain_reachable": True,
        "model_present": True,
        "identity_matches": True,
        "baseline_matches": True,
        "authenticated_probe": True,
        "no_token_rejected": True,
        "wrong_token_rejected": True,
    }
