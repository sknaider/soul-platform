from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from soul_platform.bootstrap import initialize
from soul_platform.tray import (
    MAX_DISCOVERY_BYTES,
    SoulTrayController,
    _acquire_instance_lock,
    discover_ollama_models,
    install_tray_autostart,
    main,
    remove_tray_autostart,
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
        upstream_model="gemma-test",
        enable_autostart=False,
    )


def test_discovery_is_loopback_bounded_normalized_and_deduplicated():
    seen = []

    def opener(request, **kwargs):
        seen.append((request.full_url, kwargs))
        return Response(
            {
                "models": [
                    {"name": "gemma:latest"},
                    {"name": " gemma:latest "},
                    {"name": "qwen:7b"},
                    {"name": "bad\nmodel"},
                    {"wrong": "shape"},
                ]
            }
        )

    assert discover_ollama_models(opener=opener) == ["gemma:latest", "qwen:7b"]
    assert seen[0][0] == "http://127.0.0.1:11434/api/tags"
    assert seen[0][1]["timeout"] == 2.0

    assert discover_ollama_models(opener=lambda *_a, **_k: Response(b"{")) == []
    assert discover_ollama_models(
        opener=lambda *_a, **_k: Response(b"x" * (MAX_DISCOVERY_BYTES + 1))
    ) == []


def test_default_discovery_does_not_inherit_proxy_environment(monkeypatch):
    captured: list[tuple[str, str | None]] = []

    class ProxyTrap(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            captured.append((self.path, self.headers.get("Authorization")))
            payload = b'{"models":[{"name":"intercepted"}]}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    trap = ThreadingHTTPServer(("127.0.0.1", 0), ProxyTrap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    proxy = f"http://127.0.0.1:{trap.server_port}"
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, proxy)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr("soul_platform.tray.OLLAMA_TAGS_URL", "http://127.0.0.1:9/api/tags")
    try:
        assert discover_ollama_models(timeout=0.1) == []
    finally:
        trap.shutdown()
        thread.join(timeout=2)
        trap.server_close()
    assert captured == []


def test_status_reports_uninstalled_without_creating_state(tmp_path):
    controller = SoulTrayController(
        config=tmp_path / "missing" / "proxy.toml",
        platform="linux",
        home=tmp_path / "home",
        opener=lambda *_a, **_k: (_ for _ in ()).throw(OSError("offline")),
    )
    status = controller.status()
    assert status.installed is False
    assert status.running is False
    assert not (tmp_path / "missing").exists()


def test_status_distinguishes_running_from_ready(tmp_path):
    result = _initialized(tmp_path)

    def opener(request, **_kwargs):
        if request.full_url.endswith("/health"):
            return Response({"ok": True, "machine_soul_id": result.machine_soul_id})
        if request.full_url.endswith("/ready"):
            return Response({"ready": True, "soul_loaded": True, "brain_reachable": True})
        raise AssertionError(request.full_url)

    controller = SoulTrayController(
        config=result.config,
        platform="linux",
        home=tmp_path / "home",
        opener=opener,
    )
    status = controller.status()
    assert status.installed and status.running and status.ready
    assert status.model == "gemma-test"
    assert status.machine_soul_id == result.machine_soul_id
    assert status.endpoint == "http://127.0.0.1:11435/v1"


def test_start_existing_installs_and_activates_managed_descriptor(tmp_path, monkeypatch):
    result = _initialized(tmp_path)
    calls = []
    monkeypatch.setattr(
        "soul_platform.tray.install_and_activate_descriptor",
        lambda *args, **kwargs: calls.append(("install+activate", args, kwargs)),
    )
    monkeypatch.setattr(
        SoulTrayController,
        "status",
        lambda self: SimpleNamespace(running=True, ready=True, detail="Alma activa"),
    )
    controller = SoulTrayController(
        config=result.config, platform="linux", home=tmp_path / "home"
    )
    controller.start()
    assert [call[0] for call in calls] == ["install+activate"]


def test_stop_preserves_data_and_delegates_to_runtime_stop(tmp_path, monkeypatch):
    result = _initialized(tmp_path)
    calls = []
    monkeypatch.setattr(
        "soul_platform.tray.stop_descriptor",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    monkeypatch.setattr(
        SoulTrayController,
        "status",
        lambda self: SimpleNamespace(running=False, ready=False, detail="Alma detenida"),
    )
    controller = SoulTrayController(
        config=result.config, platform="linux", home=tmp_path / "home"
    )
    controller.stop()
    assert len(calls) == 1
    assert result.config.exists() and result.token_file.exists()


def test_switch_model_restarts_only_when_runtime_is_live(tmp_path, monkeypatch):
    result = _initialized(tmp_path)
    observed = []
    monkeypatch.setattr(
        SoulTrayController,
        "status",
        lambda self: SimpleNamespace(running=True, ready=True, detail="Alma activa"),
    )

    def fake_switch(config, **kwargs):
        observed.append((config, kwargs))
        return SimpleNamespace(upstream_model=kwargs["upstream_model"])

    monkeypatch.setattr("soul_platform.tray.switch_upstream", fake_switch)
    controller = SoulTrayController(
        config=result.config, platform="linux", home=tmp_path / "home"
    )
    controller.switch_model("qwen:7b")
    assert observed[0][1]["restart"] is True
    assert observed[0][1]["upstream_base_url"] == "http://127.0.0.1:11434/v1"

    with pytest.raises(ValueError, match="inválido"):
        controller.switch_model("bad\nmodel")


def test_start_rolls_back_brain_when_activation_fails(tmp_path, monkeypatch):
    result = _initialized(tmp_path)
    before = result.config.read_bytes()
    monkeypatch.setattr(
        SoulTrayController,
        "status",
        lambda self: SimpleNamespace(running=False, ready=False, detail="detenida"),
    )
    monkeypatch.setattr(
        "soul_platform.tray.install_and_activate_descriptor",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("brain unavailable")),
    )
    controller = SoulTrayController(
        config=result.config, platform="linux", home=tmp_path / "home"
    )
    with pytest.raises(RuntimeError, match="brain unavailable"):
        controller.start("qwen:7b")
    assert result.config.read_bytes() == before


def test_headless_check_is_dependency_free(tmp_path, capsys):
    config = tmp_path / "missing" / "proxy.toml"
    assert main(["--config", str(config), "--headless-check"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["installed"] is False
    assert isinstance(payload["ollama_models"], list)


def test_tray_instance_lock_rejects_duplicate_until_owner_exits(tmp_path):
    path = tmp_path / "private" / ".soul-tray.lock"
    first = _acquire_instance_lock(path)
    assert first is not None
    try:
        assert _acquire_instance_lock(path) is None
    finally:
        first.close()
    second = _acquire_instance_lock(path)
    assert second is not None
    second.close()


def test_linux_tray_autostart_is_user_space_and_removable(tmp_path):
    home = tmp_path / "home"
    python = tmp_path / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    config = home / ".local" / "share" / "soul" / "proxy.toml"
    target = install_tray_autostart(
        config=config, platform="linux", home=home, python=python
    )
    text = target.read_text()
    assert target == home / ".config" / "autostart" / "soul-tray.desktop"
    assert "Terminal=false" in text
    assert "-m soul_platform.tray" in text
    receipt = home / ".local" / "share" / "soul" / "tray-autostart.json"
    assert json.loads(receipt.read_text())["run_level"] == "LeastPrivilege"
    assert remove_tray_autostart(platform="linux", home=home) == target
    assert not target.exists() and not receipt.exists()


def test_windows_tray_autostart_uses_limited_current_user_task_and_stdin(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    python = tmp_path / "venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    config = home / "AppData" / "Local" / "SOUL" / "proxy.toml"
    scripts = []
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        scripts.append(kwargs.get("input_text", ""))
        return SimpleNamespace(
            returncode=0,
            stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
        )

    monkeypatch.setattr("soul_platform.tray._run", fake_run)
    target = install_tray_autostart(
        config=config, platform="windows", home=home, python=python
    )
    assert commands[0][-2:] == ["-Command", "-"]
    assert "Export-ScheduledTask" in scripts[0]
    register = scripts[1]
    assert "New-ScheduledTaskTrigger -AtLogOn -User $sid" in register
    assert "if($oldXml){Stop-ScheduledTask" in register
    assert "-RunLevel Limited" in register
    assert "-RunLevel Highest" not in register
    assert "S-1-5-18" in register
    assert "Security.Principal.NTAccount($principalId)" in register
    assert "Translate([Security.Principal.SecurityIdentifier]).Value" in register
    assert "$taskSid -ne $sid" in register
    assert "soul_platform.tray" in register
    rollback = register[register.index("}catch{") :]
    assert "Register-ScheduledTask" in rollback
    assert "Start-ScheduledTask" in rollback
    assert "rollback restore could not be verified" in rollback
    assert "rollback removal could not be verified" in rollback
    assert json.loads(target.read_text())["run_level"] == "LeastPrivilege"

    remove_tray_autostart(platform="windows", home=home)
    assert "Unregister-ScheduledTask" in scripts[2]
    assert not target.exists()
