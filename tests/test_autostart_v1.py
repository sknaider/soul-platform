from __future__ import annotations

import base64
import json
import os
import plistlib
import socket
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from soul_platform.autostart import (
    AutostartContract,
    _clean_path,
    activate_descriptor,
    deactivate_descriptor,
    disable_descriptor,
    install_and_activate_descriptor,
    install_descriptor,
    stop_descriptor,
)


class _ProxyTrap(BaseHTTPRequestHandler):
    captured: list[tuple[str, str | None]] = []

    def _capture(self):
        type(self).captured.append((self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = _capture
    do_POST = _capture

    def log_message(self, *_args):
        return


def _start_proxy_trap(monkeypatch):
    _ProxyTrap.captured = []
    trap = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyTrap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    proxy = f"http://127.0.0.1:{trap.server_port}"
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, proxy)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    return trap, thread


def _contract(tmp_path: Path, monkeypatch, **proxy_overrides) -> AutostartContract:
    data = tmp_path / "SOUL Data"
    data.mkdir(mode=0o700)
    token = data / "proxy.token"
    token.write_bytes(b"a" * 32)
    token.chmod(0o600)
    credential = data / "soul-dni.json"
    trust = data / "soul-dni-trust.json"
    credential.write_bytes(Path(os.environ["SOUL_DNI_CREDENTIAL"]).read_bytes())
    trust.write_bytes(Path(os.environ["SOUL_DNI_TRUST_STORE"]).read_bytes())
    credential.chmod(0o600)
    trust.chmod(0o600)
    python = tmp_path / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    proxy = {
        "host": "127.0.0.1",
        "port": 11435,
        "require_auth": True,
        "token_file": str(token),
    }
    proxy.update(proxy_overrides)
    config = data / "proxy.toml"
    config.write_text(
        "[soul]\n"
        f'name = "MachineSoul"\ndb = "{data / "MachineSoul.db"}"\n'
        f'machine_soul_id = "{os.environ["SOUL_DNI_MACHINE_SOUL_ID"]}"\n'
        f'dni = "{os.environ["SOUL_DNI_VALUE"]}"\n'
        f'dni_credential_file = "{credential}"\n'
        f'dni_trust_store_file = "{trust}"\n'
        f'dni_trust_store_sha256 = "{os.environ["SOUL_DNI_TRUST_STORE_SHA256"]}"\n'
        "[proxy]\n"
        + "\n".join(
            f'{key} = {str(value).lower() if isinstance(value, bool) else repr(value)}'
            for key, value in proxy.items()
        )
        + "\n[upstream]\nbase_url = \"http://127.0.0.1:11434/v1\"\nmodel = \"brain\"\n"
    )
    config.chmod(0o600)
    return AutostartContract.load(config, python=str(python))


def test_autostart_requires_loopback_and_auth(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="loopback"):
        _contract(tmp_path, monkeypatch, host="0.0.0.0")


def test_autostart_rejects_remote_even_with_legacy_opt_in(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    text = contract.config.read_text().replace(
        'base_url = "http://127.0.0.1:11434/v1"',
        'base_url = "https://example.com/v1"\nallow_remote = true',
    )
    contract.config.write_text(text)
    contract.config.chmod(0o600)
    with pytest.raises(ValueError, match="disabled"):
        AutostartContract.load(contract.config, python=str(contract.python))


def test_autostart_rejects_weak_or_shared_token(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    contract.token_file.write_bytes(b"weak")
    with pytest.raises(ValueError, match="at least 32"):
        AutostartContract.load(contract.config, python=str(contract.python))
    contract.token_file.write_bytes(b"a" * 32)
    contract.token_file.chmod(0o644)
    with pytest.raises(ValueError, match="group/other"):
        AutostartContract.load(contract.config, python=str(contract.python))


@pytest.mark.parametrize("platform", ["linux", "windows", "macos"])
def test_install_is_per_user_and_disable_preserves_soul(tmp_path, monkeypatch, platform):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "User Home"
    target = install_descriptor(contract, platform, home=home)
    assert target.is_file()
    assert home in target.parents
    assert contract.config.exists() and contract.token_file.exists()
    assert disable_descriptor(platform, home=home) == target
    assert not target.exists()
    assert contract.config.exists() and contract.token_file.exists()


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_product_autostart_failure_restores_and_reactivates_prior_descriptor(
    tmp_path, monkeypatch, platform
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, platform, home=home)
    previous = b"exact prior descriptor\nwith product-specific bytes\n"
    target.write_bytes(previous)
    target.chmod(0o640)
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, target.read_bytes()))
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr(
        "soul_platform.autostart._authenticated_probe",
        lambda _contract: (_ for _ in ()).throw(RuntimeError("new service failed")),
    )
    with pytest.raises(RuntimeError, match="new service failed"):
        install_and_activate_descriptor(contract, platform, home=home)

    assert target.read_bytes() == previous
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    # The second native activation observes the restored bytes, not the failed
    # replacement.  Linux and macOS each execute three activation commands.
    expected_commands = 7 if platform == "linux" else 6
    restored_activation_offset = 4 if platform == "linux" else 3
    assert len(commands) == expected_commands
    assert all(
        payload == previous
        for _command, payload in commands[restored_activation_offset:]
    )


@pytest.mark.parametrize("manager_state", ["missing", "inactive"])
def test_product_linux_autostart_preflights_manager_before_writing(
    tmp_path, monkeypatch, manager_state
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = home / ".config" / "systemd" / "user" / "soul-platform-proxy.service"
    if manager_state == "missing":
        monkeypatch.setattr("soul_platform.autostart.shutil.which", lambda _name: None)
    else:
        monkeypatch.setattr(
            "soul_platform.autostart.shutil.which", lambda _name: "/usr/bin/systemctl"
        )
        monkeypatch.setattr(
            "soul_platform.autostart._run",
            lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
        )
    with pytest.raises(RuntimeError, match="systemd user manager"):
        install_and_activate_descriptor(contract, "linux", home=home)
    assert not target.exists()
    assert not target.parent.exists()


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_product_autostart_failure_disables_and_removes_fresh_descriptor(
    tmp_path, monkeypatch, platform
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda _contract: None)
    monkeypatch.setattr(
        "soul_platform.autostart._authenticated_probe",
        lambda _contract: (_ for _ in ()).throw(RuntimeError("fresh probe failed")),
    )
    with pytest.raises(RuntimeError, match="fresh probe failed"):
        install_and_activate_descriptor(contract, platform, home=home)

    target = (
        home / ".config" / "systemd" / "user" / "soul-platform-proxy.service"
        if platform == "linux"
        else home / "Library" / "LaunchAgents" / "com.soul.platform.proxy.plist"
    )
    assert not target.exists()
    flattened = [command for command, _kwargs in commands]
    if platform == "linux":
        assert ["systemctl", "--user", "stop", target.name] in flattened
        assert ["systemctl", "--user", "disable", target.name] in flattened
    else:
        assert [
            "launchctl",
            "bootout",
            f"gui/{os.getuid()}",
            str(target),
        ] in flattened


def test_partial_linux_activation_is_stopped_before_fresh_descriptor_removal(
    tmp_path, monkeypatch
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = home / ".config" / "systemd" / "user" / "soul-platform-proxy.service"
    state = {"active": False}
    commands = []

    monkeypatch.setattr(
        "soul_platform.autostart.shutil.which", lambda _name: "/usr/bin/systemctl"
    )

    def partial_start(command, **_kwargs):
        commands.append(command)
        if command[:4] == ["systemctl", "--user", "enable", "--now"]:
            state["active"] = True
            raise subprocess.CalledProcessError(1, command)
        if command[:3] == ["systemctl", "--user", "stop"]:
            state["active"] = False
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr("soul_platform.autostart._run", partial_start)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda _contract: None)
    with pytest.raises(subprocess.CalledProcessError):
        install_and_activate_descriptor(contract, "linux", home=home)

    assert state["active"] is False
    assert ["systemctl", "--user", "stop", target.name] in commands
    assert ["systemctl", "--user", "disable", target.name] in commands
    assert not target.exists()


@pytest.mark.parametrize("had_previous", [False, True])
def test_product_windows_descriptor_matches_successful_native_task_rollback(
    tmp_path, monkeypatch, had_previous
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "windows", home=home)
    previous = b'{"schema":"prior-product-descriptor"}'
    if had_previous:
        target.write_bytes(previous)
    else:
        target.unlink()
    scripts = []

    def fake_run(command, **kwargs):
        scripts.append(kwargs.get("input_text", ""))
        return SimpleNamespace(
            returncode=0,
            stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
        )

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr("soul_platform.autostart._request_shutdown", lambda _contract: None)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda _contract: None)
    monkeypatch.setattr(
        "soul_platform.autostart._authenticated_probe",
        lambda _contract: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    with pytest.raises(RuntimeError, match="probe failed"):
        install_and_activate_descriptor(contract, "windows", home=home)

    assert any("Export-ScheduledTask" in script for script in scripts)
    assert any("Unregister-ScheduledTask" in script for script in scripts)
    if had_previous:
        assert target.read_bytes() == previous
    else:
        assert not target.exists()


def test_descriptors_use_absolute_python_config_and_loopback_contract(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    linux = install_descriptor(contract, "linux", home=tmp_path / "linux-home").read_text()
    windows = install_descriptor(contract, "windows", home=tmp_path / "win-home").read_text()
    mac = plistlib.loads(
        install_descriptor(contract, "macos", home=tmp_path / "mac-home").read_bytes()
    )
    for rendered in (linux, windows, " ".join(mac["ProgramArguments"])):
        assert str(contract.python) in rendered
        assert str(contract.config) in rendered
        assert "0.0.0.0" not in rendered
        assert "proxy.token" not in rendered
    assert "NoNewPrivileges=true" in linux
    assert "ProtectSystem=strict" in linux
    windows_payload = json.loads(windows)
    assert windows_payload["schema"] == "soul.windows-autostart.v2"
    assert windows_payload["task_name"] == "SOUL Platform"
    assert windows_payload["run_level"] == "LeastPrivilege"
    assert windows_payload["hidden"] is True
    assert windows_payload["restart_count"] == 3
    assert "-m\" \"soul_platform.proxy" in linux


def test_newline_in_path_is_rejected(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="control"):
        _clean_path(str(tmp_path / "safe") + "\nbad", "test.path")


def test_symlinked_descriptor_parent_and_systemd_specifier_are_rejected_or_escaped(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    home.mkdir()
    escaped = tmp_path / "escaped"
    escaped.mkdir()
    (home / ".config").symlink_to(escaped, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        install_descriptor(contract, "linux", home=home)

    percent_root = tmp_path / "percent%h"
    percent_root.mkdir()
    percent_root.chmod(0o700)
    percent_contract = _contract(percent_root, monkeypatch)
    unit = install_descriptor(percent_contract, "linux", home=tmp_path / "safe-home").read_text()
    assert "percent%%h" in unit
    assert "percent%h" not in unit.replace("percent%%h", "")


def test_linux_lifecycle_enables_starts_stops_and_preserves_data(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "linux", home=home)
    commands = []
    scripts = []

    def fake_run(command, **kwargs):
        commands.append(command)
        scripts.append(kwargs.get("input_text", ""))
        return SimpleNamespace(
            returncode=0,
            stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
        )

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr("soul_platform.autostart._authenticated_probe", lambda contract: None)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda contract: None)
    assert activate_descriptor(contract, "linux", home=home) == target
    assert ["systemctl", "--user", "enable", "--now", target.name] in commands
    assert ["systemctl", "--user", "restart", target.name] in commands
    assert deactivate_descriptor(contract, "linux", home=home) == target
    assert ["systemctl", "--user", "disable", "--now", target.name] in commands
    assert not target.exists()
    assert contract.config.exists() and contract.token_file.exists()


def test_stop_descriptor_stops_runtime_without_removing_descriptor(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "linux", home=home)
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda contract: None)
    stop_descriptor(contract, "linux", home=home)
    assert commands == [
        (["systemctl", "--user", "stop", target.name], {"check": False})
    ]
    assert target.exists()
    assert contract.config.exists() and contract.token_file.exists()


def test_windows_lifecycle_uses_limited_restartable_task_and_removes_legacy_launcher(
    tmp_path, monkeypatch
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "windows", home=home)
    legacy = (
        home
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "SOUL Platform.vbs"
    )
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy")
    commands = []
    scripts = []

    def fake_run(command, **kwargs):
        commands.append(command)
        scripts.append(kwargs.get("input_text", ""))
        return SimpleNamespace(
            returncode=0,
            stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
        )

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr("soul_platform.autostart._request_shutdown", lambda contract: None)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda contract: None)
    monkeypatch.setattr("soul_platform.autostart._authenticated_probe", lambda contract: None)

    assert activate_descriptor(contract, "windows", home=home) == target
    snapshot = scripts[0]
    register = scripts[1]
    assert commands[0][-2:] == ["-Command", "-"]
    assert "SOUL_TASK_RECEIPT_V1" in snapshot
    assert "Export-ScheduledTask" in snapshot
    assert "New-ScheduledTaskTrigger -AtLogOn" in register
    assert "WindowsIdentity]::GetCurrent" in register
    assert "$identity.User.Value" in register
    assert "S-1-5-18" in register
    assert "-AtLogOn -User $sid" in register
    assert "-RunLevel Limited" in register
    assert "-RunLevel Highest" not in register
    assert "New-ScheduledTaskSettingsSet -Hidden" in register
    assert "-RestartCount 3" in register
    assert "pythonw.exe" not in register
    assert str(contract.python) in register
    assert not legacy.exists()

    assert deactivate_descriptor(contract, "windows", home=home) == target
    remove = scripts[2]
    assert "Unregister-ScheduledTask" in remove
    assert not target.exists()
    assert contract.config.exists() and contract.token_file.exists()


def test_windows_task_quotes_hostile_config_as_one_argument(tmp_path, monkeypatch):
    root = tmp_path / "hostile ' & $ ; path"
    root.mkdir()
    contract = _contract(root, monkeypatch)
    from soul_platform.autostart import _windows_task_script

    script = _windows_task_script(contract, action="register")
    expected = subprocess.list2cmdline(
        ["-m", "soul_platform.proxy", "--config", str(contract.config)]
    ).replace("'", "''")
    assert expected in script


def test_windows_probe_failure_rolls_back_and_keeps_legacy(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    install_descriptor(contract, "windows", home=home)
    legacy = (
        home / "AppData" / "Roaming" / "Microsoft" / "Windows"
        / "Start Menu" / "Programs" / "Startup" / "SOUL Platform.vbs"
    )
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy")
    commands = []
    scripts = []

    def fake_run(command, **kwargs):
        commands.append(command)
        scripts.append(kwargs.get("input_text", ""))
        return SimpleNamespace(
            returncode=0,
            stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
        )

    monkeypatch.setattr("soul_platform.autostart._run", fake_run)
    monkeypatch.setattr("soul_platform.autostart._request_shutdown", lambda contract: None)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda contract: None)
    monkeypatch.setattr(
        "soul_platform.autostart._authenticated_probe",
        lambda contract: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    with pytest.raises(RuntimeError, match="probe failed"):
        activate_descriptor(contract, "windows", home=home)
    assert len(commands) == 3
    rollback = scripts[2]
    assert "Unregister-ScheduledTask" in rollback
    assert legacy.exists()


def test_windows_unregister_failure_retains_descriptor(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "windows", home=home)

    def fail_remove(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "powershell.exe")

    monkeypatch.setattr("soul_platform.autostart._run", fail_remove)
    with pytest.raises(subprocess.CalledProcessError):
        deactivate_descriptor(contract, "windows", home=home)
    assert target.exists()


def test_windows_probe_failure_does_not_hide_rollback_failure(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "windows", home=home)
    calls = 0

    def fail_rollback(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return SimpleNamespace(
                returncode=0,
                stdout="SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML=\n",
            )
        if calls == 2:
            return SimpleNamespace(returncode=0, stdout="")
        raise subprocess.CalledProcessError(1, "powershell.exe")

    monkeypatch.setattr("soul_platform.autostart._run", fail_rollback)
    monkeypatch.setattr("soul_platform.autostart._request_shutdown", lambda contract: None)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda contract: None)
    monkeypatch.setattr(
        "soul_platform.autostart._authenticated_probe",
        lambda contract: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    with pytest.raises(subprocess.CalledProcessError):
        activate_descriptor(contract, "windows", home=home)
    assert target.exists()


def test_windows_task_receipt_is_fail_closed_and_restored_task_is_started(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    from soul_platform.autostart import _previous_windows_task, _windows_task_script

    with pytest.raises(RuntimeError, match="marker"):
        _previous_windows_task("SOUL_PREVIOUS_TASK_XML=")
    with pytest.raises(RuntimeError, match="incomplete"):
        _previous_windows_task("SOUL_TASK_RECEIPT_V1")

    xml = "<Task><Principals /></Task>"
    encoded = base64.b64encode(xml.encode("utf-16le")).decode("ascii")
    assert _previous_windows_task(
        f"SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML={encoded}\n"
    ) == xml
    rollback = _windows_task_script(contract, action="rollback", previous_xml=xml)
    assert "Register-ScheduledTask" in rollback
    assert "Start-ScheduledTask" in rollback


def test_windows_invalid_snapshot_receipt_mutates_nothing(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    install_descriptor(contract, "windows", home=home)
    commands = []
    scripts = []
    shutdown = []

    def bad_snapshot(command, **kwargs):
        commands.append(command)
        scripts.append(kwargs.get("input_text", ""))
        return SimpleNamespace(returncode=0, stdout="truncated")

    monkeypatch.setattr("soul_platform.autostart._run", bad_snapshot)
    monkeypatch.setattr(
        "soul_platform.autostart._request_shutdown", lambda contract: shutdown.append(True)
    )
    with pytest.raises(RuntimeError, match="receipt marker"):
        activate_descriptor(contract, "windows", home=home)
    assert len(commands) == 1
    snapshot = scripts[0]
    assert "Export-ScheduledTask" in snapshot
    assert "Register-ScheduledTask" not in snapshot
    assert shutdown == []


def test_shutdown_timeout_defers_to_port_stop_verification(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    from soul_platform.autostart import _request_shutdown

    monkeypatch.setattr(
        "soul_platform.autostart._local_urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("slow shutdown")),
    )
    # A timed-out response is ambiguous: caller must continue to _wait_stopped.
    # The request helper therefore returns without misreporting success/failure.
    assert _request_shutdown(contract) is None


def test_authenticated_control_requests_ignore_proxy_environment(tmp_path, monkeypatch):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        unavailable_port = reservation.getsockname()[1]
    contract = _contract(tmp_path, monkeypatch, port=unavailable_port)
    from soul_platform.autostart import _authenticated_probe, _request_shutdown

    trap, thread = _start_proxy_trap(monkeypatch)
    try:
        with pytest.raises(RuntimeError, match="failed authenticated startup probe"):
            _authenticated_probe(contract, timeout_seconds=0.05)
        assert _request_shutdown(contract) is None
    finally:
        trap.shutdown()
        thread.join(timeout=2)
        trap.server_close()
    assert _ProxyTrap.captured == []


def test_windows_large_previous_xml_uses_stdin_and_recovers_launch_failure(
    tmp_path, monkeypatch
):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    install_descriptor(contract, "windows", home=home)
    previous_xml = "<Task>" + ("x" * 100_000) + "</Task>"
    encoded = base64.b64encode(previous_xml.encode("utf-16le")).decode("ascii")
    calls = []

    def transport(command, **kwargs):
        calls.append((command, kwargs.get("input_text", "")))
        if len(calls) == 1:
            return SimpleNamespace(
                returncode=0,
                stdout=f"SOUL_TASK_RECEIPT_V1\nSOUL_PREVIOUS_TASK_XML={encoded}\n",
            )
        if len(calls) == 2:
            raise OSError("CreateProcess failed")
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr("soul_platform.autostart._run", transport)
    monkeypatch.setattr("soul_platform.autostart._request_shutdown", lambda contract: None)
    monkeypatch.setattr("soul_platform.autostart._wait_stopped", lambda contract: None)
    with pytest.raises(OSError, match="CreateProcess"):
        activate_descriptor(contract, "windows", home=home)
    assert len(calls) == 3
    assert all(sum(len(part) for part in command) < 256 for command, _script in calls)
    assert len(calls[1][1]) > 100_000
    assert "Register-ScheduledTask" in calls[2][1]
    assert "Start-ScheduledTask" in calls[2][1]


def test_failed_stop_retains_descriptor(tmp_path, monkeypatch):
    contract = _contract(tmp_path, monkeypatch)
    home = tmp_path / "home"
    target = install_descriptor(contract, "linux", home=home)
    monkeypatch.setattr(
        "soul_platform.autostart._run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1),
    )
    with pytest.raises(RuntimeError, match="descriptor retained"):
        deactivate_descriptor(contract, "linux", home=home)
    assert target.exists()
