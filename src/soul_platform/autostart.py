"""Per-user autostart descriptors for the local SOUL Proxy.

This module deliberately does not install Python, elevate privileges, delete
data, or start an unauthenticated proxy.  It only writes an OS-native per-user
descriptor after the proxy configuration proves the minimum security contract.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import plistlib
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from soul_platform.proxy import (
    ProxySettings,
    _assert_no_symlink_components,
)


PlatformName = Literal["linux", "windows", "macos"]
WINDOWS_TASK_NAME = "SOUL Platform"


def _loopback_base_url(host: str, port: int) -> str:
    """Build a valid HTTP origin for a validated literal loopback address."""
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"http://{authority}:{port}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _local_urlopen(request: urllib.request.Request, *, timeout: float):
    """Open a literal-loopback control request without ambient proxies/redirects."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()
    )
    return opener.open(request, timeout=timeout)


def _clean_path(value: object, field: str) -> Path:
    text = str(value or "")
    if not text or any(char in text for char in ("\x00", "\r", "\n")):
        raise ValueError(f"{field} must be a non-empty path without control characters")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    return path


@dataclass(frozen=True)
class AutostartContract:
    config: Path
    soul_db: Path
    token_file: Path
    host: str
    port: int
    python: Path
    upstream_model: str

    @classmethod
    def load(cls, config_path: str | os.PathLike[str], *, python: str | None = None):
        config = _clean_path(config_path, "config")
        settings = ProxySettings.from_toml(config)
        executable = _clean_path(python or sys.executable, "python")
        if not executable.is_file():
            raise ValueError("python executable does not exist")
        return cls(
            config=config,
            soul_db=settings.soul_db,
            token_file=settings.token_file,
            host=settings.host,
            port=settings.port,
            python=executable,
            upstream_model=settings.upstream_model,
        )

    @property
    def command(self) -> tuple[str, ...]:
        return (str(self.python), "-m", "soul_platform.proxy", "--config", str(self.config))


def _systemd_quote(value: str) -> str:
    escaped = value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


def render_linux(contract: AutostartContract) -> bytes:
    command = " ".join(_systemd_quote(value) for value in contract.command)
    writable = _systemd_quote(str(contract.soul_db.parent))
    return (
        "[Unit]\nDescription=SOUL Proxy - persistent machine soul\nAfter=network.target\n\n"
        "[Service]\nType=simple\n"
        f"ExecStart={command}\nRestart=on-failure\nRestartSec=3\n"
        "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n"
        f"ReadWritePaths={writable}\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\n"
        "[Install]\nWantedBy=default.target\n"
    ).encode()


def _vbs_string(value: str) -> str:
    if any(char in value for char in ("\x00", "\r", "\n")):
        raise ValueError("unsafe control character in Windows launcher value")
    return value.replace('"', '""')


def render_windows(contract: AutostartContract) -> bytes:
    python = contract.python.with_name("pythonw.exe")
    if not python.exists():
        python = contract.python
    return json.dumps(
        {
            "schema": "soul.windows-autostart.v2",
            "task_name": WINDOWS_TASK_NAME,
            "executable": str(python),
            "arguments": [
                "-m",
                "soul_platform.proxy",
                "--config",
                str(contract.config),
            ],
            "logon_type": "InteractiveToken",
            "run_level": "LeastPrivilege",
            "hidden": True,
            "restart_count": 3,
            "restart_interval_seconds": 60,
        },
        sort_keys=True,
    ).encode("utf-8")


def render_macos(contract: AutostartContract) -> bytes:
    payload = {
        "Label": "com.soul.platform.proxy",
        "ProgramArguments": list(contract.command),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Interactive",
        "StandardOutPath": str(contract.soul_db.parent / "proxy.stdout.log"),
        "StandardErrorPath": str(contract.soul_db.parent / "proxy.stderr.log"),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def descriptor_path(platform: PlatformName, home: Path) -> Path:
    if platform == "linux":
        return home / ".config" / "systemd" / "user" / "soul-platform-proxy.service"
    if platform == "windows":
        return home / "AppData" / "Local" / "SOUL" / "autostart-task.json"
    if platform == "macos":
        return home / "Library" / "LaunchAgents" / "com.soul.platform.proxy.plist"
    raise ValueError(f"unsupported platform: {platform}")


def _safe_descriptor_parent(target: Path, home: Path) -> None:
    _assert_no_symlink_components(home, "home")
    home.mkdir(parents=True, exist_ok=True)
    current = home
    relative = target.parent.relative_to(home)
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("autostart path contains a symlinked directory")
        current.mkdir(exist_ok=True)
        if not current.is_dir():
            raise ValueError("autostart parent is not a directory")


def install_descriptor(contract: AutostartContract, platform: PlatformName, *, home: Path | None = None) -> Path:
    requested_home = (home or Path.home()).expanduser()
    _assert_no_symlink_components(requested_home, "home")
    resolved_home = requested_home.resolve()
    target = descriptor_path(platform, resolved_home)
    _safe_descriptor_parent(target, resolved_home)
    if target.is_symlink():
        raise ValueError("refusing to replace a symlinked autostart descriptor")
    payload = {
        "linux": render_linux,
        "windows": render_windows,
        "macos": render_macos,
    }[platform](contract)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def _descriptor_snapshot(target: Path) -> tuple[bytes, int] | None:
    """Capture the exact managed descriptor before a product-level upgrade."""
    if target.is_symlink():
        raise ValueError("refusing to snapshot a symlinked autostart descriptor")
    if not target.exists():
        return None
    if not target.is_file():
        raise ValueError("autostart descriptor is not a regular file")
    return target.read_bytes(), stat.S_IMODE(target.stat().st_mode)


def _restore_descriptor(target: Path, snapshot: tuple[bytes, int]) -> None:
    """Atomically restore the descriptor bytes and mode captured before upgrade."""
    if target.is_symlink():
        raise ValueError("refusing to restore over a symlinked autostart descriptor")
    payload, mode = snapshot
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.rollback.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _require_linux_user_manager() -> None:
    """Fail before writing a unit when no usable per-user systemd exists."""
    if shutil.which("systemctl") is None:
        raise RuntimeError(
            "systemd user manager is unavailable; use --no-autostart for an "
            "explicit on-demand runtime"
        )
    probe = _run(["systemctl", "--user", "show-environment"], check=False)
    if probe.returncode != 0:
        raise RuntimeError(
            "systemd user manager is not running; use --no-autostart for an "
            "explicit on-demand runtime"
        )


def _remove_failed_fresh_descriptor(
    contract: AutostartContract,
    platform: PlatformName,
    *,
    home: Path | None = None,
) -> None:
    """Disable a failed first install before removing its new descriptor."""
    resolved_home = (home or Path.home()).expanduser().resolve()
    target = descriptor_path(platform, resolved_home)
    if platform == "linux":
        try:
            stopped = _run(
                ["systemctl", "--user", "stop", target.name],
                check=False,
            )
        except OSError:
            stopped = None
        if stopped is None or stopped.returncode != 0:
            _request_shutdown(contract)
        _wait_stopped(contract)
        try:
            _run(
                ["systemctl", "--user", "disable", target.name],
                check=False,
            )
        except OSError:
            pass
        disable_descriptor(platform, home=resolved_home)
        try:
            _run(["systemctl", "--user", "daemon-reload"], check=False)
        except OSError:
            pass
    elif platform == "macos":
        _run(
            ["launchctl", "bootout", f"gui/{os.getuid()}", str(target)],
            check=False,
        )
        _wait_stopped(contract)
        disable_descriptor(platform, home=resolved_home)
    elif platform == "windows":
        # activate_descriptor owns the Scheduled Task snapshot/rollback.  The
        # JSON descriptor is only removed after that rollback succeeded.
        disable_descriptor(platform, home=resolved_home)
    else:
        raise ValueError(f"unsupported platform: {platform}")


def install_and_activate_descriptor(
    contract: AutostartContract,
    platform: PlatformName,
    *,
    home: Path | None = None,
) -> Path:
    """Transactionally replace and activate the product autostart descriptor.

    Linux/macOS restore and reactivate the exact prior descriptor on failure.
    A failed fresh install is disabled and removed.  Windows keeps its native
    Scheduled Task rollback inside :func:`activate_descriptor`; this wrapper
    only makes the companion JSON descriptor agree with the rolled-back task.
    """
    requested_home = (home or Path.home()).expanduser()
    _assert_no_symlink_components(requested_home, "home")
    resolved_home = requested_home.resolve()
    target = descriptor_path(platform, resolved_home)
    if platform == "linux":
        _require_linux_user_manager()
    _safe_descriptor_parent(target, resolved_home)
    previous = _descriptor_snapshot(target)
    install_descriptor(contract, platform, home=resolved_home)
    try:
        return activate_descriptor(contract, platform, home=resolved_home)
    except Exception as activation_error:
        # When the native Windows task rollback itself failed, its live state
        # is ambiguous.  Retaining the new descriptor is safer than claiming
        # the old descriptor is active; direct activate_descriptor tests cover
        # this fail-closed branch.
        if platform == "windows" and getattr(
            activation_error, "_soul_windows_task_rollback_failed", False
        ):
            raise
        try:
            if previous is None:
                _remove_failed_fresh_descriptor(
                    contract, platform, home=resolved_home
                )
            else:
                _restore_descriptor(target, previous)
                if platform in ("linux", "macos"):
                    activate_descriptor(
                        contract, platform, home=resolved_home, wait=False
                    )
        except Exception as rollback_error:
            raise RuntimeError(
                "autostart activation failed and descriptor rollback also failed"
            ) from rollback_error
        raise


def disable_descriptor(platform: PlatformName, *, home: Path | None = None) -> Path:
    """Disable autostart only. Soul data, config, token and venv are preserved."""
    requested_home = (home or Path.home()).expanduser()
    _assert_no_symlink_components(requested_home, "home")
    target = descriptor_path(platform, requested_home.resolve())
    _assert_no_symlink_components(target.parent, "autostart path")
    if target.exists() and not target.is_symlink():
        target.unlink()
    elif target.is_symlink():
        raise ValueError("refusing to remove a symlinked autostart descriptor")
    return target


def _run(
    command: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        input=input_text,
        capture_output=True,
        timeout=30,
    )


def _powershell_literal(value: str) -> str:
    if any(char in value for char in ("\x00", "\r", "\n")):
        raise ValueError("unsafe control character in PowerShell value")
    return "'" + value.replace("'", "''") + "'"


def _powershell_stdin() -> list[str]:
    """Use a fixed short argv; task XML travels over stdin, not CreateProcess argv."""
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "-",
    ]


def _windows_task_script(
    contract: AutostartContract,
    *,
    action: str,
    previous_xml: str = "",
) -> str:
    task = _powershell_literal(WINDOWS_TASK_NAME)
    identity = (
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$sid=$identity.User.Value;"
        "if($sid -eq 'S-1-5-18'){throw 'SYSTEM identity is forbidden'};"
    )
    if action == "remove":
        return (
            "$ErrorActionPreference='Stop';"
            + identity
            +
            f"$task=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
            "if($task){"
            f"Stop-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
            f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false"
            "};"
            f"if(Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue){{"
            "throw 'SOUL scheduled task removal could not be verified'"
            "}"
        )
    if action == "rollback":
        encoded_xml = base64.b64encode(previous_xml.encode("utf-16le")).decode("ascii")
        xml_literal = _powershell_literal(encoded_xml)
        restore = ""
        if previous_xml:
            restore = (
                f"$xml=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String({xml_literal}));"
                f"Register-ScheduledTask -TaskName {task} -Xml $xml -Force | Out-Null;"
                f"Start-ScheduledTask -TaskName {task};"
            )
        return (
            "$ErrorActionPreference='Stop';"
            + identity
            +
            f"$current=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
            "if($current){"
            f"Stop-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
            f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false"
            "};"
            + restore
            + (
                f"if(-not (Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue)){{"
                "throw 'SOUL scheduled task rollback restore could not be verified'"
                "}"
                if previous_xml
                else f"if(Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue){{"
                "throw 'SOUL scheduled task rollback removal could not be verified'"
                "}"
            )
        )
    if action == "snapshot":
        return (
            "$ErrorActionPreference='Stop';"
            + identity
            + f"$old=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
            "$oldXml='';"
            "if($old){$oldXml=Export-ScheduledTask -TaskName $old.TaskName};"
            "$oldEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($oldXml));"
            "Write-Output 'SOUL_TASK_RECEIPT_V1';"
            "Write-Output ('SOUL_PREVIOUS_TASK_XML='+$oldEncoded)"
        )
    if action != "register":
        raise ValueError("unsupported Windows task action")
    python = contract.python.with_name("pythonw.exe")
    if os.name == "nt" and not python.is_file():
        raise RuntimeError("pythonw.exe is required for hidden Windows autostart")
    if not python.is_file():
        python = contract.python
    executable = _powershell_literal(str(python))
    arguments = _powershell_literal(
        subprocess.list2cmdline(
            ["-m", "soul_platform.proxy", "--config", str(contract.config)]
        )
    )
    encoded_previous = base64.b64encode(previous_xml.encode("utf-16le")).decode("ascii")
    previous_literal = _powershell_literal(encoded_previous)
    return (
        "$ErrorActionPreference='Stop';"
        + identity
        + f"$oldXml=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String({previous_literal}));"
        f"$action=New-ScheduledTaskAction -Execute {executable} -Argument {arguments};"
        "$trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid;"
        "$settings=New-ScheduledTaskSettingsSet -Hidden -RestartCount 3 "
        "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable "
        "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero);"
        "$principal=New-ScheduledTaskPrincipal -UserId $sid "
        "-LogonType Interactive -RunLevel Limited;"
        "$definition=New-ScheduledTask -Action $action -Trigger $trigger "
        "-Settings $settings -Principal $principal;"
        "try{"
        f"Register-ScheduledTask -TaskName {task} -InputObject $definition -Force | Out-Null;"
        f"Start-ScheduledTask -TaskName {task}"
        "}catch{"
        f"$new=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        "if($new){"
        f"Stop-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false"
        "};"
        "if($oldXml){"
        f"Register-ScheduledTask -TaskName {task} -Xml $oldXml -Force | Out-Null;"
        f"Start-ScheduledTask -TaskName {task}"
        "};throw}"
    )


def _previous_windows_task(stdout: str) -> str:
    lines = str(stdout or "").splitlines()
    if "SOUL_TASK_RECEIPT_V1" not in lines:
        raise RuntimeError("missing Windows task rollback receipt marker")
    fields = {}
    for line in lines:
        if line.startswith("SOUL_PREVIOUS_TASK_") and "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value.strip()
    if "SOUL_PREVIOUS_TASK_XML" not in fields:
        raise RuntimeError("incomplete Windows task rollback receipt")
    encoded = fields["SOUL_PREVIOUS_TASK_XML"]
    try:
        xml = base64.b64decode(encoded, validate=True).decode("utf-16le") if encoded else ""
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("invalid Windows task rollback receipt") from exc
    return xml


def _legacy_windows_descriptor(home: Path) -> Path:
    return (
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


def _authenticated_probe(contract: AutostartContract, *, timeout_seconds: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    token = contract.token_file.read_text(encoding="utf-8").strip()
    base_url = _loopback_base_url(contract.host, contract.port)
    models_request = urllib.request.Request(
        f"{base_url}/v1/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    ready_request = urllib.request.Request(f"{base_url}/ready")
    last_error = "not started"
    while time.monotonic() < deadline:
        try:
            with _local_urlopen(models_request, timeout=1) as response:
                models_payload = json.loads(response.read())
            with _local_urlopen(ready_request, timeout=1) as ready_response:
                ready_payload = json.loads(ready_response.read())
            models = models_payload.get("data") if models_payload.get("object") == "list" else []
            if response.status == 200 and ready_response.status == 200 and ready_payload.get("ready") is True and any(
                item.get("id") == contract.upstream_model for item in models if isinstance(item, dict)
            ):
                return
            last_error = f"unexpected health response {response.status}"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise RuntimeError(f"SOUL proxy failed authenticated startup probe: {last_error}")


def activate_descriptor(
    contract: AutostartContract,
    platform: PlatformName,
    *,
    home: Path | None = None,
    wait: bool = True,
) -> Path:
    """Enable and start the per-user service without elevation or shell parsing."""
    target = descriptor_path(platform, (home or Path.home()).expanduser().resolve())
    if not target.is_file() or target.is_symlink():
        raise ValueError("autostart descriptor is missing or unsafe")
    if platform == "linux":
        _run(["systemctl", "--user", "daemon-reload"])
        _run(["systemctl", "--user", "enable", "--now", target.name])
        # Converge upgrades too: enable --now does not replace an already-live
        # process whose package bytes changed.
        _run(["systemctl", "--user", "restart", target.name])
    elif platform == "macos":
        domain = f"gui/{os.getuid()}"
        _run(["launchctl", "bootout", domain, str(target)], check=False)
        _run(["launchctl", "bootstrap", domain, str(target)])
        _run(["launchctl", "kickstart", "-k", f"{domain}/com.soul.platform.proxy"])
    elif platform == "windows":
        shell_command = _powershell_stdin()
        snapshot_script = _windows_task_script(contract, action="snapshot")
        snapshot = _run(shell_command, input_text=snapshot_script)
        previous_xml = _previous_windows_task(getattr(snapshot, "stdout", ""))
        register_script = _windows_task_script(
            contract,
            action="register",
            previous_xml=previous_xml,
        )
        rollback_script = _windows_task_script(
            contract,
            action="rollback",
            previous_xml=previous_xml,
        )
        _request_shutdown(contract)
        _wait_stopped(contract)
        try:
            _run(shell_command, input_text=register_script)
        except Exception:
            try:
                _run(shell_command, input_text=rollback_script)
            except Exception as rollback_error:
                setattr(rollback_error, "_soul_windows_task_rollback_failed", True)
                raise
            raise
    else:
        raise ValueError(f"unsupported platform: {platform}")
    try:
        if wait:
            _authenticated_probe(contract)
    except Exception:
        if platform == "windows":
            try:
                _run(_powershell_stdin(), input_text=rollback_script)
            except Exception as rollback_error:
                setattr(rollback_error, "_soul_windows_task_rollback_failed", True)
                raise
        raise
    if platform == "windows":
        legacy = _legacy_windows_descriptor((home or Path.home()).expanduser().resolve())
        if legacy.is_symlink():
            raise ValueError("refusing to remove a symlinked legacy autostart descriptor")
        if legacy.is_file():
            legacy.unlink()
    return target


def _request_shutdown(contract: AutostartContract) -> None:
    token = contract.token_file.read_text(encoding="utf-8").strip()
    request = urllib.request.Request(
        f"{_loopback_base_url(contract.host, contract.port)}/admin/shutdown",
        method="POST",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with _local_urlopen(request, timeout=2) as response:
            if response.status != 200:
                raise RuntimeError(f"shutdown returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"shutdown returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        return


def _wait_stopped(contract: AutostartContract, *, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((contract.host, contract.port), timeout=0.5):
                pass
        except OSError:
            return
        time.sleep(0.2)
    raise RuntimeError("SOUL proxy did not stop; autostart descriptor retained")


def deactivate_descriptor(
    contract: AutostartContract,
    platform: PlatformName,
    *,
    home: Path | None = None,
) -> Path:
    """Stop the managed proxy, disable autostart, and preserve all soul data."""
    target = descriptor_path(platform, (home or Path.home()).expanduser().resolve())
    if platform == "linux":
        stopped = _run(["systemctl", "--user", "disable", "--now", target.name], check=False)
        if stopped.returncode != 0:
            raise RuntimeError(f"systemctl failed to stop {target.name}; descriptor retained")
        _wait_stopped(contract)
        _run(["systemctl", "--user", "daemon-reload"])
    elif platform == "macos":
        stopped = _run(["launchctl", "bootout", f"gui/{os.getuid()}", str(target)], check=False)
        if stopped.returncode != 0:
            raise RuntimeError("launchctl failed to stop SOUL proxy; descriptor retained")
        _wait_stopped(contract)
    elif platform == "windows":
        _run(
            _powershell_stdin(),
            input_text=_windows_task_script(contract, action="remove"),
        )
        _request_shutdown(contract)
        _wait_stopped(contract)
    return disable_descriptor(platform, home=home)


def stop_descriptor(
    contract: AutostartContract,
    platform: PlatformName,
    *,
    home: Path | None = None,
) -> None:
    """Stop the proxy without deleting its login-time autostart descriptor.

    This is the reversible operation used by the tray UI.  It must never
    remove identity, memory, token, configuration, or the descriptor itself.
    A later :func:`activate_descriptor` starts the same machine soul again.
    """

    target = descriptor_path(platform, (home or Path.home()).expanduser().resolve())
    if not target.is_file() or target.is_symlink():
        raise RuntimeError("cannot stop an unmanaged SOUL proxy")
    if platform == "linux":
        stopped = _run(["systemctl", "--user", "stop", target.name], check=False)
        if stopped.returncode != 0:
            raise RuntimeError(f"systemctl failed to stop {target.name}")
    elif platform == "macos":
        stopped = _run(
            ["launchctl", "bootout", f"gui/{os.getuid()}", str(target)],
            check=False,
        )
        if stopped.returncode != 0:
            raise RuntimeError("launchctl failed to stop SOUL proxy")
    elif platform == "windows":
        _request_shutdown(contract)
    else:
        raise ValueError(f"unsupported platform: {platform}")
    _wait_stopped(contract)


def restart_descriptor(
    contract: AutostartContract,
    platform: PlatformName,
    *,
    home: Path | None = None,
) -> None:
    target = descriptor_path(platform, (home or Path.home()).expanduser().resolve())
    if not target.is_file() or target.is_symlink():
        raise RuntimeError("cannot switch a running brain without a managed autostart service")
    if platform == "linux":
        _run(["systemctl", "--user", "restart", target.name])
    elif platform == "macos":
        _run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/com.soul.platform.proxy"])
    elif platform == "windows":
        _request_shutdown(contract)
        _wait_stopped(contract)
        activate_descriptor(contract, platform, home=home, wait=False)
    _authenticated_probe(contract)


def _current_platform() -> PlatformName:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if os.name == "nt":
        return "windows"
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m soul_platform.autostart")
    actions = parser.add_subparsers(dest="action", required=True)
    install = actions.add_parser("install")
    install.add_argument("--config", required=True)
    install.add_argument("--python")
    actions.add_parser("disable")
    args = parser.parse_args()
    platform = _current_platform()
    if args.action == "install":
        target = install_descriptor(
            AutostartContract.load(args.config, python=args.python), platform
        )
        print(f"autostart installed: {target}")
    else:
        target = disable_descriptor(platform)
        print(f"autostart disabled; soul data preserved: {target}")


if __name__ == "__main__":
    main()
