from __future__ import annotations

import base64
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from soul_platform.autostart import (
    PlatformName,
    _current_platform,
    _powershell_literal,
    _powershell_stdin,
    _previous_windows_task,
    _run,
)

WINDOWS_TASK_NAME = "SOUL AutoWire"


def _atomic_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _windows_snapshot_script() -> str:
    task = _powershell_literal(WINDOWS_TASK_NAME)
    return (
        "$ErrorActionPreference='Stop';"
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$sid=$identity.User.Value;if($sid -eq 'S-1-5-18'){throw 'SYSTEM forbidden'};"
        f"$old=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        "$oldXml='';if($old){$oldXml=Export-ScheduledTask -TaskName $old.TaskName};"
        "$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($oldXml));"
        "Write-Output 'SOUL_TASK_RECEIPT_V1';"
        "Write-Output ('SOUL_PREVIOUS_TASK_XML='+$encoded)"
    )


def _windows_register_script(
    python: Path, root: Path, previous_xml: str, interval: float
) -> str:
    task = _powershell_literal(WINDOWS_TASK_NAME)
    executable_path = python.with_name("pythonw.exe")
    if os.name == "nt" and not executable_path.is_file():
        raise RuntimeError("pythonw.exe is required for hidden Windows AutoWire")
    if not executable_path.is_file():
        executable_path = python
    executable = _powershell_literal(str(executable_path))
    arguments = _powershell_literal(
        subprocess.list2cmdline(
            [
                "-m",
                "soul_platform.autowire.cli",
                "--root",
                str(root),
                "watch",
                "--interval",
                f"{interval:g}",
            ]
        )
    )
    previous = _powershell_literal(
        base64.b64encode(previous_xml.encode("utf-16le")).decode("ascii")
    )
    return (
        "$ErrorActionPreference='Stop';"
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$sid=$identity.User.Value;if($sid -eq 'S-1-5-18'){throw 'SYSTEM forbidden'};"
        f"$oldXml=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String({previous}));"
        f"$old=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        f"$action=New-ScheduledTaskAction -Execute {executable} -Argument {arguments};"
        "$trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid;"
        "$settings=New-ScheduledTaskSettingsSet -Hidden -RestartCount 3 "
        "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable "
        "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;"
        "$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited;"
        "$definition=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal;"
        "try{"
        f"if($old){{Stop-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue}};"
        f"Register-ScheduledTask -TaskName {task} -InputObject $definition -Force | Out-Null;"
        f"Start-ScheduledTask -TaskName {task};"
        f"$live=Get-ScheduledTask -TaskName {task};"
        "$principalId=[string]$live.Principal.UserId;"
        "if($principalId -match '^S-1-'){$taskSid=$principalId}else{"
        "$taskSid=(New-Object Security.Principal.NTAccount($principalId))."
        "Translate([Security.Principal.SecurityIdentifier]).Value};"
        "if($taskSid -ne $sid -or $taskSid -eq 'S-1-5-18' -or "
        "[string]$live.Principal.RunLevel -ne 'Limited'){throw 'AutoWire task principal verification failed'}"
        "}catch{"
        f"$new=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        f"if($new){{Unregister-ScheduledTask -TaskName {task} -Confirm:$false}};"
        f"if($oldXml){{Register-ScheduledTask -TaskName {task} -Xml $oldXml -Force | Out-Null}};"
        "throw}"
    )


def install_autowire_autostart(
    *,
    root: Path,
    platform: PlatformName | None = None,
    home: Path | None = None,
    python: Path | None = None,
    interval: float = 30.0,
) -> Path:
    if not 5 <= interval <= 3600:
        raise ValueError("watch interval must be between 5 and 3600 seconds")
    platform = platform or _current_platform()
    home = (home or Path.home()).expanduser().resolve()
    python = (python or Path(sys.executable)).expanduser().resolve()
    root = root.expanduser().resolve()
    if not python.is_file() or not (root / "proxy.toml").is_file():
        raise ValueError("AutoWire requires an installed SOUL runtime")
    receipt = root / "autowire-autostart.json"
    if platform == "windows":
        shell = _powershell_stdin()
        snapshot = _run(shell, input_text=_windows_snapshot_script())
        previous_xml = _previous_windows_task(snapshot.stdout)
        _run(
            shell,
            input_text=_windows_register_script(python, root, previous_xml, interval),
        )
        target = receipt
    elif platform == "linux":
        target = home / ".config" / "systemd" / "user" / "soul-autowire.service"
        systemctl = shutil.which("systemctl")
        if not systemctl:
            raise RuntimeError(
                "Linux AutoWire autostart requires a systemd user manager; "
                "shadow reconcile remains available and no unit was written"
            )
        manager = _run([systemctl, "--user", "show-environment"], check=False)
        if manager.returncode != 0:
            raise RuntimeError(
                "Linux AutoWire autostart requires a running systemd user manager; "
                "shadow reconcile remains available and no unit was written"
            )
        command = " ".join(
            '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
            for value in (
                str(python),
                "-m",
                "soul_platform.autowire.cli",
                "--root",
                str(root),
                "watch",
                "--interval",
                f"{interval:g}",
            )
        )
        previous = target.read_bytes() if target.is_file() else None
        previous_mode = (
            stat.S_IMODE(target.stat().st_mode) if previous is not None else None
        )
        previous_enabled = (
            _run(
                [systemctl, "--user", "is-enabled", target.name], check=False
            ).returncode
            == 0
            if previous is not None
            else False
        )
        previous_active = (
            _run(
                [systemctl, "--user", "is-active", target.name], check=False
            ).returncode
            == 0
            if previous is not None
            else False
        )
        try:
            _atomic_private(
                target,
                (
                    "[Unit]\nDescription=SOUL AutoWire local discovery\nAfter=soul-platform-proxy.service\n\n"
                    "[Service]\nType=simple\n"
                    + f"ExecStart={command}\nRestart=on-failure\nRestartSec=3\n"
                    "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n"
                    f'ReadWritePaths="{root}"\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\n'
                    "[Install]\nWantedBy=default.target\n"
                ).encode("utf-8"),
            )
            _run([systemctl, "--user", "daemon-reload"])
            _run([systemctl, "--user", "enable", "--now", target.name])
        except Exception as activation_error:
            rollback_errors = []
            for command in (
                [systemctl, "--user", "stop", target.name],
                [systemctl, "--user", "disable", target.name],
            ):
                try:
                    _run(command, check=False)
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    rollback_errors.append(exc)
            if previous is None:
                target.unlink(missing_ok=True)
            else:
                _atomic_private(target, previous)
                if previous_mode is not None:
                    target.chmod(previous_mode)
            try:
                _run([systemctl, "--user", "daemon-reload"])
                if previous_enabled:
                    _run([systemctl, "--user", "enable", target.name])
                if previous_active:
                    _run([systemctl, "--user", "start", target.name])
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                rollback_errors.append(exc)
            if rollback_errors:
                raise RuntimeError(
                    "AutoWire activation failed and native service rollback also failed"
                ) from rollback_errors[0]
            raise
    elif platform == "macos":
        target = home / "Library" / "LaunchAgents" / "com.soul.platform.autowire.plist"
        _atomic_private(
            target,
            plistlib.dumps(
                {
                    "Label": "com.soul.platform.autowire",
                    "ProgramArguments": [
                        str(python),
                        "-m",
                        "soul_platform.autowire.cli",
                        "--root",
                        str(root),
                        "watch",
                        "--interval",
                        f"{interval:g}",
                    ],
                    "RunAtLoad": True,
                    "KeepAlive": {"SuccessfulExit": False},
                    "ProcessType": "Background",
                },
                fmt=plistlib.FMT_XML,
                sort_keys=True,
            ),
        )
        _run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)])
    else:
        raise ValueError(f"unsupported platform: {platform}")
    _atomic_private(
        receipt,
        (
            json.dumps(
                {
                    "schema": "soul.autowire-autostart.v1",
                    "platform": platform,
                    "target": str(target),
                    "root": str(root),
                    "python": str(python),
                    "interval_seconds": interval,
                    "run_level": "LeastPrivilege",
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )
    return target
