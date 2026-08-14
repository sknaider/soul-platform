"""Native system-tray controller for the persistent machine soul.

The tray is deliberately a thin local control surface.  It never owns the
proxy process, identity, token, or memory database; those remain under the
verified bootstrap/autostart contracts.  Closing the tray therefore cannot
silently kill or replace the machine soul.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from soul_platform.autostart import (
    AutostartContract,
    PlatformName,
    _current_platform,
    _powershell_literal,
    _powershell_stdin,
    _previous_windows_task,
    _run,
    install_and_activate_descriptor,
    stop_descriptor,
)
from soul_platform.bootstrap import _atomic_config, default_root, initialize, switch_upstream
from soul_platform.proxy import ProxySettings


OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
MAX_DISCOVERY_BYTES = 1_048_576
MAX_DISCOVERED_MODELS = 100
TRAY_TASK_NAME = "SOUL Tray"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _local_urlopen(request: urllib.request.Request, *, timeout: float):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()
    )
    return opener.open(request, timeout=timeout)


@dataclass(frozen=True)
class TrayStatus:
    installed: bool
    running: bool
    ready: bool
    model: str | None
    endpoint: str
    machine_soul_id: str | None
    detail: str


def _read_bounded(response: Any, limit: int = MAX_DISCOVERY_BYTES) -> bytes:
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("response exceeds the tray discovery limit")
    return raw


def discover_ollama_models(
    *,
    timeout: float = 2.0,
    opener: Callable[..., Any] = _local_urlopen,
) -> list[str]:
    """Return a bounded, normalized model list from loopback Ollama only."""

    request = urllib.request.Request(OLLAMA_TAGS_URL, method="GET")
    try:
        with opener(request, timeout=timeout) as response:
            if int(getattr(response, "status", 200)) != 200:
                return []
            payload = json.loads(_read_bounded(response))
    except (OSError, ValueError, TypeError, json.JSONDecodeError, urllib.error.URLError):
        return []
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for item in models[:MAX_DISCOVERED_MODELS]:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str):
            continue
        name = name.strip()
        if (
            not name
            or len(name) > 256
            or any(character in name for character in ("\x00", "\r", "\n"))
            or name in seen
        ):
            continue
        seen.add(name)
        result.append(name)
    return result


class SoulTrayController:
    """Safe controller around the existing bootstrap/autostart contracts."""

    def __init__(
        self,
        *,
        config: Path | None = None,
        platform: PlatformName | None = None,
        home: Path | None = None,
        opener: Callable[..., Any] = _local_urlopen,
    ) -> None:
        self.platform = platform or _current_platform()
        self.home = (home or Path.home()).expanduser().resolve()
        self.config = (config or (default_root(self.platform, home=self.home) / "proxy.toml")).expanduser().resolve()
        self.opener = opener

    def _settings(self) -> ProxySettings | None:
        if not self.config.is_file() or self.config.is_symlink():
            return None
        return ProxySettings.from_toml(self.config)

    @staticmethod
    def _endpoint(settings: ProxySettings | None) -> str:
        host = settings.host if settings else "127.0.0.1"
        port = settings.port if settings else 11435
        display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return f"http://{display_host}:{port}/v1"

    def _json_get(self, url: str, *, timeout: float = 1.0) -> tuple[int, dict[str, Any]]:
        try:
            with self.opener(urllib.request.Request(url, method="GET"), timeout=timeout) as response:
                raw = _read_bounded(response, 256 * 1024)
                payload = json.loads(raw)
                return int(getattr(response, "status", 200)), payload if isinstance(payload, dict) else {}
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(_read_bounded(exc, 256 * 1024))
            except Exception:
                payload = {}
            return int(exc.code), payload if isinstance(payload, dict) else {}
        except (OSError, ValueError, TypeError, json.JSONDecodeError, urllib.error.URLError):
            return 0, {}

    def status(self) -> TrayStatus:
        settings = self._settings()
        endpoint = self._endpoint(settings)
        if settings is None:
            return TrayStatus(False, False, False, None, endpoint, None, "SOUL no está inicializado")
        base = endpoint.removesuffix("/v1")
        health_code, health = self._json_get(base + "/health")
        ready_code, ready = self._json_get(base + "/ready")
        running = health_code == 200 and health.get("ok") is True
        ready_now = running and ready_code == 200 and ready.get("ready") is True
        detail = "Alma activa" if ready_now else ("Alma activa; cerebro no disponible" if running else "Alma detenida")
        return TrayStatus(
            True,
            running,
            ready_now,
            settings.upstream_model,
            endpoint,
            settings.machine_soul_id,
            detail,
        )

    def start(self, model: str | None = None) -> TrayStatus:
        settings = self._settings()
        if settings is None:
            if not model:
                raise RuntimeError("SOUL no está inicializado y no hay un modelo Ollama seleccionado")
            initialize(
                root=self.config.parent,
                upstream_kind="ollama",
                upstream_base_url=OLLAMA_BASE_URL,
                upstream_model=model,
                platform=self.platform,
                home=self.home,
            )
            return self.status()
        previous_config = self.config.read_text(encoding="utf-8")
        was_running = self.status().running
        switched = False
        if model and model != settings.upstream_model:
            settings = switch_upstream(
                self.config,
                upstream_kind="ollama",
                upstream_base_url=OLLAMA_BASE_URL,
                upstream_model=model,
                restart=False,
                platform=self.platform,
                home=self.home,
            )
            switched = True
        try:
            contract = AutostartContract.load(self.config)
            install_and_activate_descriptor(
                contract, self.platform, home=self.home
            )
        except Exception:
            if switched:
                _atomic_config(self.config, previous_config)
                previous_contract = AutostartContract.load(self.config)
                if was_running:
                    try:
                        install_and_activate_descriptor(
                            previous_contract, self.platform, home=self.home
                        )
                    except Exception:
                        pass
            raise
        return self.status()

    def stop(self) -> TrayStatus:
        settings = self._settings()
        if settings is None:
            raise RuntimeError("SOUL no está inicializado")
        stop_descriptor(
            AutostartContract.load(self.config),
            self.platform,
            home=self.home,
        )
        return self.status()

    def switch_model(self, model: str) -> TrayStatus:
        model = str(model or "").strip()
        if not model or len(model) > 256 or any(char in model for char in ("\x00", "\r", "\n")):
            raise ValueError("nombre de modelo inválido")
        settings = self._settings()
        if settings is None:
            return self.start(model)
        running = self.status().running
        switch_upstream(
            self.config,
            upstream_kind="ollama",
            upstream_base_url=OLLAMA_BASE_URL,
            upstream_model=model,
            restart=running,
            platform=self.platform,
            home=self.home,
        )
        return self.status()

    def models(self) -> list[str]:
        return discover_ollama_models(opener=self.opener)

    def copy_endpoint(self) -> bool:
        endpoint = self.status().endpoint
        try:
            if sys.platform.startswith("win"):
                subprocess.run(["clip.exe"], input=endpoint, text=True, check=True, timeout=5)
            elif sys.platform == "darwin":
                subprocess.run(["pbcopy"], input=endpoint, text=True, check=True, timeout=5)
            else:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=endpoint,
                    text=True,
                    check=True,
                    timeout=5,
                )
            return True
        except (OSError, subprocess.SubprocessError):
            return False


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


def _tray_receipt_path(platform: PlatformName, home: Path) -> Path:
    return default_root(platform, home=home) / "tray-autostart.json"


def _acquire_instance_lock(path: Path):
    """Hold a per-user, non-blocking lock so retries cannot duplicate the tray."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    handle = os.fdopen(fd, "r+b", buffering=0)
    try:
        if path.stat().st_size == 0:
            handle.write(b"\0")
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, PermissionError):
        handle.close()
        return None
    return handle


def _windows_tray_snapshot_script() -> str:
    task = _powershell_literal(TRAY_TASK_NAME)
    return (
        "$ErrorActionPreference='Stop';"
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$sid=$identity.User.Value;"
        "if($sid -eq 'S-1-5-18'){throw 'SYSTEM identity is forbidden'};"
        f"$old=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        "$oldXml='';if($old){$oldXml=Export-ScheduledTask -TaskName $old.TaskName};"
        "$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($oldXml));"
        "Write-Output 'SOUL_TASK_RECEIPT_V1';"
        "Write-Output ('SOUL_PREVIOUS_TASK_XML='+$encoded)"
    )


def _windows_tray_register_script(python: Path, config: Path, previous_xml: str) -> str:
    pythonw = python.with_name("pythonw.exe")
    if os.name == "nt" and not pythonw.is_file():
        raise RuntimeError("pythonw.exe is required for hidden SOUL Tray autostart")
    if not pythonw.is_file():
        pythonw = python
    task = _powershell_literal(TRAY_TASK_NAME)
    executable = _powershell_literal(str(pythonw))
    arguments = _powershell_literal(
        subprocess.list2cmdline(["-m", "soul_platform.tray", "--config", str(config)])
    )
    previous = _powershell_literal(
        base64.b64encode(previous_xml.encode("utf-16le")).decode("ascii")
    )
    return (
        "$ErrorActionPreference='Stop';"
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$sid=$identity.User.Value;"
        "if($sid -eq 'S-1-5-18'){throw 'SYSTEM identity is forbidden'};"
        f"$oldXml=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String({previous}));"
        f"$action=New-ScheduledTaskAction -Execute {executable} -Argument {arguments};"
        "$trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid;"
        "$settings=New-ScheduledTaskSettingsSet -Hidden -RestartCount 3 "
        "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable "
        "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;"
        "$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited;"
        "$definition=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal;"
        "try{"
        f"if($oldXml){{Stop-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        "Start-Sleep -Milliseconds 250};"
        f"Register-ScheduledTask -TaskName {task} -InputObject $definition -Force | Out-Null;"
        f"$task=Get-ScheduledTask -TaskName {task};"
        "$principalId=[string]$task.Principal.UserId;"
        "try{"
        "if($principalId -match '^S-1-'){$taskSid=$principalId}"
        "else{$taskSid=(New-Object Security.Principal.NTAccount($principalId))."
        "Translate([Security.Principal.SecurityIdentifier]).Value}"
        "}catch{throw 'SOUL Tray task principal identity could not be verified'};"
        "$runLevel=[string]$task.Principal.RunLevel;"
        "if($taskSid -ne $sid -or $taskSid -eq 'S-1-5-18' -or $runLevel -ne 'Limited'){"
        "throw 'SOUL Tray task principal verification failed'};"
        f"Start-ScheduledTask -TaskName {task}"
        "}catch{"
        f"$new=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        f"if($new){{Unregister-ScheduledTask -TaskName {task} -Confirm:$false}};"
        f"if($oldXml){{Register-ScheduledTask -TaskName {task} -Xml $oldXml -Force | Out-Null;"
        f"Start-ScheduledTask -TaskName {task};"
        f"if(-not (Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue)){{"
        "throw 'SOUL Tray task rollback restore could not be verified'}}"
        f"elseif(Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue){{"
        "throw 'SOUL Tray task rollback removal could not be verified'};"
        "throw}"
    )


def _windows_tray_remove_script() -> str:
    task = _powershell_literal(TRAY_TASK_NAME)
    return (
        "$ErrorActionPreference='Stop';"
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$sid=$identity.User.Value;"
        "if($sid -eq 'S-1-5-18'){throw 'SYSTEM identity is forbidden'};"
        f"$task=Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        f"if($task){{Stop-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue;"
        f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false}};"
        f"if(Get-ScheduledTask -TaskName {task} -ErrorAction SilentlyContinue){{"
        "throw 'SOUL Tray task removal could not be verified'}"
    )


def install_tray_autostart(
    *,
    config: Path,
    platform: PlatformName | None = None,
    home: Path | None = None,
    python: Path | None = None,
) -> Path:
    """Install least-privilege login autostart for the tray, never for SYSTEM."""

    platform = platform or _current_platform()
    home = (home or Path.home()).expanduser().resolve()
    python = (python or Path(sys.executable)).expanduser().resolve()
    config = config.expanduser().resolve()
    if not python.is_file():
        raise ValueError("tray python executable does not exist")
    receipt = _tray_receipt_path(platform, home)
    if platform == "windows":
        shell = _powershell_stdin()
        snapshot = _run(shell, input_text=_windows_tray_snapshot_script())
        previous_xml = _previous_windows_task(snapshot.stdout)
        _run(shell, input_text=_windows_tray_register_script(python, config, previous_xml))
        target = receipt
    elif platform == "linux":
        target = home / ".config" / "autostart" / "soul-tray.desktop"
        executable = str(python).replace("\\", "\\\\").replace('"', '\\"')
        config_arg = str(config).replace("\\", "\\\\").replace('"', '\\"')
        payload = (
            "[Desktop Entry]\nType=Application\nName=SOUL Tray\n"
            f'Exec="{executable}" -m soul_platform.tray --config "{config_arg}"\n'
            "Terminal=false\nX-GNOME-Autostart-enabled=true\n"
        ).encode()
        _atomic_private(target, payload)
    elif platform == "macos":
        target = home / "Library" / "LaunchAgents" / "com.soul.platform.tray.plist"
        _atomic_private(
            target,
            plistlib.dumps(
                {
                    "Label": "com.soul.platform.tray",
                    "ProgramArguments": [
                        str(python), "-m", "soul_platform.tray", "--config", str(config)
                    ],
                    "RunAtLoad": True,
                    "KeepAlive": False,
                    "ProcessType": "Interactive",
                },
                fmt=plistlib.FMT_XML,
                sort_keys=True,
            ),
        )
    else:
        raise ValueError(f"unsupported platform: {platform}")
    _atomic_private(
        receipt,
        (json.dumps(
            {
                "schema": "soul.tray-autostart.v1",
                "platform": platform,
                "target": str(target),
                "python": str(python),
                "config": str(config),
                "run_level": "LeastPrivilege",
            },
            sort_keys=True,
        ) + "\n").encode(),
    )
    return target


def remove_tray_autostart(
    *, platform: PlatformName | None = None, home: Path | None = None
) -> Path:
    platform = platform or _current_platform()
    home = (home or Path.home()).expanduser().resolve()
    receipt = _tray_receipt_path(platform, home)
    if platform == "windows":
        _run(_powershell_stdin(), input_text=_windows_tray_remove_script())
        target = receipt
    elif platform == "linux":
        target = home / ".config" / "autostart" / "soul-tray.desktop"
    elif platform == "macos":
        target = home / "Library" / "LaunchAgents" / "com.soul.platform.tray.plist"
    else:
        raise ValueError(f"unsupported platform: {platform}")
    for path in (target, receipt):
        if path.is_symlink():
            raise ValueError("refusing to remove a symlinked tray autostart artifact")
        if path.is_file():
            path.unlink()
    return target


def _icon_image():
    from PIL import Image, ImageDraw

    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((5, 5, 59, 59), fill=(124, 58, 237, 255))
    draw.ellipse((24, 24, 40, 40), fill=(255, 255, 255, 255))
    return image


class SoulTrayApplication:
    def __init__(self, controller: SoulTrayController, pystray_module: Any) -> None:
        self.controller = controller
        self.pystray = pystray_module
        self._busy = threading.Lock()
        self.icon = pystray_module.Icon(
            "soul-platform",
            _icon_image(),
            "SOUL — el alma de tu máquina",
        )
        self.icon.menu = self._menu()

    def _notify(self, message: str) -> None:
        self.icon.notify(str(message)[:300], "SOUL")

    def _background(self, operation: Callable[[], TrayStatus]) -> None:
        if not self._busy.acquire(blocking=False):
            self._notify("SOUL ya está procesando otra acción")
            return

        def run() -> None:
            try:
                status = operation()
                self._notify(status.detail)
            except Exception as exc:  # UI boundary: report without crashing the tray.
                self._notify(f"No pude completar la acción: {exc}")
            finally:
                self._busy.release()
                self.icon.menu = self._menu()
                self.icon.update_menu()

        threading.Thread(target=run, name="soul-tray-action", daemon=True).start()

    def _toggle(self, _icon: Any, _item: Any) -> None:
        status = self.controller.status()
        if status.running:
            self._background(self.controller.stop)
            return
        model = status.model
        if not model:
            models = self.controller.models()
            model = models[0] if models else None
        self._background(lambda: self.controller.start(model))

    def _select_model(self, model: str) -> Callable[[Any, Any], None]:
        return lambda _icon, _item: self._background(lambda: self.controller.switch_model(model))

    def _refresh(self, _icon: Any, _item: Any) -> None:
        self.icon.menu = self._menu()
        self.icon.update_menu()

    def _menu(self):
        status = self.controller.status()
        models = self.controller.models()
        Menu = self.pystray.Menu
        MenuItem = self.pystray.MenuItem
        status_label = (
            f"🟢 Alma activa · {status.model}" if status.ready
            else (f"🟡 Alma activa · cerebro sin respuesta ({status.model})" if status.running else "⚪ Alma detenida")
        )
        model_items = [
            MenuItem(
                model,
                self._select_model(model),
                checked=lambda _item, name=model: self.controller.status().model == name,
                radio=True,
            )
            for model in models
        ]
        if not model_items:
            model_items = [MenuItem("(Ollama sin modelos)", None, enabled=False)]
        return Menu(
            MenuItem(status_label, None, enabled=False),
            Menu.SEPARATOR,
            MenuItem("Prender / apagar alma", self._toggle),
            MenuItem("Elegir cerebro", Menu(*model_items)),
            MenuItem("Actualizar estado y modelos", self._refresh),
            MenuItem(
                f"Copiar endpoint ({status.endpoint})",
                lambda _icon, _item: self._notify(
                    "Endpoint copiado" if self.controller.copy_endpoint() else status.endpoint
                ),
            ),
            Menu.SEPARATOR,
            MenuItem("Salir de la bandeja (el alma sigue activa)", lambda icon, _item: icon.stop()),
        )

    def run(self) -> None:
        self.icon.run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-tray")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--headless-check", action="store_true")
    parser.add_argument("--install-autostart", action="store_true")
    parser.add_argument("--remove-autostart", action="store_true")
    args = parser.parse_args(argv)
    controller = SoulTrayController(config=args.config)
    if args.install_autostart and args.remove_autostart:
        parser.error("choose only one autostart action")
    if args.install_autostart:
        target = install_tray_autostart(config=controller.config)
        print(f"tray_autostart={target}")
        return 0
    if args.remove_autostart:
        target = remove_tray_autostart()
        print(f"tray_autostart_removed={target}")
        return 0
    if args.headless_check:
        payload = asdict(controller.status())
        payload["ollama_models"] = controller.models()
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    try:
        import pystray
        from PIL import Image  # noqa: F401 -- verify the complete desktop extra.
    except ImportError:
        print("Falta el extra de escritorio: pip install 'soul-platform[desktop]'", file=sys.stderr)
        return 2
    instance_lock = _acquire_instance_lock(controller.config.parent / ".soul-tray.lock")
    if instance_lock is None:
        return 0
    try:
        SoulTrayApplication(controller, pystray).run()
    finally:
        instance_lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
