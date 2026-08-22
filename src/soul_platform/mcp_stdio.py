"""Local stdio MCP bridge for official Codex/Claude client configuration.

The bridge never changes the selected model.  It exposes the installed machine
soul as explicit tools over a child process started by the client itself.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import ntpath
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from soul_framework import Soul
from soul_framework.config import SoulConfig

from soul_platform.proxy import ProxySettings


PROTOCOL_VERSION = "2025-06-18"
ALLOWED_CLIENTS = {"codex", "claude"}
ATTACH_TTL_SECONDS = 8 * 60 * 60
_GRANT_THREAD_LOCK = threading.Lock()


@dataclass(frozen=True)
class ProcessIdentity:
    executable: str
    executable_sha256: str
    owner: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _owner_identity() -> str:
    if os.name != "nt":
        return f"uid:{os.getuid()}"
    script = (
        "$i=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "[ordered]@{sid=[string]$i.User.Value}|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=8, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise ValueError("cannot resolve Windows owner identity")
    payload = json.loads(completed.stdout)
    sid = str(payload.get("sid") or "")
    if not sid.startswith("S-"):
        raise ValueError("invalid Windows owner identity")
    return f"sid:{sid}"


def _select_windows_client_ancestor(
    ancestors: list[dict[str, Any]],
    server_executable: Path,
    base_python_executable: Path | None = None,
) -> dict[str, Any]:
    """Skip only the private distlib launcher chain and return the real client."""

    server = ntpath.normcase(ntpath.normpath(str(server_executable)))
    private_scripts = ntpath.normcase(ntpath.dirname(server))
    base_python = ntpath.normcase(
        ntpath.normpath(str(base_python_executable or getattr(sys, "_base_executable", "")))
    )
    trusted_shells = _trusted_windows_shell_relays()
    # Claude Desktop/Code executes SessionStart command hooks through the Git for
    # Windows bash relay.  Treat only vendor installation paths as launch
    # intermediates: skipping every executable named ``bash.exe`` would let an
    # untrusted lookalike evade the immutable client binding.
    for item in ancestors:
        candidate = ntpath.normcase(ntpath.normpath(str(item.get("path") or "")))
        name = ntpath.basename(candidate)
        directory = ntpath.dirname(candidate)
        if candidate in trusted_shells or candidate in {server, base_python} or (
            directory == private_scripts
            and name in {
                "python.exe",
                "pythonw.exe",
                "python3.exe",
                "soul-codex-session-start.exe",
            }
        ):
            continue
        if not candidate:
            break
        return item
    raise ValueError("cannot resolve MCP client behind the private launcher chain")


def _trusted_windows_shell_relays() -> set[str]:
    """Resolve protected Windows/Git relay paths without trusting env vars."""

    # Static values make path-selection tests deterministic on non-Windows.
    # Production Windows values come only from WinAPI and protected HKLM.
    if os.name != "nt":
        windows_root = r"C:\Windows"
        program_files = [r"C:\Program Files", r"C:\Program Files (x86)"]
    else:
        import ctypes
        import winreg

        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if length <= 0 or length >= len(buffer):
            raise ValueError("cannot resolve protected Windows directory")
        windows_root = buffer.value
        program_files: list[str] = []
        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion",
                0,
                access,
            ) as key:
                for name in ("ProgramFilesDir", "ProgramFilesDir (x86)"):
                    try:
                        value, _kind = winreg.QueryValueEx(key, name)
                    except OSError:
                        continue
                    if (
                        isinstance(value, str)
                        and "%" not in value
                        and ntpath.isabs(value)
                    ):
                        program_files.append(value)
        except OSError as exc:
            raise ValueError("cannot resolve protected Program Files directories") from exc
        if not program_files:
            raise ValueError("cannot resolve protected Program Files directories")

    trusted = {
        ntpath.normcase(ntpath.join(windows_root, "System32", "cmd.exe")),
        ntpath.normcase(
            ntpath.join(
                windows_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
            )
        ),
    }
    for root in program_files:
        trusted.update(
            {
                ntpath.normcase(ntpath.join(root, "Git", "usr", "bin", "bash.exe")),
                ntpath.normcase(ntpath.join(root, "Git", "bin", "bash.exe")),
            }
        )
    return trusted


def _parent_identity() -> ProcessIdentity:
    parent_pid = os.getppid()
    if os.name == "nt":
        script = (
            "$ErrorActionPreference='Stop';"
            "$all=@(Get-CimInstance Win32_Process);$byPid=@{};"
            "foreach($item in $all){$byPid[[int]$item.ProcessId]=$item};"
            f"$next={parent_pid};$rows=@();"
            "for($n=0;$n -lt 12 -and $next -gt 0;$n++){"
            "$p=$byPid[$next];"
            "if(-not $p -or -not $p.ExecutablePath){break};"
            "$rows+=([ordered]@{path=[string]$p.ExecutablePath;session=[int]$p.SessionId;"
            "pid=[int]$p.ProcessId;parent_pid=[int]$p.ParentProcessId});"
            "$next=[int]$p.ParentProcessId};"
            "if($rows.Count -eq 0){throw 'parent missing'};"
            "ConvertTo-Json -InputObject @($rows) -Compress"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=12, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            raise ValueError("cannot inspect MCP parent process")
        ancestors = json.loads(completed.stdout)
        if not isinstance(ancestors, list):
            raise ValueError("invalid MCP parent process chain")
        payload = _select_windows_client_ancestor(
            ancestors, _current_server_executable()
        )
        sessions = {int(row.get("session", -1)) for row in ancestors}
        if len(sessions) != 1 or -1 in sessions:
            raise ValueError("MCP process ancestry crosses a Windows session boundary")
        path = Path(str(payload.get("path") or "")).resolve()
        owner = _owner_identity()
    else:
        proc = Path(f"/proc/{parent_pid}")
        path = proc.joinpath("exe").resolve(strict=True)
        owner = f"uid:{proc.stat().st_uid}"
    if not path.is_file():
        raise ValueError("MCP parent executable is unavailable")
    return ProcessIdentity(str(path), _sha256(path), owner)


def _grant_file(settings: ProxySettings) -> Path:
    return settings.soul_db.parent / "client-grants.json"


def _current_server_executable() -> Path:
    """Resolve the real console launcher, including Windows' hidden .exe suffix."""

    raw = Path(sys.argv[0]).expanduser()
    candidates = [raw]
    if raw.suffix.casefold() != ".exe":
        candidates.append(raw.with_suffix(f"{raw.suffix}.exe"))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    raise ValueError("SOUL MCP server executable is unavailable")


@contextmanager
def _grant_store_lock(path: Path):
    """Serialize grant read/validate/write across threads and processes."""

    lock_path = path.with_name(f"{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _GRANT_THREAD_LOCK:
        with lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _migrate_v1_grants(
    path: Path, raw_bytes: bytes, settings: ProxySettings
) -> dict[str, Any]:
    """Replace legacy enabled-only grants during explicit enrollment only."""

    try:
        legacy = json.loads(raw_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("client grant store differs from the installed machine soul") from exc
    clients = legacy.get("clients") if isinstance(legacy, dict) else None
    if (
        not isinstance(legacy, dict)
        or legacy.get("schema") != "soul.client-grants.v1"
        or legacy.get("machine_soul_id") != settings.machine_soul_id
        or not isinstance(clients, dict)
        or any(
            client_id not in ALLOWED_CLIENTS
            or not isinstance(entry, dict)
            or set(entry) != {"enabled"}
            or entry.get("enabled") is not True
            for client_id, entry in clients.items()
        )
    ):
        raise ValueError("client grant store differs from the installed machine soul")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    backup = path.with_name(f"{path.name}.v1.{digest[:16]}.bak")
    if backup.exists():
        if backup.is_symlink() or not backup.is_file() or backup.read_bytes() != raw_bytes:
            raise ValueError("client grant migration backup collision")
    else:
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, raw_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)
        if os.name != "nt":
            os.chmod(backup, 0o600)
    return {
        "schema": "soul.client-grants.v2",
        "machine_soul_id": settings.machine_soul_id,
        "clients": {},
    }


def _write_exact_grant_backup(path: Path, raw_bytes: bytes, label: str) -> Path:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    backup = path.with_name(f"{path.name}.{label}.{digest[:16]}.bak")
    if backup.exists():
        if backup.is_symlink() or not backup.is_file() or backup.read_bytes() != raw_bytes:
            raise ValueError("client grant migration backup collision")
        return backup
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, raw_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name != "nt":
        os.chmod(backup, 0o600)
    return backup


def ensure_client_grants(
    settings: ProxySettings, *, allow_v1_migration: bool = False
) -> Path:
    path = _grant_file(settings)
    expected = {
        "schema": "soul.client-grants.v2",
        "machine_soul_id": settings.machine_soul_id,
        "clients": {},
    }
    with _grant_store_lock(path):
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ValueError("client grant store must be a regular file")
            raw_bytes = path.read_bytes()
            raw = json.loads(raw_bytes)
            if raw.get("schema") == "soul.client-grants.v1" and allow_v1_migration:
                raw = _migrate_v1_grants(path, raw_bytes, settings)
                _atomic_json(path, raw)
            if (
                not isinstance(raw, dict)
                or raw.get("schema") != expected["schema"]
                or raw.get("machine_soul_id") != settings.machine_soul_id
                or not isinstance(raw.get("clients"), dict)
            ):
                raise ValueError("client grant store differs from the installed machine soul")
            return path
        _atomic_json(path, expected)
    return path


def _launch_digest(
    *, server_executable: str, config_path: Path, client_id: str
) -> str:
    material = json.dumps(
        {
            "server_executable": os.path.normcase(str(Path(server_executable).resolve())),
            "config": os.path.normcase(str(config_path.resolve())),
            "client_id": client_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()


def _parent_binding(parent: Path, owner: str, *, enrolled_unix_ms: int) -> dict[str, Any]:
    return {
        "executable": str(parent),
        "sha256": _sha256(parent),
        "owner": owner,
        "enrolled_unix_ms": enrolled_unix_ms,
    }


def _entry_parent_bindings(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Return strict v2 parent bindings, including legacy single-parent rows."""

    raw = entry.get("parent_bindings")
    if raw is None:
        raw = [{
            "executable": entry.get("parent_executable"),
            "sha256": entry.get("parent_sha256"),
            "owner": entry.get("owner"),
            "enrolled_unix_ms": entry.get("enrolled_unix_ms"),
        }]
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise ValueError("SOUL client parent bindings are invalid")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("SOUL client parent binding is invalid")
        executable = str(item.get("executable") or "")
        digest = str(item.get("sha256") or "")
        # Early v2 builds stored shared metadata only on the client row. Keep
        # those exact path/hash bindings readable, then normalize them on the
        # next owner-controlled rotation.
        owner = str(item.get("owner") or entry.get("owner") or "")
        normalized = os.path.normcase(str(Path(executable).resolve()))
        if (
            not executable or len(digest) != 64 or not owner
            or normalized in seen
        ):
            raise ValueError("SOUL client parent binding is invalid")
        seen.add(normalized)
        result.append({
            "executable": executable,
            "sha256": digest,
            "owner": owner,
            "enrolled_unix_ms": int(
                item.get("enrolled_unix_ms") or entry.get("enrolled_unix_ms") or 0
            ),
        })
    return result


def discover_windows_codex_app_parents() -> list[Path]:
    """Discover only OS-registered Codex App binaries and byte-identical cache copies."""

    if os.name != "nt":
        return []
    script = r'''
$ErrorActionPreference='Stop'
$package=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
if(-not $package){ConvertTo-Json -InputObject @() -Compress;exit 0}
$canonical=Join-Path $package.InstallLocation 'app\resources\codex.exe'
if(-not (Test-Path -LiteralPath $canonical -PathType Leaf)){throw 'Codex App runtime missing'}
$digest=(Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash.ToLowerInvariant()
$rows=@($canonical)
$cache=Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin'
if(Test-Path -LiteralPath $cache -PathType Container){
  Get-ChildItem -LiteralPath $cache -Filter codex.exe -File -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
      if((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -eq $digest){
        $rows += $_.FullName
      }
    }
}
ConvertTo-Json -InputObject @($rows | Sort-Object -Unique) -Compress
'''
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=15, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise ValueError("cannot attest Codex App package")
    rows = json.loads(completed.stdout or "[]")
    if isinstance(rows, str):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) > 8:
        raise ValueError("Codex App parent discovery is invalid")
    result: list[Path] = []
    for raw in rows:
        path = Path(str(raw)).expanduser().resolve(strict=True)
        if not path.is_file() or path.name.casefold() != "codex.exe":
            raise ValueError("Codex App parent discovery is invalid")
        result.append(path)
    return result


def discover_windows_claude_app_parents() -> list[Path]:
    """Discover the registered Claude Desktop app and its current local runtime.

    Claude Desktop starts MCP either behind its AppX executable or behind the
    versioned Claude Code runtime it provisions under the current user's
    profile.  Both surfaces remain exact path+hash grants; no name wildcard is
    accepted.
    """

    if os.name != "nt":
        return []
    script = r'''
$ErrorActionPreference='Stop'
$package=Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1
if(-not $package){ConvertTo-Json -InputObject @() -Compress;exit 0}
$desktop=Join-Path $package.InstallLocation 'app\Claude.exe'
if(-not (Test-Path -LiteralPath $desktop -PathType Leaf)){throw 'Claude Desktop executable missing'}
$rows=@($desktop)
$runtimeRoot=Join-Path $env:APPDATA 'Claude\claude-code'
if(Test-Path -LiteralPath $runtimeRoot -PathType Container){
  $live=@(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object {
        $_.ExecutablePath -and
        $_.ExecutablePath.StartsWith($runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($_.ExecutablePath) -ieq 'claude.exe'
      } | ForEach-Object {$_.ExecutablePath} | Sort-Object -Unique
  )
  if($live.Count -gt 0){
    $rows += $live
  } else {
    $latest=Get-ChildItem -LiteralPath $runtimeRoot -Filter claude.exe -File -Recurse -ErrorAction SilentlyContinue |
      Where-Object {$_.FullName -match '\\claude-code\\[^\\]+\\claude\.exe$'} |
      Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if($latest){$rows += $latest.FullName}
  }
}
ConvertTo-Json -InputObject @($rows | Sort-Object -Unique) -Compress
'''
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=15, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise ValueError("cannot attest Claude Desktop package")
    rows = json.loads(completed.stdout or "[]")
    if isinstance(rows, str):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) > 8:
        raise ValueError("Claude Desktop parent discovery is invalid")
    result: list[Path] = []
    for raw in rows:
        path = Path(str(raw)).expanduser().resolve(strict=True)
        if not path.is_file() or path.name.casefold() != "claude.exe":
            raise ValueError("Claude Desktop parent discovery is invalid")
        result.append(path)
    return result


def enroll_client(
    settings: ProxySettings,
    client_id: str,
    *,
    parent_executable: Path,
    server_executable: Path,
    config_path: Path,
    rotate_existing: bool = False,
    add_parent_binding: bool = False,
) -> dict[str, Any]:
    if client_id not in ALLOWED_CLIENTS:
        raise ValueError("unsupported SOUL client")
    parent = parent_executable.expanduser().resolve(strict=True)
    server = server_executable.expanduser().resolve(strict=True)
    if not parent.is_file() or not server.is_file():
        raise ValueError("client or MCP executable is unavailable")
    enrolled_unix_ms = int(time.time() * 1000)
    owner = _owner_identity()
    binding = _parent_binding(parent, owner, enrolled_unix_ms=enrolled_unix_ms)
    entry = {
        "enabled": True,
        "owner": owner,
        "parent_executable": str(parent),
        "parent_sha256": binding["sha256"],
        "parent_bindings": [binding],
        "server_executable": str(server),
        "server_sha256": _sha256(server),
        "launch_digest": _launch_digest(
            server_executable=str(server), config_path=config_path, client_id=client_id
        ),
        # Model-facing clients may read the public boot projection, search
        # approved memory, and stage candidates. They never receive canonical
        # memory/profile mutation authority.
        "scopes": [
            "boot.public",
            "boot.private",
            "memory.search.private",
            "memory.propose",
            "profile.propose",
        ],
        "enrolled_unix_ms": enrolled_unix_ms,
    }
    path = _grant_file(settings)
    expected = {
        "schema": "soul.client-grants.v2",
        "machine_soul_id": settings.machine_soul_id,
        "clients": {},
    }
    with _grant_store_lock(path):
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ValueError("client grant store must be a regular file")
            raw_bytes = path.read_bytes()
            raw = json.loads(raw_bytes)
            if isinstance(raw, dict) and raw.get("schema") == "soul.client-grants.v1":
                raw = _migrate_v1_grants(path, raw_bytes, settings)
        else:
            raw = dict(expected)
            raw["clients"] = {}
        if (
            not isinstance(raw, dict)
            or raw.get("schema") != expected["schema"]
            or raw.get("machine_soul_id") != settings.machine_soul_id
            or not isinstance(raw.get("clients"), dict)
        ):
            raise ValueError("client grant store differs from the installed machine soul")
        existing = raw["clients"].get(client_id)
        if isinstance(existing, dict):
            upgradable_scope_sets = (
                ["boot", "memory.search", "memory.store"],
                [
                    "boot.public",
                    "boot.private",
                    "memory.search.private",
                    "memory.propose",
                ],
            )
            scopes_upgraded = False
            prior_scopes = existing.get("scopes")
            if rotate_existing and prior_scopes in upgradable_scope_sets:
                # Exact, owner-controlled upgrade from the only historical
                # model-facing scope sets. This removes canonical write access
                # or adds proposal-only profile authority; arbitrary scope
                # changes remain immutable and fail closed.
                _write_exact_grant_backup(path, raw_bytes, "scopes")
                existing = dict(existing)
                existing["previous_scopes"] = prior_scopes
                existing["scopes"] = entry["scopes"]
                existing["scopes_rotated_unix_ms"] = enrolled_unix_ms
                raw["clients"][client_id] = existing
                scopes_upgraded = True
            existing_bindings = _entry_parent_bindings(existing)
            normalized_parent = os.path.normcase(str(parent))
            matching = next(
                (
                    item for item in existing_bindings
                    if os.path.normcase(str(Path(item["executable"]).resolve()))
                    == normalized_parent
                ),
                None,
            )
            immutable_fields = (
                "enabled",
                "owner",
                "server_executable",
                "server_sha256",
                "launch_digest",
                "scopes",
            )
            if (
                matching is not None
                and matching["sha256"] == binding["sha256"]
                and all(existing.get(field) == entry.get(field) for field in immutable_fields)
            ):
                if scopes_upgraded:
                    _atomic_json(path, raw)
                return existing
            stable_fields = (
                "enabled",
                "owner",
                "server_executable",
                "launch_digest",
                "scopes",
            )
            stable = all(existing.get(field) == entry.get(field) for field in stable_fields)
            if matching is None and add_parent_binding and stable:
                if len(existing_bindings) >= 16:
                    raise ValueError("SOUL client parent binding limit reached")
                changed = dict(existing)
                changed["parent_bindings"] = [*existing_bindings, binding]
                if rotate_existing and existing.get("server_sha256") != entry["server_sha256"]:
                    changed["previous_server_sha256"] = existing.get("server_sha256")
                    changed["server_sha256"] = entry["server_sha256"]
                    changed["rotated_unix_ms"] = enrolled_unix_ms
                changed["bindings_updated_unix_ms"] = enrolled_unix_ms
                raw["clients"][client_id] = changed
                _atomic_json(path, raw)
                return changed
            if matching is not None and rotate_existing and stable:
                changed = dict(existing)
                changed_bindings = [
                    binding
                    if os.path.normcase(str(Path(item["executable"]).resolve()))
                    == normalized_parent
                    else item
                    for item in existing_bindings
                ]
                changed["parent_bindings"] = changed_bindings
                changed["parent_executable"] = changed_bindings[0]["executable"]
                changed["parent_sha256"] = changed_bindings[0]["sha256"]
                changed["server_sha256"] = entry["server_sha256"]
                changed["rotated_unix_ms"] = enrolled_unix_ms
                changed["previous_server_sha256"] = existing.get("server_sha256")
                raw["clients"][client_id] = changed
                _atomic_json(path, raw)
                return changed
            raise ValueError(
                "SOUL client already has an immutable binding; explicit owner-controlled "
                "reinstallation is required to rotate it"
            )
        raw["clients"][client_id] = entry
        _atomic_json(path, raw)
    return entry


def verify_client_grant(
    settings: ProxySettings,
    client_id: str,
    *,
    config_path: Path | None = None,
    server_executable: Path | None = None,
    process_identity: ProcessIdentity | None = None,
) -> dict[str, Any]:
    if client_id not in ALLOWED_CLIENTS:
        raise ValueError("unsupported SOUL client")
    path = ensure_client_grants(settings)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw["machine_soul_id"] != settings.machine_soul_id:
        raise ValueError("client grant audience mismatch")
    entry = raw["clients"].get(client_id)
    if not isinstance(entry, dict) or entry.get("enabled") is not True:
        raise ValueError("SOUL client is not granted")
    observed = process_identity or _parent_identity()
    expected_owner = str(entry.get("owner") or "")
    if observed.owner != expected_owner or _owner_identity() != expected_owner:
        raise ValueError("SOUL client OS session mismatch")
    bindings = _entry_parent_bindings(entry)
    observed_path = os.path.normcase(str(Path(observed.executable).resolve()))
    binding = next(
        (
            item for item in bindings
            if os.path.normcase(str(Path(item["executable"]).resolve())) == observed_path
        ),
        None,
    )
    if binding is None:
        raise ValueError(
            f"SOUL client parent executable mismatch ({observed.executable})"
        )
    if observed.owner != binding["owner"] or observed.executable_sha256 != binding["sha256"]:
        raise ValueError("SOUL client parent hash mismatch")
    server = (
        server_executable.expanduser().resolve(strict=True)
        if server_executable is not None
        else _current_server_executable()
    )
    if os.path.normcase(str(server)) != os.path.normcase(
        str(Path(str(entry.get("server_executable") or "")).resolve())
    ) or _sha256(server) != entry.get("server_sha256"):
        raise ValueError("SOUL MCP server binary mismatch")
    bound_config = (config_path or settings.soul_db.parent / "proxy.toml").resolve()
    if _launch_digest(
        server_executable=str(server), config_path=bound_config, client_id=client_id
    ) != entry.get("launch_digest"):
        raise ValueError("SOUL client launch binding mismatch")
    return entry


def sync_codex_app_grants(
    settings: ProxySettings,
    *,
    config_path: Path,
    server_executable: Path,
    parents: list[Path] | None = None,
) -> int:
    """Idempotently bind current signed Codex App surfaces to the Codex grant."""

    candidates = discover_windows_codex_app_parents() if parents is None else parents
    grant_path = ensure_client_grants(settings)
    added = 0
    for parent in candidates:
        before = json.loads(grant_path.read_text()).get("clients", {}).get("codex", {})
        before_count = len(_entry_parent_bindings(before)) if before else 0
        enroll_client(
            settings,
            "codex",
            parent_executable=parent,
            server_executable=server_executable,
            config_path=config_path,
            rotate_existing=True,
            add_parent_binding=True,
        )
        after = json.loads(grant_path.read_text())["clients"]["codex"]
        added += max(0, len(_entry_parent_bindings(after)) - before_count)
    return added


def sync_claude_app_grants(
    settings: ProxySettings,
    *,
    config_path: Path,
    server_executable: Path,
    parents: list[Path] | None = None,
) -> int:
    """Idempotently bind current exact Claude Desktop surfaces."""

    candidates = discover_windows_claude_app_parents() if parents is None else parents
    grant_path = ensure_client_grants(settings)
    added = 0
    for parent in candidates:
        before = json.loads(grant_path.read_text()).get("clients", {}).get("claude", {})
        before_count = len(_entry_parent_bindings(before)) if before else 0
        enroll_client(
            settings,
            "claude",
            parent_executable=parent,
            server_executable=server_executable,
            config_path=config_path,
            rotate_existing=True,
            add_parent_binding=True,
        )
        after = json.loads(grant_path.read_text())["clients"]["claude"]
        added += max(0, len(_entry_parent_bindings(after)) - before_count)
    return added


def sync_claude_desktop_mcp_config(
    *,
    config_path: Path,
    server_executable: Path,
    desktop_config_path: Path | None = None,
    installed_parents: list[Path] | None = None,
) -> bool:
    """Ensure Claude Desktop exposes ``soul-local`` without losing other servers.

    The Claude CLI user config and Claude Desktop config are distinct surfaces.
    This uses exact executable/config paths, preserves all unrelated JSON, and
    fails closed if another process changes the file during the update.
    """

    if desktop_config_path is None:
        if os.name != "nt":
            return False
        parents = (
            discover_windows_claude_app_parents()
            if installed_parents is None else installed_parents
        )
        if not parents:
            return False
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise ValueError("APPDATA is required for Claude Desktop")
        desktop_config_path = Path(appdata) / "Claude" / "claude_desktop_config.json"
    target = desktop_config_path.expanduser()
    desired = {
        "command": str(server_executable.resolve(strict=True)),
        "args": ["--config", str(config_path.resolve(strict=True)), "--client-id", "claude"],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with _GRANT_THREAD_LOCK:
        before = target.read_bytes() if target.exists() else None
        try:
            document = json.loads(before.decode("utf-8-sig")) if before is not None else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Claude Desktop config is not valid JSON") from exc
        if not isinstance(document, dict):
            raise ValueError("Claude Desktop config root must be an object")
        servers = document.setdefault("mcpServers", {})
        if not isinstance(servers, dict):
            raise ValueError("Claude Desktop mcpServers must be an object")
        if servers.get("soul-local") == desired:
            return False
        servers["soul-local"] = desired
        payload = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        fd, raw_temporary = tempfile.mkstemp(
            dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
        )
        temporary = Path(raw_temporary)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            current = target.read_bytes() if target.exists() else None
            if current != before:
                raise ValueError("Claude Desktop config changed concurrently")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        verified = json.loads(target.read_text(encoding="utf-8"))
        if verified.get("mcpServers", {}).get("soul-local") != desired:
            raise ValueError("Claude Desktop config post-write verification failed")
        return True


def sync_claude_session_start_hook(
    *,
    config_path: Path,
    server_executable: Path,
    hook_executable: Path,
    settings_path: Path | None = None,
    installed_parents: list[Path] | None = None,
) -> bool:
    """Eagerly attach SOUL before Claude's first model response.

    Claude's MCP configuration exposes the tools; its SessionStart hook makes
    the connection automatic by calling ``soul_boot_context`` before the first
    response. Existing hooks are preserved and concurrent edits fail closed.
    """

    if settings_path is None:
        if os.name != "nt":
            return False
        parents = (
            discover_windows_claude_app_parents()
            if installed_parents is None else installed_parents
        )
        if not parents:
            return False
        profile = os.environ.get("USERPROFILE")
        if not profile:
            raise ValueError("USERPROFILE is required for Claude SessionStart")
        settings_path = Path(profile) / ".claude" / "settings.json"
    target = settings_path.expanduser()
    hook = hook_executable.resolve(strict=True)
    server = server_executable.resolve(strict=True)
    config = config_path.resolve(strict=True)
    command = subprocess.list2cmdline(
        [
            str(hook), "--config", str(config), "--server-executable", str(server),
            "--client-id", "claude",
        ]
    )
    desired_group = {
        "matcher": "^(startup|resume|clear|compact|fork)$",
        "hooks": [{"type": "command", "command": command, "timeout": 25}],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with _GRANT_THREAD_LOCK:
        before = target.read_bytes() if target.exists() else None
        try:
            document = json.loads(before.decode("utf-8-sig")) if before is not None else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Claude settings are not valid JSON") from exc
        if not isinstance(document, dict):
            raise ValueError("Claude settings root must be an object")
        hooks = document.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError("Claude settings hooks must be an object")
        groups = hooks.setdefault("SessionStart", [])
        if not isinstance(groups, list):
            raise ValueError("Claude SessionStart hooks must be an array")

        def is_owned(group: object) -> bool:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                return False
            return any(
                isinstance(handler, dict)
                and handler.get("type") == "command"
                and str(hook).casefold() in str(handler.get("command") or "").casefold()
                and "--client-id claude" in str(handler.get("command") or "").casefold()
                for handler in group["hooks"]
            )

        updated = [group for group in groups if not is_owned(group)] + [desired_group]
        if updated == groups:
            return False
        hooks["SessionStart"] = updated
        payload = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        fd, raw_temporary = tempfile.mkstemp(
            dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
        )
        temporary = Path(raw_temporary)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            current = target.read_bytes() if target.exists() else None
            if current != before:
                raise ValueError("Claude settings changed concurrently")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        verified = json.loads(target.read_text(encoding="utf-8"))
        live_groups = verified.get("hooks", {}).get("SessionStart", [])
        if sum(is_owned(group) for group in live_groups) != 1:
            raise ValueError("Claude SessionStart post-write verification failed")
        return True


def _soul_config(settings: ProxySettings) -> SoulConfig:
    return SoulConfig(
        backend="sqlite",
        backend_url=str(settings.soul_db),
        embedding_provider=settings.embedding_provider,
        embedding_dimensions=settings.embedding_dimensions,
        memory_vector_index=settings.memory_vector_index,
        dni_credential_path=str(settings.dni_credential_file),
        dni_trust_store_path=str(settings.dni_trust_store_file),
        dni_trust_store_sha256=settings.dni_trust_store_sha256,
        machine_soul_id=settings.machine_soul_id,
    )


async def _run_tool(
    settings: ProxySettings,
    name: str,
    arguments: dict[str, Any],
    *,
    client_id: str = "unknown",
    session_id: str = "",
) -> dict[str, Any]:
    config = _soul_config(settings)
    if name == "soul_boot_context":
        from soul_platform.living_soul import public_boot_projection, public_boot_text

        projection = await public_boot_projection(settings)
        return {
            "content": [{"type": "text", "text": public_boot_text(projection)}],
            "structuredContent": projection,
        }
    if name == "soul_private_boot_context":
        from soul_platform.living_soul import private_boot_context

        content, projection = await private_boot_context(settings)
        return {
            "content": [{"type": "text", "text": content}],
            "structuredContent": projection,
        }
    if name == "soul_memory_propose":
        from soul_platform.living_soul import propose_memory_candidate

        proposal = propose_memory_candidate(
            settings,
            client_id=client_id,
            source_event_id=arguments.get("source_event_id"),
            content=arguments.get("content"),
            importance=arguments.get("importance", 5),
            provenance={
                "session_id": arguments.get("session_id", ""),
                "turn_id": arguments.get("turn_id", ""),
                "surface": arguments.get("surface", "mcp"),
            },
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"candidate:{proposal['candidate_id']}:{proposal['status']}",
                }
            ],
            "structuredContent": proposal,
        }
    if name == "soul_profile_propose":
        from soul_platform.living_soul import propose_profile_change

        proposal = propose_profile_change(
            settings,
            client_id=client_id,
            source_event_id=arguments.get("source_event_id"),
            change_kind=arguments.get("change_kind"),
            patch=arguments.get("patch"),
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"profile-proposal:{proposal['proposal_id']}:{proposal['status']}",
                }
            ],
            "structuredContent": proposal,
        }
    async with Soul.create(settings.soul_name, config=config) as soul:
        if name == "soul_memory_search":
            query = arguments.get("query")
            limit = arguments.get("limit", 4)
            if not isinstance(query, str) or not query.strip() or len(query) > 4096:
                raise ValueError("query must be non-empty text up to 4096 characters")
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 8:
                raise ValueError("limit must be an integer from 1 to 8")
            hits = await soul.memory.search(query.strip(), limit=limit)
            # Retrieval is not authorization.  Every private excerpt released
            # to an MCP/cloud client must cross the same durable T5 egress
            # boundary as the OpenAI-compatible proxy.
            from soul_platform.t5_memory_egress import SQLiteT5EgressStore

            if settings.t5_mode == "compatibility-single-owner":
                egress = SQLiteT5EgressStore(settings.t5_state_path)
                await egress.initialize()
                await egress.bind_legacy_memories(
                    soul_id=settings.machine_soul_id,
                    memory_ids=[hit.memory.id for hit in hits],
                    tenant=settings.t5_tenant,
                    owner_subject=settings.t5_owner_subject,
                )
                decision = await egress.evaluate(
                    soul_id=settings.machine_soul_id,
                    tenant=settings.t5_tenant,
                    session_id=session_id or f"mcp:{client_id}",
                    interlocutor=settings.t5_owner_subject,
                    memory_ids=[hit.memory.id for hit in hits],
                )
                allowed_ids = set(decision.allowed_ids)
                hits = [hit for hit in hits if str(hit.memory.id) in allowed_ids]
                egress_reason = decision.reason
            else:
                # An MCP parent binding proves the application binary, not the
                # human interlocutor.  Enforced multi-owner installations need
                # an authenticated principal and therefore fail closed here.
                hits = []
                egress_reason = "locked-no-verified-interlocutor"
            payload = [
                {
                    "id": str(hit.memory.id),
                    "content": hit.memory.content,
                    "importance": hit.memory.importance,
                    "scope": hit.memory.scope,
                    "score": round(float(hit.score), 6),
                }
                for hit in hits
            ]
            return {
                "content": [
                    {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}
                ],
                "structuredContent": {"memories": payload, "egress": egress_reason},
            }
    raise ValueError("unknown SOUL tool")


TOOLS = [
    {
        "name": "soul_boot_context",
        "description": "Load the persistent machine identity without dumping all memories.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "soul_private_boot_context",
        "description": (
            "Load the owner-consented private identity projection. Hidden and denied "
            "without exact processor consent."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "soul_memory_search",
        "description": "Search only the local machine soul's authorized persistent memories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 4096},
                "limit": {"type": "integer", "minimum": 1, "maximum": 8, "default": 4},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "soul_memory_propose",
        "description": (
            "Stage one untrusted declarative memory candidate for local-owner review. "
            "This never mutates canonical SOUL memory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "minLength": 1, "maxLength": 4096},
                "importance": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
                "source_event_id": {"type": "string", "minLength": 1, "maxLength": 200},
                "session_id": {"type": "string", "maxLength": 200},
                "turn_id": {"type": "string", "maxLength": 200},
                "surface": {"type": "string", "maxLength": 80},
            },
            "required": ["content", "source_event_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "soul_profile_propose",
        "description": (
            "Stage an untrusted identity, OCEAN, rule or relationship change for "
            "local-owner review. This never mutates the canonical profile."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "change_kind": {
                    "type": "string",
                    "enum": ["identity", "ocean", "rule", "relationship"],
                },
                "patch": {"type": "object"},
                "source_event_id": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "required": ["change_kind", "patch", "source_event_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    },
]

TOOL_SCOPES = {
    "soul_boot_context": "boot.public",
    "soul_private_boot_context": "boot.private",
    "soul_memory_search": "memory.search.private",
    "soul_memory_propose": "memory.propose",
    "soul_profile_propose": "profile.propose",
}


ToolRunner = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class MCPStdioServer:
    def __init__(
        self,
        runner: ToolRunner,
        *,
        scopes: set[str] | frozenset[str],
        scope_resolver: Callable[[], frozenset[str]] | None = None,
        dni_verifier: Callable[[], Any] | None = None,
    ) -> None:
        self.runner = runner
        self.scopes = frozenset(scopes)
        self.scope_resolver = scope_resolver
        self.dni_verifier = dni_verifier
        self.session_id: str | None = None
        self.expires_at = 0.0

    def _current_scopes(self) -> frozenset[str]:
        return self.scope_resolver() if self.scope_resolver is not None else self.scopes

    def _visible_tools(self) -> list[dict[str, Any]]:
        scopes = self._current_scopes()
        return [tool for tool in TOOLS if TOOL_SCOPES[tool["name"]] in scopes]

    async def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            raise ValueError("invalid JSON-RPC request")
        if self.dni_verifier is not None:
            try:
                self.dni_verifier()
            except Exception as exc:
                raise PermissionError("SOUL DNI renewal required") from exc
        method = request.get("method")
        request_id = request.get("id")
        if method and str(method).startswith("notifications/"):
            return None
        if request_id is None:
            raise ValueError("request id is required")
        if method == "initialize":
            self.session_id = secrets.token_urlsafe(24)
            self.expires_at = time.monotonic() + ATTACH_TTL_SECONDS
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "soul-local", "version": "0.7.0.dev1"},
                "instructions": (
                    "SOUL is the local persistent identity and memory layer. Call "
                    "soul_boot_context once, search memory when prior context matters, "
                    "and store only explicit declarative facts requested by the owner."
                ),
                "_meta": {"soulAttachSession": self.session_id, "ttlSeconds": ATTACH_TTL_SECONDS},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            if self.session_id is None or time.monotonic() >= self.expires_at:
                raise ValueError("SOUL attach session is not active")
            result = {"tools": self._visible_tools()}
        elif method == "tools/call":
            if self.session_id is None or time.monotonic() >= self.expires_at:
                raise ValueError("SOUL attach session is not active")
            params = request.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("arguments", {}), dict):
                raise ValueError("invalid tool call")
            tool_name = str(params.get("name") or "")
            required_scope = TOOL_SCOPES.get(tool_name)
            if required_scope is None or required_scope not in self._current_scopes():
                raise PermissionError("SOUL tool scope denied")
            result = await self.runner(tool_name, params.get("arguments", {}))
            if self.dni_verifier is not None:
                try:
                    self.dni_verifier()
                except Exception as exc:
                    raise PermissionError("SOUL DNI renewal required") from exc
            # The private-context consent is bound to an exact snapshot.  A
            # writer may change that snapshot while an async tool is running;
            # never serialize bytes authorized against the stale snapshot.
            # There is intentionally no await between this second check and
            # returning the already-built result.
            if required_scope not in self._current_scopes():
                raise PermissionError("SOUL tool scope changed during call")
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


async def serve(config_path: Path, client_id: str) -> None:
    from soul_platform.dni_online import attempt_startup_renewal

    await asyncio.to_thread(attempt_startup_renewal, config_path)
    settings = ProxySettings.from_toml(config_path)
    entry = verify_client_grant(settings, client_id, config_path=config_path)
    scopes = entry.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes):
        raise ValueError("SOUL client grant scopes are invalid")
    def resolve_scopes() -> frozenset[str]:
        from soul_platform.context_consent import effective_scopes

        raw = json.loads(ensure_client_grants(settings).read_text(encoding="utf-8"))
        live_entry = raw.get("clients", {}).get(client_id)
        if not isinstance(live_entry, dict) or live_entry.get("enabled") is not True:
            return frozenset()
        live_scopes = live_entry.get("scopes")
        if not isinstance(live_scopes, list):
            return frozenset()
        return effective_scopes(settings, client_id, live_scopes)

    runtime_session_id = secrets.token_urlsafe(24)
    server = MCPStdioServer(
        lambda name, arguments: _run_tool(
            settings,
            name,
            arguments,
            client_id=client_id,
            session_id=runtime_session_id,
        ),
        scopes=frozenset(),
        scope_resolver=resolve_scopes,
        dni_verifier=lambda: settings.verified_dni("soul-platform"),
    )
    while True:
        line = await asyncio.to_thread(sys.stdin.buffer.readline)
        if not line:
            return
        try:
            request = json.loads(line)
            response = await server.handle(request)
        except Exception as exc:
            request_id = request.get("id") if isinstance(locals().get("request"), dict) else None
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": type(exc).__name__},
            }
        if response is not None:
            raw = (json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-mcp-stdio")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--client-id", choices=sorted(ALLOWED_CLIENTS), required=True)
    parser.add_argument("--enroll-parent", type=Path)
    parser.add_argument("--rotate-existing", action="store_true")
    parser.add_argument("--add-parent-binding", action="store_true")
    args = parser.parse_args(argv)
    config = args.config.expanduser().resolve()
    if args.enroll_parent is not None:
        settings = ProxySettings.from_toml(config)
        entry = enroll_client(
            settings,
            args.client_id,
            parent_executable=args.enroll_parent,
            server_executable=_current_server_executable(),
            config_path=config,
            rotate_existing=args.rotate_existing,
            add_parent_binding=args.add_parent_binding,
        )
        print(json.dumps({"enrolled": args.client_id, "parent_sha256": entry["parent_sha256"]}))
        return 0
    asyncio.run(serve(config, args.client_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
