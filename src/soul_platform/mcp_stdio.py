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
    windows_root = ntpath.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    trusted_shells = {
        ntpath.normcase(ntpath.join(windows_root, "System32", "cmd.exe")),
        ntpath.normcase(
            ntpath.join(
                windows_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
            )
        ),
    }
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
        "scopes": ["boot", "memory.search", "memory.store"],
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


def _soul_config(settings: ProxySettings) -> SoulConfig:
    return SoulConfig(
        backend="sqlite",
        backend_url=str(settings.soul_db),
        embedding_provider=settings.embedding_provider,
        embedding_dimensions=settings.embedding_dimensions,
        memory_vector_index=settings.memory_vector_index,
    )


async def _run_tool(
    settings: ProxySettings, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    config = _soul_config(settings)
    async with Soul.create(settings.soul_name, config=config) as soul:
        if name == "soul_boot_context":
            content = await soul.boot()
            return {"content": [{"type": "text", "text": content}]}
        if name == "soul_memory_search":
            query = arguments.get("query")
            limit = arguments.get("limit", 4)
            if not isinstance(query, str) or not query.strip() or len(query) > 4096:
                raise ValueError("query must be non-empty text up to 4096 characters")
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 8:
                raise ValueError("limit must be an integer from 1 to 8")
            hits = await soul.memory.search(query.strip(), limit=limit)
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
                "structuredContent": {"memories": payload},
            }
        if name == "soul_memory_store":
            content = arguments.get("content")
            importance = arguments.get("importance", 5)
            if (
                not isinstance(content, str)
                or not 1 <= len(content.strip()) <= 4096
                or "?" in content
            ):
                raise ValueError("content must be a declarative fact up to 4096 characters")
            if (
                not isinstance(importance, int)
                or isinstance(importance, bool)
                or not 1 <= importance <= 10
            ):
                raise ValueError("importance must be an integer from 1 to 10")
            memory_id = await soul.memory.store(
                content.strip(), importance=importance, scope="private"
            )
            return {
                "content": [{"type": "text", "text": f"stored:{memory_id}"}],
                "structuredContent": {"memory_id": str(memory_id)},
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
        "name": "soul_memory_store",
        "description": "Persist one explicit declarative fact in the local machine soul.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "minLength": 1, "maxLength": 4096},
                "importance": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
            },
            "required": ["content"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    },
]


ToolRunner = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class MCPStdioServer:
    def __init__(self, runner: ToolRunner) -> None:
        self.runner = runner
        self.session_id: str | None = None
        self.expires_at = 0.0

    async def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            raise ValueError("invalid JSON-RPC request")
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
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "soul-local", "version": "0.5.9"},
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
            result = {"tools": TOOLS}
        elif method == "tools/call":
            if self.session_id is None or time.monotonic() >= self.expires_at:
                raise ValueError("SOUL attach session is not active")
            params = request.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("arguments", {}), dict):
                raise ValueError("invalid tool call")
            result = await self.runner(str(params.get("name") or ""), params.get("arguments", {}))
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


async def serve(config_path: Path, client_id: str) -> None:
    settings = ProxySettings.from_toml(config_path)
    verify_client_grant(settings, client_id, config_path=config_path)
    server = MCPStdioServer(lambda name, arguments: _run_tool(settings, name, arguments))
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
