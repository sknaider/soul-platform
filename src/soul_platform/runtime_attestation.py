"""Owner-approved, process-bound trust for local model runtimes.

AutoWire may discover any protocol-compatible loopback listener, but private
SOUL context is released only when the current Windows owner explicitly pins
the executable that owns the listener.  The pin is rechecked against the live
PID and executable bytes for every request.  Other operating systems remain
fail-closed until they gain an equivalent OS-backed implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


SCHEMA = "soul.runtime-attestation.v1"
OLLAMA_ORIGIN = "http://127.0.0.1:11434"


class RuntimeAttestationError(RuntimeError):
    pass


def _is_windows() -> bool:
    return os.name == "nt"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _receipt_path(root: Path) -> Path:
    return root / "trusted-local-runtimes.json"


def _powershell_json(script: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeAttestationError("Windows runtime inspection failed")
    try:
        payload = json.loads(completed.stdout.strip())
    except (ValueError, TypeError) as exc:
        raise RuntimeAttestationError("Windows runtime inspection was invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeAttestationError("Windows runtime inspection was invalid")
    return payload


def _windows_listener() -> dict[str, Any]:
    # Exact fixed endpoint only.  GetOwner binds the listener to the same
    # interactive Windows principal that approves the receipt.
    return _powershell_json(
        "$ErrorActionPreference='Stop';"
        "$c=Get-NetTCPConnection -State Listen -LocalPort 11434 | "
        "Where-Object {$_.LocalAddress -eq '127.0.0.1'} | Select-Object -First 1;"
        "if(-not $c){throw 'listener missing'};"
        "$p=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$c.OwningProcess);"
        "if(-not $p -or -not $p.ExecutablePath){throw 'process missing'};"
        "$o=Invoke-CimMethod -InputObject $p -MethodName GetOwner;"
        "[ordered]@{pid=[int]$p.ProcessId;path=[string]$p.ExecutablePath;"
        "created=[string]$p.CreationDate;owner=([string]$o.Domain+'\\'+[string]$o.User)}"
        "|ConvertTo-Json -Compress"
    )


def _current_windows_owner() -> str:
    return _powershell_json(
        "$i=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "[ordered]@{owner=[string]$i.Name}|ConvertTo-Json -Compress"
    )["owner"]


def _atomic_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if not _is_windows():
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def trust_current_ollama(root: Path, *, machine_soul_id: str) -> dict[str, Any]:
    """Pin the live Windows Ollama listener after explicit owner action."""

    if not _is_windows():
        raise RuntimeAttestationError("runtime trust enrollment is Windows-only in AutoWire A")
    info = _windows_listener()
    executable = Path(str(info.get("path") or "")).resolve()
    if not executable.is_file() or executable.name.casefold() != "ollama.exe":
        raise RuntimeAttestationError("Ollama listener executable is unavailable")
    current_owner = str(_current_windows_owner()).casefold()
    listener_owner = str(info.get("owner") or "").casefold()
    if not current_owner or listener_owner != current_owner:
        raise RuntimeAttestationError("Ollama listener is not owned by the current user")
    receipt = {
        "schema": SCHEMA,
        "machine_soul_id": machine_soul_id,
        "source": "ollama",
        "origin": OLLAMA_ORIGIN,
        "executable_path": str(executable),
        "executable_sha256": _sha256(executable),
        "owner": str(info["owner"]),
        "approved_unix_ms": int(time.time() * 1000),
    }
    _atomic_private_json(_receipt_path(root.resolve()), receipt)
    return {**receipt, "executable_path": str(executable)}


def verify_runtime_attestation(settings: Any) -> bool:
    """Verify receipt, live listener identity, owner and executable bytes."""

    if not _is_windows() or settings.upstream_kind != "ollama":
        return False
    parsed = urlsplit(settings.upstream_base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 11434
        or parsed.path.rstrip("/") != "/v1"
    ):
        return False
    path = _receipt_path(Path(settings.soul_db).resolve().parent)
    try:
        if path.is_symlink() or not path.is_file():
            return False
        receipt = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(receipt, dict):
            return False
        expected = {
            "schema": SCHEMA,
            "machine_soul_id": settings.machine_soul_id,
            "source": "ollama",
            "origin": OLLAMA_ORIGIN,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            return False
        expected_hash = str(receipt.get("executable_sha256") or "").lower()
        if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
            return False
        info = _windows_listener()
        executable = Path(str(info.get("path") or "")).resolve()
        pinned = Path(str(receipt.get("executable_path") or "")).resolve()
        if executable.name.casefold() != "ollama.exe":
            return False
        if os.path.normcase(str(executable)) != os.path.normcase(str(pinned)):
            return False
        if str(info.get("owner") or "").casefold() != str(receipt.get("owner") or "").casefold():
            return False
        if str(info.get("owner") or "").casefold() != str(_current_windows_owner()).casefold():
            return False
        return executable.is_file() and _sha256(executable) == expected_hash
    except (OSError, ValueError, TypeError, RuntimeAttestationError):
        return False
