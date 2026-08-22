from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from soul_platform.autowire.discovery import discover_all
from soul_platform.autowire.probe import MAX_DISCOVERY_BYTES, _NoRedirect, get_json, strict_json
from soul_platform.autowire.registry import ProviderRegistry, RegistryConflict
from soul_platform.autowire.types import ProviderCandidate, ProviderState
from soul_platform.bootstrap import _atomic_config, render_config, switch_upstream
from soul_platform.mcp_stdio import (
    sync_claude_app_grants,
    sync_claude_desktop_mcp_config,
    sync_codex_app_grants,
)
from soul_platform.proxy import ProxySettings
from soul_platform.runtime_attestation import verify_runtime_attestation


class ActivationDenied(RuntimeError):
    pass


_ACTIVATION_THREAD_LOCK = threading.Lock()


def _is_windows() -> bool:
    return os.name == "nt"


@contextmanager
def _activation_lock(path: Path):
    """Serialize check -> side effects -> CAS across threads and processes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with _ACTIVATION_THREAD_LOCK:
        with path.open("a+b") as handle:
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


def _private_capability(path: Path) -> str:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError("AutoWire capability must be a regular file")
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError("AutoWire capability permissions are too broad")
        value = path.read_text(encoding="ascii").strip()
        if len(value.encode()) < 32:
            raise ValueError("AutoWire capability is invalid")
        return value
    value = secrets.token_urlsafe(48)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (value + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name != "nt":
        os.chmod(path, 0o600)
    return value


class AutoWireManager:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.config_path = self.root / "proxy.toml"
        self.settings = ProxySettings.from_toml(self.config_path)
        embedding = (
            self.settings.embedding_provider,
            self.settings.embedding_dimensions,
            self.settings.embedding_model,
        )
        self.registry = ProviderRegistry(
            self.root / "autowire.sqlite3",
            machine_soul_id=self.settings.machine_soul_id,
            embedding_identity=embedding,
        )
        self.capability_file = self.root / "autowire.admin.cap"
        _private_capability(self.capability_file)

    def _is_current(self, candidate: ProviderCandidate) -> bool:
        return (
            candidate.kind == self.settings.upstream_kind
            and candidate.base_url.rstrip("/") == self.settings.upstream_base_url.rstrip("/")
            and candidate.model == self.settings.upstream_model
        )

    def reconcile(self) -> dict[str, object]:
        self.settings = ProxySettings.from_toml(self.config_path)
        candidates, errors = discover_all()
        if _is_windows():
            server_executable = (
                self.root / "venv" / "Scripts" / "soul-mcp-stdio.exe"
            )
            try:
                sync_codex_app_grants(
                    self.settings,
                    config_path=self.config_path,
                    server_executable=server_executable,
                )
            except (OSError, ValueError) as exc:
                errors["codex-app-grant"] = type(exc).__name__
            try:
                sync_claude_app_grants(
                    self.settings,
                    config_path=self.config_path,
                    server_executable=server_executable,
                )
            except (OSError, ValueError) as exc:
                errors["claude-app-grant"] = type(exc).__name__
            try:
                sync_claude_desktop_mcp_config(
                    config_path=self.config_path,
                    server_executable=server_executable,
                )
            except (OSError, ValueError) as exc:
                errors["claude-desktop-config"] = type(exc).__name__
        seen: set[str] = set()
        active_id: str | None = None
        for candidate in candidates:
            seen.add(candidate.provider_id)
            active = self._is_current(candidate)
            candidate_settings = replace(
                self.settings,
                upstream_kind=candidate.kind,
                upstream_base_url=candidate.base_url,
                upstream_model=candidate.model,
            )
            memory_allowed = candidate.source == "ollama" and verify_runtime_attestation(
                candidate_settings
            )
            state = ProviderState.ACTIVE if active else (
                ProviderState.IDENTITY_ATTESTED
                if memory_allowed
                else ProviderState.DISCOVERED
            )
            # Protocol discovery is never identity proof.  Private memory is
            # enabled only when the live listener matches the owner's durable,
            # process-bound receipt.
            self.registry.upsert(candidate, state=state, memory_allowed=memory_allowed)
            if active:
                active_id = candidate.provider_id
        self.registry.mark_unseen_stale(seen)
        if active_id is not None:
            current_id, generation = self.registry.binding()
            if current_id is None:
                self.registry.commit_binding(active_id, expected_generation=generation)
            elif current_id != active_id:
                self.registry.audit("LIVE_BINDING_DRIFT", active_id, "config differs from registry")
        self.registry.audit("RECONCILE", active_id or "none", json.dumps(errors, sort_keys=True))
        return self.status(errors=errors)

    def status(self, *, errors: dict[str, str] | None = None) -> dict[str, object]:
        active_id, generation = self.registry.binding()
        return {
            "schema": "soul.autowire.status.v1",
            "machine_soul_id": self.settings.machine_soul_id,
            "embedding_lock": {
                "provider": self.settings.embedding_provider,
                "dimensions": self.settings.embedding_dimensions,
                "model": self.settings.embedding_model,
            },
            "mode": "shadow",
            "active_provider_id": active_id,
            "generation": generation,
            "providers": self.registry.rows(),
            "discovery_errors": errors or {},
        }

    def activate(self, provider_id: str, *, expected_generation: int) -> dict[str, object]:
        with _activation_lock(self.root / "autowire.activate.lock"):
            # The generation fence is checked while holding the same lock that
            # covers every external side effect.  A loser cannot restart or
            # roll back a winner's live configuration.
            self.registry.assert_generation(expected_generation)
            row = self.registry.get(provider_id)
            if row is None:
                raise ActivationDenied("unknown provider")
            if not bool(row["memory_allowed"]):
                raise ActivationDenied("provider is protocol-compatible but not identity-attested")
            candidate = ProviderCandidate(
                source=str(row["source"]), kind=str(row["kind"]), protocol=str(row["protocol"]),
                origin=str(row["origin"]), base_url=str(row["base_url"]), model=str(row["model"]),
                attestation=str(row["attestation"]), detail=str(row["detail"]),
            )
            candidates, _errors = discover_all()
            if candidate.provider_id not in {item.provider_id for item in candidates}:
                raise ActivationDenied("provider disappeared before activation")
            before = ProxySettings.from_toml(self.config_path)
            embedding_before = (
                before.embedding_provider,before.embedding_dimensions,before.embedding_model,
                before.embedding_url,before.memory_vector_index,
            )
            previous = self.config_path.read_bytes()
            backup = self.root / f"proxy.toml.autowire.{time.time_ns()}.bak"
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, previous)
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.name != "nt":
                os.chmod(backup, 0o600)
            try:
                changed = switch_upstream(
                    self.config_path,
                    upstream_kind=candidate.kind,
                    upstream_base_url=candidate.base_url,
                    upstream_model=candidate.model,
                    restart=True,
                )
                embedding_after = (
                    changed.embedding_provider,changed.embedding_dimensions,changed.embedding_model,
                    changed.embedding_url,changed.memory_vector_index,
                )
                if embedding_after != embedding_before:
                    raise RuntimeError("brain activation changed the embedding lock")
                self._verify_proxy(changed)
                generation = self.registry.commit_binding(
                    provider_id, expected_generation=expected_generation
                )
            except Exception:
                _atomic_config(self.config_path, previous.decode("utf-8"))
                try:
                    from soul_platform.autostart import restart_descriptor, AutostartContract, _current_platform
                    restart_descriptor(AutostartContract.load(self.config_path), _current_platform())
                except Exception:
                    pass
                self.registry.audit("ACTIVATION_ROLLED_BACK", provider_id, hashlib.sha256(previous).hexdigest())
                raise
            self.settings = changed
            self.registry.audit("ACTIVATION_COMMITTED", provider_id, f"generation={generation}")
        # Reconciliation happens after the committed critical section and can
        # never trigger rollback of a successful activation.
        return self.reconcile()

    def _verify_proxy(self, settings: ProxySettings) -> None:
        token = settings.read_token()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )
        deadline = time.monotonic() + 20
        last = "not ready"
        while time.monotonic() < deadline:
            try:
                ready = get_json(f"http://{settings.host}:{settings.port}/ready", timeout=1)
                request = urllib.request.Request(
                    f"http://{settings.host}:{settings.port}/v1/models",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with opener.open(request, timeout=1) as response:
                    raw = response.read(MAX_DISCOVERY_BYTES + 1)
                    if len(raw) > MAX_DISCOVERY_BYTES:
                        raise ValueError("proxy model response too large")
                    payload = strict_json(raw)
                ids = {item.get("id") for item in payload.get("data", []) if isinstance(item, dict)}
                if ready.get("ready") is True and settings.upstream_model in ids:
                    return
                last = "ready/model mismatch"
            except Exception as exc:
                last = type(exc).__name__
            time.sleep(0.2)
        raise RuntimeError(f"post-activation live gate failed: {last}")
