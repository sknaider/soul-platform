"""Safe, idempotent user-space bootstrap for the machine-wide SOUL proxy."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

from soul_platform.autostart import (
    AutostartContract,
    PlatformName,
    _current_platform,
    deactivate_descriptor,
    disable_descriptor,
    install_and_activate_descriptor,
    install_descriptor,
    restart_descriptor,
)
from soul_platform.proxy import ProxySettings
from soul_framework.identity.binding import enroll_legacy_sqlite_identity_binding
from soul_framework.identity.dni import verify_soul_dni


_DNI_RENEWAL_THREAD_LOCK = threading.Lock()


@contextmanager
def _dni_renewal_lock(path: Path):
    """Serialize the read/verify/promote DNI transaction across processes."""

    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("DNI renewal lock must be a regular file")
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)
    with _DNI_RENEWAL_THREAD_LOCK:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "a+b") as handle:
            if os.name != "nt":
                os.chmod(path, 0o600)
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


@dataclass(frozen=True)
class BootstrapResult:
    root: Path
    config: Path
    token_file: Path
    soul_db: Path
    machine_soul_id: str
    autostart: Path | None
    created: bool


def default_root(platform: PlatformName | None = None, *, home: Path | None = None) -> Path:
    platform = platform or _current_platform()
    home = (home or Path.home()).resolve()
    if platform == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return base / "SOUL"
    if platform == "macos":
        return home / "Library" / "Application Support" / "SOUL"
    return home / ".local" / "share" / "soul"


def _private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlinked SOUL directory: {path}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"SOUL root exists but is not a directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)


def _create_token(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (secrets.token_urlsafe(48) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name != "nt":
        os.chmod(path, 0o600)


def _toml_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def render_config(settings: ProxySettings) -> str:
    return (
        "# SOUL machine identity. The model can change; these values remain.\n"
        "[soul]\n"
        f"name = {_toml_string(settings.soul_name)}\n"
        f"db = {_toml_string(settings.soul_db)}\n"
        f"machine_soul_id = {_toml_string(settings.machine_soul_id)}\n\n"
        f"dni = {_toml_string(settings.soul_dni)}\n"
        f"dni_credential_file = {_toml_string(settings.dni_credential_file)}\n"
        f"dni_trust_store_file = {_toml_string(settings.dni_trust_store_file)}\n"
        f"dni_trust_store_sha256 = {_toml_string(settings.dni_trust_store_sha256)}\n\n"
        "[embedding]\n"
        f"provider = {_toml_string(settings.embedding_provider)}\n"
        f"dimensions = {settings.embedding_dimensions}\n"
        f"model = {_toml_string(settings.embedding_model)}\n"
        f"url = {_toml_string(settings.embedding_url)}\n"
        f"timeout_seconds = {settings.embedding_timeout_seconds:g}\n"
        f"vector_index = {_toml_string(settings.memory_vector_index)}\n\n"
        "[proxy]\n"
        f"host = {_toml_string(settings.host)}\n"
        f"port = {settings.port}\n"
        "require_auth = true\n"
        f"token_file = {_toml_string(settings.token_file)}\n"
        f"mem_k = {settings.mem_k}\n"
        f"auto_store = {str(settings.auto_store).lower()}\n"
        f"max_request_bytes = {settings.max_request_bytes}\n\n"
        f"max_response_bytes = {settings.max_response_bytes}\n\n"
        "[memory_egress]\n"
        f"mode = {_toml_string(settings.t5_mode)}\n"
        f"tenant = {_toml_string(settings.t5_tenant)}\n"
        f"owner_subject = {_toml_string(settings.t5_owner_subject)}\n"
        f"state_db = {_toml_string(settings.t5_state_path)}\n"
        + (
            f"principal_keys_file = {_toml_string(settings.t5_principal_keys_file)}\n"
            if settings.t5_principal_keys_file is not None
            else ""
        )
        + "\n"
        "[upstream]\n"
        f"kind = {_toml_string(settings.upstream_kind)}\n"
        f"base_url = {_toml_string(settings.upstream_base_url)}\n"
        f"model = {_toml_string(settings.upstream_model)}\n"
        f"timeout_seconds = {settings.timeout_seconds:g}\n"
        f"api_key_env = {_toml_string(settings.upstream_api_key_env)}\n"
        f"allow_remote = {str(settings.upstream_allow_remote).lower()}\n"
    )


def _ensure_profile_before_return(settings: ProxySettings) -> dict[str, object]:
    """Run the async Core bootstrap from every synchronous initialize caller.

    ``initialize`` is also used by async test/application code. Running the
    coroutine in a short dedicated thread in that case preserves the stronger
    invariant that the function never returns an empty machine soul.
    """

    from soul_platform.living_soul import ensure_initial_profile

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(ensure_initial_profile(settings))
    result: list[dict[str, object]] = []
    failure: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(ensure_initial_profile(settings)))
        except BaseException as exc:  # propagate the original failure to the caller
            failure.append(exc)

    worker = threading.Thread(target=runner, name="soul-profile-bootstrap")
    worker.start()
    worker.join()
    if failure:
        raise failure[0]
    if len(result) != 1:
        raise RuntimeError("SOUL profile bootstrap returned no result")
    return result[0]


def _require_owner_tty_confirmation(*, expected_digest: str, subject: str) -> None:
    """Require an interactive local-owner act before a canonical mutation."""

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise PermissionError(f"{subject} approval requires an interactive owner TTY")
    sys.stdout.write(
        f"Owner approval for {subject}. Retype exact digest {expected_digest}: "
    )
    sys.stdout.flush()
    supplied = sys.stdin.readline()
    if not supplied:
        raise PermissionError(f"{subject} approval was not confirmed")
    import hmac

    if not hmac.compare_digest(supplied.strip(), expected_digest):
        raise PermissionError(f"{subject} approval digest confirmation failed")


def _atomic_config(path: Path, content: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_new_text(path: Path, content: str) -> None:
    """Publish a new private file without ever replacing an existing path."""

    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def initialize(
    *,
    root: Path,
    upstream_kind: str,
    upstream_base_url: str,
    upstream_model: str,
    python: str | None = None,
    platform: PlatformName | None = None,
    home: Path | None = None,
    enable_autostart: bool = True,
    activate_autostart: bool = True,
    dni_credential: Path | None = None,
    dni_trust_store: Path | None = None,
    dni_trust_store_sha256: str | None = None,
) -> BootstrapResult:
    root = root.expanduser()
    platform = platform or _current_platform()
    if platform == "windows":
        expected = default_root("windows", home=home).resolve()
        if root.resolve() != expected:
            raise ValueError("Windows SOUL root must be %LOCALAPPDATA%\\SOUL")
    if root.is_symlink():
        raise ValueError(f"refusing symlinked SOUL directory: {root}")
    root = root.resolve()
    _private_dir(root)
    config, token, database = root / "proxy.toml", root / "proxy.token", root / "MachineSoul.db"
    created = False
    if config.exists():
        settings = ProxySettings.from_toml(config)
        if settings.soul_db.parent != root or settings.token_file != token:
            raise ValueError("existing config points outside the canonical SOUL root")
        database = settings.soul_db
    else:
        if token.exists() or token.is_symlink():
            raise ValueError("token exists without a config; refusing ambiguous partial install")
        token_created = False
        dni_created: list[Path] = []
        try:
            credential_source = dni_credential or (
                Path(os.environ["SOUL_DNI_CREDENTIAL"])
                if os.environ.get("SOUL_DNI_CREDENTIAL")
                else None
            )
            trust_source = dni_trust_store or (
                Path(os.environ["SOUL_DNI_TRUST_STORE"])
                if os.environ.get("SOUL_DNI_TRUST_STORE")
                else None
            )
            trust_digest = dni_trust_store_sha256 or os.environ.get(
                "SOUL_DNI_TRUST_STORE_SHA256", ""
            )
            if credential_source is None or trust_source is None or not trust_digest:
                raise PermissionError(
                    "SOUL Identity Authority must issue a DNI before Core/Platform install"
                )
            verified_dni = verify_soul_dni(
                credential_source,
                trust_source,
                expected_audience="soul-platform",
                expected_trust_store_sha256=trust_digest,
            )
            _create_token(token)
            token_created = True
            credential = root / "soul-dni.json"
            trust_store = root / "soul-dni-trust.json"
            _atomic_new_text(
                credential,
                verified_dni.credential_bytes.decode("utf-8"),
            )
            dni_created.append(credential)
            _atomic_new_text(
                trust_store,
                verified_dni.trust_store_bytes.decode("utf-8"),
            )
            dni_created.append(trust_store)
            machine_soul_id = verified_dni.machine_soul_id
            settings = ProxySettings(
                soul_name="MachineSoul",
                soul_db=database,
                machine_soul_id=machine_soul_id,
                host="127.0.0.1",
                port=11435,
                require_auth=True,
                token_file=token,
                upstream_kind=upstream_kind,
                upstream_base_url=upstream_base_url.rstrip("/"),
                upstream_model=upstream_model,
                t5_mode="compatibility-single-owner",
                t5_tenant="local-machine",
                t5_owner_subject=f"local-owner:{machine_soul_id}",
                t5_state_db=root / "MachineSoul.t5-egress.sqlite3",
                soul_dni=verified_dni.soul_dni,
                dni_credential_file=credential,
                dni_trust_store_file=trust_store,
                dni_trust_store_sha256=trust_digest,
            )
            settings.validate()
            _atomic_config(config, render_config(settings))
            created = True
        except Exception:
            if token_created and token.exists() and not token.is_symlink():
                token.unlink()
            for path in dni_created:
                path.unlink(missing_ok=True)
            raise
    # Bind the physical database before the living-profile bootstrap writes
    # identity/rules. Otherwise a fresh install would become a populated,
    # unbound "legacy" database before Core ever sees it.
    if not database.exists():
        import sqlite3

        connection = sqlite3.connect(database)
        connection.close()
        if os.name != "nt":
            os.chmod(database, 0o600)
    enroll_legacy_sqlite_identity_binding(
        database, settings.verified_dni("soul-platform")
    )

    # ``initialize`` itself owns this invariant. Installers may repeat the
    # check, but no direct Python/CLI caller can receive an empty MachineSoul.
    _ensure_profile_before_return(settings)
    autostart = None
    if enable_autostart:
        contract = AutostartContract.load(config, python=python)
        if activate_autostart:
            autostart = install_and_activate_descriptor(
                contract, platform, home=home
            )
        else:
            autostart = install_descriptor(contract, platform, home=home)
    return BootstrapResult(
        root=root,
        config=config,
        token_file=token,
        soul_db=database,
        machine_soul_id=settings.machine_soul_id,
        autostart=autostart,
        created=created,
    )


def switch_upstream(
    config: Path,
    *,
    upstream_kind: str,
    upstream_base_url: str,
    upstream_model: str,
    allow_remote: bool = False,
    restart: bool = False,
    platform: PlatformName | None = None,
    home: Path | None = None,
) -> ProxySettings:
    """Change only the brain. Machine soul identity, DB and token are preserved."""
    current = ProxySettings.from_toml(config)
    changed = replace(
        current,
        upstream_kind=upstream_kind,
        upstream_base_url=upstream_base_url.rstrip("/"),
        upstream_model=upstream_model,
        upstream_allow_remote=allow_remote,
    )
    changed.validate()
    previous = config.read_text(encoding="utf-8")
    _atomic_config(config, render_config(changed))
    try:
        reloaded = ProxySettings.from_toml(config)
        if (
            reloaded.machine_soul_id != current.machine_soul_id
            or reloaded.baseline_hash != current.baseline_hash
            or reloaded.token_file != current.token_file
        ):
            raise RuntimeError("brain switch changed the machine soul invariant")
        if restart:
            restart_descriptor(
                AutostartContract.load(config), platform or _current_platform(), home=home
            )
        return reloaded
    except Exception:
        _atomic_config(config, previous)
        if restart:
            try:
                restart_descriptor(
                    AutostartContract.load(config), platform or _current_platform(), home=home
                )
            except Exception:
                pass
        raise


def enroll_dni(
    config: Path,
    *,
    dni_credential: Path,
    dni_trust_store: Path,
    dni_trust_store_sha256: str,
) -> ProxySettings:
    """Owner migration: bind a legacy SQLite soul to an SIA-issued DNI."""

    import tomllib

    config = config.expanduser()
    if not config.is_absolute() or config.is_symlink() or not config.is_file():
        raise ValueError("legacy config must be an absolute regular file")
    root = config.parent.resolve()
    before = config.read_bytes()
    text = before.decode("utf-8")
    raw = tomllib.loads(text)
    soul = raw.get("soul")
    if not isinstance(soul, dict):
        raise ValueError("legacy config has no soul section")
    if soul.get("dni"):
        # Idempotent crash recovery: config/DNI promotion may have completed
        # before the legacy DB binding.  Re-verify the installed identity and
        # finish that binding instead of returning a superficially valid but
        # unusable partial migration.
        settings = ProxySettings.from_toml(config)
        verified = settings.verified_dni("soul-platform")
        enroll_legacy_sqlite_identity_binding(settings.soul_db, verified)
        return settings
    machine_soul_id = str(soul.get("machine_soul_id") or "")
    verified = verify_soul_dni(
        dni_credential,
        dni_trust_store,
        expected_audience="soul-platform",
        expected_machine_soul_id=machine_soul_id,
        expected_trust_store_sha256=dni_trust_store_sha256,
    )
    credential_target = root / "soul-dni.json"
    trust_target = root / "soul-dni-trust.json"
    if any(path.exists() or path.is_symlink() for path in (credential_target, trust_target)):
        raise ValueError("DNI files already exist without a config binding")
    section_end = min(
        (position for position in (text.find("\n[embedding]"), text.find("\n[proxy]")) if position >= 0),
        default=-1,
    )
    if section_end < 0:
        raise ValueError("legacy soul section has no following section")
    addition = (
        f"\ndni = {_toml_string(verified.soul_dni)}"
        f"\ndni_credential_file = {_toml_string(credential_target)}"
        f"\ndni_trust_store_file = {_toml_string(trust_target)}"
        f"\ndni_trust_store_sha256 = {_toml_string(dni_trust_store_sha256)}"
    )
    migrated = text[:section_end] + addition + text[section_end:]
    digest = hashlib.sha256(before).hexdigest()[:16]
    backup = config.with_name(f"{config.name}.pre-dni-{digest}.bak")
    if backup.exists() and backup.read_bytes() != before:
        raise RuntimeError("existing DNI migration backup does not match legacy config")
    if not backup.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(backup, flags, 0o600)
        try:
            os.write(descriptor, before)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    created: list[Path] = []
    try:
        _atomic_new_text(
            credential_target,
            verified.credential_bytes.decode("utf-8"),
        )
        created.append(credential_target)
        _atomic_new_text(
            trust_target,
            verified.trust_store_bytes.decode("utf-8"),
        )
        created.append(trust_target)
        _atomic_config(config, migrated)
        settings = ProxySettings.from_toml(config)
        if settings.machine_soul_id != machine_soul_id:
            raise RuntimeError("DNI enrollment changed machine_soul_id")
        installed = settings.verified_dni("soul-platform")
        if (
            installed.sequence != verified.sequence
            or installed.trust_sequence != verified.trust_sequence
        ):
            raise RuntimeError("DNI enrollment promoted bytes other than the verified generation")
        enroll_legacy_sqlite_identity_binding(settings.soul_db, verified)
        return settings
    except Exception:
        _atomic_config(config, text)
        for path in created:
            path.unlink(missing_ok=True)
        raise


def renew_dni(
    config: Path,
    *,
    dni_credential: Path,
    dni_trust_store: Path,
    dni_trust_store_sha256: str,
) -> ProxySettings:
    """Install a strictly newer SIA credential without opening the soul DB."""

    config = config.expanduser()
    if not config.is_absolute() or config.is_symlink() or not config.is_file():
        raise ValueError("DNI renewal config must be an absolute regular file")
    root = config.parent.resolve()
    with _dni_renewal_lock(root / ".dni-renew.lock"):
        return _renew_dni_locked(
            config,
            dni_credential=dni_credential,
            dni_trust_store=dni_trust_store,
            dni_trust_store_sha256=dni_trust_store_sha256,
        )


def _renew_dni_locked(
    config: Path,
    *,
    dni_credential: Path,
    dni_trust_store: Path,
    dni_trust_store_sha256: str,
) -> ProxySettings:
    """Read, verify and promote while holding the interprocess renewal lock."""

    import tomllib

    root = config.parent.resolve()
    before_config = config.read_bytes()
    text = before_config.decode("utf-8")
    raw = tomllib.loads(text)
    soul = raw.get("soul")
    if not isinstance(soul, dict):
        raise ValueError("SOUL config has no soul section")
    machine_soul_id = str(soul.get("machine_soul_id") or "")
    soul_dni = str(soul.get("dni") or "")
    credential_target = Path(str(soul.get("dni_credential_file") or ""))
    trust_target = Path(str(soul.get("dni_trust_store_file") or ""))
    if credential_target != root / "soul-dni.json" or trust_target != root / "soul-dni-trust.json":
        raise ValueError("DNI renewal targets are outside the canonical SOUL root")
    if any(path.is_symlink() or not path.is_file() for path in (credential_target, trust_target)):
        raise ValueError("current DNI files must be regular files")
    current_digest = str(soul.get("dni_trust_store_sha256") or "")
    current = verify_soul_dni(
        credential_target,
        trust_target,
        expected_audience="soul-platform",
        expected_machine_soul_id=machine_soul_id,
        expected_trust_store_sha256=current_digest,
        allow_expired=True,
    )
    if current.soul_dni != soul_dni:
        raise PermissionError("installed DNI does not match the configured soul identity")
    old_sequence = current.sequence
    old_trust_sequence = current.trust_sequence
    verified = verify_soul_dni(
        dni_credential,
        dni_trust_store,
        expected_audience="soul-platform",
        expected_machine_soul_id=machine_soul_id,
        expected_trust_store_sha256=dni_trust_store_sha256,
    )
    if verified.soul_dni != soul_dni:
        raise PermissionError("DNI renewal cannot replace the sovereign soul identity")
    if verified.sequence <= old_sequence:
        raise PermissionError("DNI renewal sequence must increase monotonically")
    if verified.trust_sequence <= old_trust_sequence:
        raise PermissionError("DNI trust sequence must increase monotonically")
    # Publish the exact bytes that passed signature/digest verification.  A
    # second path read here would allow a source-file swap between verify and
    # promotion.
    new_credential = verified.credential_bytes.decode("utf-8")
    new_trust = verified.trust_store_bytes.decode("utf-8")
    before_credential = credential_target.read_text(encoding="utf-8")
    before_trust = trust_target.read_text(encoding="utf-8")
    digest_pattern = re.compile(r"(?m)^dni_trust_store_sha256\s*=\s*[^\r\n]+$")
    migrated, replacements = digest_pattern.subn(
        f"dni_trust_store_sha256 = {_toml_string(dni_trust_store_sha256)}",
        text,
    )
    if replacements != 1:
        raise ValueError("SOUL config has an ambiguous DNI trust digest")
    try:
        _atomic_config(credential_target, new_credential)
        _atomic_config(trust_target, new_trust)
        _atomic_config(config, migrated)
        renewed = ProxySettings.from_toml(config)
        if renewed.machine_soul_id != machine_soul_id or renewed.soul_dni != soul_dni:
            raise RuntimeError("DNI renewal changed a sovereign identity invariant")
        renewed_verified = renewed.verified_dni("soul-platform")
        if (
            renewed_verified.sequence != verified.sequence
            or renewed_verified.trust_sequence != verified.trust_sequence
        ):
            raise RuntimeError("DNI renewal promoted bytes other than the verified generation")
        return renewed
    except Exception:
        _atomic_config(credential_target, before_credential)
        _atomic_config(trust_target, before_trust)
        _atomic_config(config, text)
        raise


def upgrade_config(config: Path) -> ProxySettings:
    """Add current fail-closed sections to an older config without moving its soul.

    The only automatic compatibility promotion is the existing single-owner
    local machine profile.  Explicit ``locked`` or ``enforce`` configurations
    are never weakened.
    """

    config = config.expanduser().resolve()
    before_bytes = config.read_bytes()
    before_text = before_bytes.decode("utf-8")
    current = ProxySettings.from_toml(config)
    if "[memory_egress]" in before_text:
        return current
    changed = replace(
        current,
        t5_mode="compatibility-single-owner",
        t5_tenant="local-machine",
        t5_owner_subject=f"local-owner:{current.machine_soul_id}",
        t5_state_db=config.parent / "MachineSoul.t5-egress.sqlite3",
        t5_principal_keys_file=None,
    )
    changed.validate()
    digest = hashlib.sha256(before_bytes).hexdigest()[:16]
    backup = config.with_name(f"{config.name}.pre-t5-{digest}.bak")
    if backup.exists() and backup.read_bytes() != before_bytes:
        raise RuntimeError("existing config backup does not match current legacy bytes")
    if not backup.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(backup, flags, 0o600)
        try:
            os.write(fd, before_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)
        if os.name != "nt":
            os.chmod(backup, 0o600)
    _atomic_config(config, render_config(changed))
    try:
        verified = ProxySettings.from_toml(config)
        if (
            verified.machine_soul_id != current.machine_soul_id
            or verified.soul_db != current.soul_db
            or verified.token_file != current.token_file
            or verified.embedding_provider != current.embedding_provider
            or verified.embedding_dimensions != current.embedding_dimensions
            or verified.embedding_model != current.embedding_model
        ):
            raise RuntimeError("config upgrade changed a machine-soul invariant")
        return verified
    except Exception:
        _atomic_config(config, before_text)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(prog="soul-machine")
    actions = parser.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init")
    init.add_argument("--root")
    init.add_argument("--kind", default="ollama")
    init.add_argument("--base-url", default="http://127.0.0.1:11434/v1")
    init.add_argument("--model", required=True)
    init.add_argument("--no-autostart", action="store_true")
    init.add_argument("--dni-credential", type=Path)
    init.add_argument("--dni-trust-store", type=Path)
    init.add_argument("--dni-trust-store-sha256")
    switch = actions.add_parser("switch-brain")
    switch.add_argument("--config", required=True)
    switch.add_argument("--kind", required=True)
    switch.add_argument("--base-url", required=True)
    switch.add_argument("--model", required=True)
    upgrade = actions.add_parser("upgrade-config")
    upgrade.add_argument("--config")
    enroll = actions.add_parser("enroll-dni")
    enroll.add_argument("--config", required=True, type=Path)
    enroll.add_argument("--dni-credential", required=True, type=Path)
    enroll.add_argument("--dni-trust-store", required=True, type=Path)
    enroll.add_argument("--dni-trust-store-sha256", required=True)
    renew = actions.add_parser("renew-dni")
    renew.add_argument("--config", required=True, type=Path)
    renew.add_argument("--dni-credential", required=True, type=Path)
    renew.add_argument("--dni-trust-store", required=True, type=Path)
    renew.add_argument("--dni-trust-store-sha256", required=True)
    acquire_online = actions.add_parser("acquire-dni-online")
    acquire_online.add_argument("--root", required=True, type=Path)
    acquire_online.add_argument("--endpoint", required=True)
    token_source = acquire_online.add_mutually_exclusive_group(required=True)
    token_source.add_argument("--enrollment-token-stdin", action="store_true")
    token_source.add_argument("--enrollment-token-file", type=Path)
    acquire_online.add_argument("--machine-soul-id")
    acquire_online.add_argument("--timeout", type=float, default=15.0)
    renew_online = actions.add_parser("renew-dni-online")
    renew_online.add_argument("--config", required=True, type=Path)
    renew_online.add_argument("--timeout", type=float, default=15.0)
    renew_online.add_argument("--no-restart", action="store_true")
    profile = actions.add_parser("ensure-profile")
    profile.add_argument("--config")
    consent = actions.add_parser("context-consent")
    consent.add_argument("operation", choices=("grant", "revoke", "status"))
    consent.add_argument("--client", choices=("codex", "claude"), required=True)
    consent.add_argument("--ttl-days", type=int, default=365)
    consent.add_argument("--config")
    candidates = actions.add_parser("memory-candidates")
    candidates.add_argument("operation", choices=("list", "approve"))
    candidates.add_argument("--candidate-id")
    candidates.add_argument("--digest")
    candidates.add_argument("--status", default="pending")
    candidates.add_argument("--limit", type=int, default=50)
    candidates.add_argument("--config")
    proposals = actions.add_parser("profile-proposals")
    proposals.add_argument("operation", choices=("list", "propose", "approve"))
    proposals.add_argument(
        "--kind", choices=("identity", "ocean", "rule", "relationship")
    )
    proposals.add_argument("--patch-json")
    proposals.add_argument("--source-event-id")
    proposals.add_argument("--client-id", default="local-owner-cli")
    proposals.add_argument("--proposal-id")
    proposals.add_argument("--digest")
    proposals.add_argument("--status", default="pending")
    proposals.add_argument("--limit", type=int, default=50)
    proposals.add_argument("--config")
    for name in ("disable-autostart", "uninstall"):
        disable = actions.add_parser(name)
        disable.add_argument("--config")
    args = parser.parse_args()
    if args.action == "init":
        result = initialize(
            root=Path(args.root).expanduser() if args.root else default_root(),
            upstream_kind=args.kind,
            upstream_base_url=args.base_url,
            upstream_model=args.model,
            enable_autostart=not args.no_autostart,
            dni_credential=args.dni_credential,
            dni_trust_store=args.dni_trust_store,
            dni_trust_store_sha256=args.dni_trust_store_sha256,
        )
        print(f"machine_soul_id={result.machine_soul_id}")
        print(f"config={result.config}")
        print(f"data={result.soul_db} (preserved on uninstall)")
        if result.autostart:
            print(f"autostart={result.autostart}")
    elif args.action == "switch-brain":
        result = switch_upstream(
            Path(args.config).expanduser().resolve(),
            upstream_kind=args.kind,
            upstream_base_url=args.base_url,
            upstream_model=args.model,
            restart=True,
        )
        print(f"brain={result.upstream_kind}:{result.upstream_model}")
        print(f"machine_soul_id={result.machine_soul_id} (unchanged)")
    elif args.action == "upgrade-config":
        config = (
            Path(args.config).expanduser().resolve()
            if args.config
            else default_root() / "proxy.toml"
        )
        result = upgrade_config(config)
        print(f"config={config}")
        print(f"memory_egress={result.t5_mode}")
        print(f"machine_soul_id={result.machine_soul_id} (unchanged)")
    elif args.action == "enroll-dni":
        result = enroll_dni(
            args.config.expanduser().resolve(),
            dni_credential=args.dni_credential.expanduser().resolve(),
            dni_trust_store=args.dni_trust_store.expanduser().resolve(),
            dni_trust_store_sha256=args.dni_trust_store_sha256,
        )
        print(f"soul_dni={result.soul_dni}")
        print(f"machine_soul_id={result.machine_soul_id} (unchanged)")
    elif args.action == "renew-dni":
        config = args.config.expanduser().resolve()
        result = renew_dni(
            config,
            dni_credential=args.dni_credential.expanduser().resolve(),
            dni_trust_store=args.dni_trust_store.expanduser().resolve(),
            dni_trust_store_sha256=args.dni_trust_store_sha256,
        )
        restart_descriptor(
            AutostartContract.load(config), _current_platform()
        )
        print(f"soul_dni={result.soul_dni} (unchanged)")
        print("dni_renewal=active (daemon restarted)")
    elif args.action == "acquire-dni-online":
        from soul_platform.dni_online import _read_private_file, acquire_dni_online

        if args.enrollment_token_stdin:
            token_payload = sys.stdin.buffer.read(257)
            if len(token_payload) > 256:
                raise ValueError("DNI enrollment token is too large")
        else:
            token_payload = _read_private_file(
                args.enrollment_token_file.expanduser().resolve(),
                "DNI enrollment token",
                limit=256,
            )
        token_payload = token_payload.rstrip(b"\r\n")
        if (
            not token_payload
            or b"\0" in token_payload
            or b"\r" in token_payload
            or b"\n" in token_payload
        ):
            raise ValueError("DNI enrollment token must be one non-empty line")
        try:
            enrollment_token = token_payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("DNI enrollment token must be ASCII") from exc
        if not 32 <= len(enrollment_token) <= 128:
            raise ValueError("DNI enrollment token length is invalid")

        try:
            result = acquire_dni_online(
                root=args.root,
                endpoint=args.endpoint,
                enrollment_token=enrollment_token,
                machine_soul_id=args.machine_soul_id,
                timeout=args.timeout,
            )
        finally:
            enrollment_token = ""
            token_payload = b""
        print(f"soul_dni={result.soul_dni}")
        print(f"machine_soul_id={result.machine_soul_id}")
        print(f"dni_credential={result.credential}")
        print(f"dni_trust_store={result.trust_store}")
        print(f"dni_trust_store_sha256={result.trust_store_sha256}")
    elif args.action == "renew-dni-online":
        from soul_platform.dni_online import renew_dni_online

        result = renew_dni_online(
            config=args.config,
            timeout=args.timeout,
            restart=not args.no_restart,
        )
        print(f"soul_dni={result.soul_dni} (unchanged)")
        print("dni_online_renewal=active")
    elif args.action == "ensure-profile":
        from soul_platform.living_soul import ensure_initial_profile

        config = (
            Path(args.config).expanduser().resolve()
            if args.config
            else default_root() / "proxy.toml"
        )
        settings = ProxySettings.from_toml(config)
        result = asyncio.run(ensure_initial_profile(settings))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif args.action == "context-consent":
        from soul_platform.context_consent import (
            issue_context_consent,
            prepare_context_consent,
            revoke_context_consent,
            verify_context_consent,
        )

        config = (
            Path(args.config).expanduser().resolve()
            if args.config
            else default_root() / "proxy.toml"
        )
        settings = ProxySettings.from_toml(config)
        if args.operation == "grant":
            prepared = prepare_context_consent(
                settings, args.client, ttl_days=args.ttl_days
            )
            print(json.dumps(prepared, ensure_ascii=False, sort_keys=True))
            _require_owner_tty_confirmation(
                expected_digest=prepared["confirmation_sha256"],
                subject=f"{args.client} private-context consent",
            )
            result = issue_context_consent(
                settings,
                args.client,
                ttl_days=args.ttl_days,
                expected_snapshot_sha256=prepared["context_snapshot_sha256"],
            )
        elif args.operation == "revoke":
            result = revoke_context_consent(settings, args.client)
        else:
            result = verify_context_consent(settings, args.client)
        print(json.dumps({"valid": result is not None, "grant": result}, ensure_ascii=False, sort_keys=True))
    elif args.action == "memory-candidates":
        from soul_platform.living_soul import (
            list_memory_candidates,
            promote_memory_candidate,
        )

        config = (
            Path(args.config).expanduser().resolve()
            if args.config
            else default_root() / "proxy.toml"
        )
        settings = ProxySettings.from_toml(config)
        if args.operation == "list":
            result = list_memory_candidates(settings, status=args.status, limit=args.limit)
        else:
            if not args.candidate_id or not args.digest:
                raise SystemExit("approve requires --candidate-id and --digest")
            _require_owner_tty_confirmation(
                expected_digest=args.digest, subject="memory candidate"
            )
            result = asyncio.run(
                promote_memory_candidate(
                    settings,
                    candidate_id=args.candidate_id,
                    expected_sha256=args.digest,
                )
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif args.action == "profile-proposals":
        from soul_platform.living_soul import (
            approve_profile_proposal,
            list_profile_proposals,
            propose_profile_change,
        )

        config = (
            Path(args.config).expanduser().resolve()
            if args.config
            else default_root() / "proxy.toml"
        )
        settings = ProxySettings.from_toml(config)
        if args.operation == "list":
            result = list_profile_proposals(
                settings, status=args.status, limit=args.limit
            )
        elif args.operation == "propose":
            if not args.kind or not args.patch_json or not args.source_event_id:
                raise SystemExit(
                    "propose requires --kind, --patch-json and --source-event-id"
                )
            try:
                patch = json.loads(args.patch_json)
            except json.JSONDecodeError as exc:
                raise SystemExit("--patch-json must be valid JSON") from exc
            result = propose_profile_change(
                settings,
                client_id=args.client_id,
                source_event_id=args.source_event_id,
                change_kind=args.kind,
                patch=patch,
            )
        else:
            if not args.proposal_id or not args.digest:
                raise SystemExit("approve requires --proposal-id and --digest")
            _require_owner_tty_confirmation(
                expected_digest=args.digest, subject="profile proposal"
            )
            result = asyncio.run(
                approve_profile_proposal(
                    settings,
                    proposal_id=args.proposal_id,
                    expected_sha256=args.digest,
                )
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        config = (
            Path(args.config).expanduser().resolve()
            if args.config
            else default_root() / "proxy.toml"
        )
        if config.exists():
            target = deactivate_descriptor(
                AutostartContract.load(config), _current_platform()
            )
        else:
            target = disable_descriptor(_current_platform())
        action = "runtime uninstalled" if args.action == "uninstall" else "autostart disabled"
        print(f"{action}; soul data preserved: {target}")


if __name__ == "__main__":
    main()
