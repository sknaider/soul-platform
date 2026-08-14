"""Safe, idempotent user-space bootstrap for the machine-wide SOUL proxy."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

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
        "[upstream]\n"
        f"kind = {_toml_string(settings.upstream_kind)}\n"
        f"base_url = {_toml_string(settings.upstream_base_url)}\n"
        f"model = {_toml_string(settings.upstream_model)}\n"
        f"timeout_seconds = {settings.timeout_seconds:g}\n"
        f"api_key_env = {_toml_string(settings.upstream_api_key_env)}\n"
        f"allow_remote = {str(settings.upstream_allow_remote).lower()}\n"
    )


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
        try:
            _create_token(token)
            token_created = True
            settings = ProxySettings(
                soul_name="MachineSoul",
                soul_db=database,
                machine_soul_id=str(uuid.uuid4()),
                host="127.0.0.1",
                port=11435,
                require_auth=True,
                token_file=token,
                upstream_kind=upstream_kind,
                upstream_base_url=upstream_base_url.rstrip("/"),
                upstream_model=upstream_model,
            )
            settings.validate()
            _atomic_config(config, render_config(settings))
            created = True
        except Exception:
            if token_created and token.exists() and not token.is_symlink():
                token.unlink()
            raise
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


def main() -> None:
    parser = argparse.ArgumentParser(prog="soul-machine")
    actions = parser.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init")
    init.add_argument("--root")
    init.add_argument("--kind", default="ollama")
    init.add_argument("--base-url", default="http://127.0.0.1:11434/v1")
    init.add_argument("--model", required=True)
    init.add_argument("--no-autostart", action="store_true")
    switch = actions.add_parser("switch-brain")
    switch.add_argument("--config", required=True)
    switch.add_argument("--kind", required=True)
    switch.add_argument("--base-url", required=True)
    switch.add_argument("--model", required=True)
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
