"""Safe, idempotent user-space bootstrap for the machine-wide SOUL proxy."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
import uuid
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
            machine_soul_id = str(uuid.uuid4())
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
            )
            settings.validate()
            _atomic_config(config, render_config(settings))
            created = True
        except Exception:
            if token_created and token.exists() and not token.is_symlink():
                token.unlink()
            raise
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
    switch = actions.add_parser("switch-brain")
    switch.add_argument("--config", required=True)
    switch.add_argument("--kind", required=True)
    switch.add_argument("--base-url", required=True)
    switch.add_argument("--model", required=True)
    upgrade = actions.add_parser("upgrade-config")
    upgrade.add_argument("--config")
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
