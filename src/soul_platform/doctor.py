"""Fail-closed runtime drift detector for SOUL Platform.

The doctor is deliberately read-only.  It compares installed package metadata,
the private machine-soul configuration, SQLite bytes, the managed autostart
descriptor, and the live loopback proxy.  It never prints the proxy token.
"""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import soul_platform

from soul_platform.autostart import (
    AutostartContract,
    PlatformName,
    _current_platform,
    _loopback_base_url,
    descriptor_path,
    render_linux,
    render_macos,
    render_windows,
)
from soul_platform.proxy import (
    ProxySettings,
    _assert_no_symlink_components,
    _assert_private_owned_file,
    _is_link_or_reparse,
)

REPORT_SCHEMA = "soul.platform.doctor.v1"
MAX_PROBE_BYTES = 65_536
APPROVED_BGE_M3_DIGEST = (
    "7907646426070047a77226ac3e684fbbe8410524f7b4a74d02837e43f2146bab"
)
_CORE_PIN = re.compile(
    r"^soul-framework(?:\[[^\]]+\])?\s*==\s*([^\s;]+)", re.IGNORECASE
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _local_urlopen(request: urllib.request.Request, *, timeout: float):
    """Probe a literal loopback service without ambient proxies or redirects."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()
    )
    return opener.open(request, timeout=timeout)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    details: dict[str, Any]


def _failure(name: str, reason: str, **details: Any) -> DoctorCheck:
    return DoctorCheck(name, False, {"reason": reason, **details})


def _expected_core_version() -> str:
    requirements = metadata.requires("soul-platform") or []
    # The same exact Core pin legitimately appears in base and optional extras.
    # Drift exists only if there is no exact pin or the declared pins disagree.
    pins = {match.group(1) for item in requirements if (match := _CORE_PIN.match(item))}
    if len(pins) != 1:
        raise ValueError("soul-platform must declare exactly one exact soul-framework pin")
    return pins.pop()


def _check_versions() -> DoctorCheck:
    try:
        expected_platform = soul_platform.__version__
        installed_platform = metadata.version("soul-platform")
        expected_core = _expected_core_version()
        installed_core = metadata.version("soul-framework")
    except (metadata.PackageNotFoundError, ValueError) as exc:
        return _failure("versions", type(exc).__name__)
    ok = (
        expected_platform == installed_platform
        and expected_core == installed_core
    )
    return DoctorCheck(
        "versions",
        ok,
        {
            "expected_platform": expected_platform,
            "installed_platform": installed_platform,
            "expected_core": expected_core,
            "installed_core": installed_core,
        },
    )


def _check_config(config: Path) -> tuple[DoctorCheck, ProxySettings | None]:
    try:
        settings = ProxySettings.from_toml(config)
    except (OSError, ValueError) as exc:
        return _failure("config", type(exc).__name__), None
    return (
        DoctorCheck(
            "config",
            True,
            {
                "path": str(config),
                "profile": settings.embedding_provider,
                "dimensions": settings.embedding_dimensions,
                "host": settings.host,
                "port": settings.port,
            },
        ),
        settings,
    )


def _read_only_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2)


def _check_database(settings: ProxySettings) -> DoctorCheck:
    path = settings.soul_db
    try:
        _assert_no_symlink_components(path, "soul.db")
        _assert_private_owned_file(path, "soul.db")
        if _is_link_or_reparse(path):
            raise ValueError("soul.db must not be a symlink/reparse point")
        expected_bytes = settings.embedding_dimensions * 4
        tables: dict[str, dict[str, int]] = {}
        with _read_only_connection(path) as connection:
            quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
            if quick_check != ["ok"]:
                raise sqlite3.DatabaseError("SQLite quick_check failed")
            known_tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            for table in ("memories", "procedural_memories"):
                if table not in known_tables:
                    raise sqlite3.DatabaseError(f"required table is missing: {table}")
                columns = {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")')
                }
                if not {"id", "embedding"}.issubset(columns):
                    raise sqlite3.DatabaseError(f"embedding schema is invalid: {table}")
                total, embedded, missing, wrong = connection.execute(
                    f'SELECT COUNT(*), '
                    f'SUM(CASE WHEN embedding IS NOT NULL THEN 1 ELSE 0 END), '
                    f'SUM(CASE WHEN embedding IS NULL THEN 1 ELSE 0 END), '
                    f'SUM(CASE WHEN embedding IS NOT NULL AND length(embedding) != ? '
                    f'THEN 1 ELSE 0 END) FROM "{table}"',
                    (expected_bytes,),
                ).fetchone()
                tables[table] = {
                    "total": int(total),
                    "embedded": int(embedded or 0),
                    "missing_embeddings": int(missing or 0),
                    "wrong_dimensions": int(wrong or 0),
                }
        wrong_total = sum(item["wrong_dimensions"] for item in tables.values())
        missing_total = sum(item["missing_embeddings"] for item in tables.values())
        return DoctorCheck(
            "database",
            wrong_total == 0 and missing_total == 0,
            {
                "path": str(path),
                "quick_check": "ok",
                "expected_dimensions": settings.embedding_dimensions,
                "expected_embedding_bytes": expected_bytes,
                "tables": tables,
            },
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        return _failure("database", type(exc).__name__, path=str(path))


def _request_json(
    url: str, token: str | None, timeout_seconds: float
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    request = urllib.request.Request(url, headers=headers)
    with _local_urlopen(request, timeout=timeout_seconds) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        payload = response.read(MAX_PROBE_BYTES + 1)
    if len(payload) > MAX_PROBE_BYTES:
        raise ValueError("probe response exceeded the safe limit")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("probe response must be a JSON object")
    return value


def _check_embedding_model(
    settings: ProxySettings, timeout_seconds: float
) -> DoctorCheck:
    if settings.embedding_provider != "bge-m3":
        return DoctorCheck(
            "embedding_model",
            True,
            {"profile": settings.embedding_provider, "status": "not-required"},
        )
    parsed = urlsplit(settings.embedding_url)
    tags_url = urlunsplit((parsed.scheme, parsed.netloc, "/api/tags", "", ""))
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    try:
        tags = _request_json(tags_url, None, timeout_seconds)
        models = tags.get("models")
        if not isinstance(models, list):
            raise ValueError("Ollama tags response is missing models")
        matches = [
            item
            for item in models
            if isinstance(item, dict)
            and (
                item.get("name") in {"bge-m3", "bge-m3:latest"}
                or item.get("model") in {"bge-m3", "bge-m3:latest"}
            )
        ]
        if len(matches) != 1:
            raise ValueError("Ollama must expose exactly one bge-m3 model")
        installed_digest = str(matches[0].get("digest") or "").lower()
        digest_matches = installed_digest == APPROVED_BGE_M3_DIGEST
        return DoctorCheck(
            "embedding_model",
            digest_matches,
            {
                "profile": "bge-m3",
                "model": "bge-m3",
                "origin": origin,
                "expected_digest": APPROVED_BGE_M3_DIGEST,
                "installed_digest": installed_digest,
                "digest_matches": digest_matches,
            },
        )
    except urllib.error.HTTPError as exc:
        return _failure(
            "embedding_model", "HTTPError", status=exc.code, origin=origin
        )
    except (OSError, TimeoutError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return _failure("embedding_model", type(exc).__name__, origin=origin)


def _request_status(url: str, token: str | None, timeout_seconds: float) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with _local_urlopen(request, timeout=timeout_seconds) as response:
            response.read(MAX_PROBE_BYTES + 1)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        # Status alone is evidence.  Never propagate a server body into the report.
        exc.close()
        return int(exc.code)


def _check_runtime(settings: ProxySettings, timeout_seconds: float) -> DoctorCheck:
    base_url = _loopback_base_url(settings.host, settings.port)
    try:
        token = settings.read_token()
        health = _request_json(f"{base_url}/health", token, timeout_seconds)
        ready = _request_json(f"{base_url}/ready", token, timeout_seconds)
        models = _request_json(f"{base_url}/v1/models", token, timeout_seconds)
        models_url = f"{base_url}/v1/models"
        no_token_status = _request_status(models_url, None, timeout_seconds)
        wrong_token_status = _request_status(
            models_url, "soul-doctor-deliberately-invalid", timeout_seconds
        )
        model_ids = [
            str(item.get("id"))
            for item in models.get("data", [])
            if isinstance(item, dict) and item.get("id") is not None
        ]
        ok = (
            health.get("ok") is True
            and health.get("machine_soul_id") == settings.machine_soul_id
            and health.get("baseline_hash") == settings.baseline_hash
            and ready.get("ready") is True
            and ready.get("soul_loaded") is True
            and ready.get("brain_reachable") is True
            and settings.upstream_model in model_ids
            and no_token_status == 401
            and wrong_token_status == 401
        )
        return DoctorCheck(
            "runtime",
            ok,
            {
                "origin": base_url,
                "health": health.get("ok") is True,
                "ready": ready.get("ready") is True,
                "soul_loaded": ready.get("soul_loaded") is True,
                "brain_reachable": ready.get("brain_reachable") is True,
                "model_present": settings.upstream_model in model_ids,
                "identity_matches": health.get("machine_soul_id")
                == settings.machine_soul_id,
                "baseline_matches": health.get("baseline_hash")
                == settings.baseline_hash,
                "authenticated_probe": True,
                "no_token_rejected": no_token_status == 401,
                "wrong_token_rejected": wrong_token_status == 401,
            },
        )
    except urllib.error.HTTPError as exc:
        return _failure("runtime", "HTTPError", status=exc.code, origin=base_url)
    except (OSError, TimeoutError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return _failure("runtime", type(exc).__name__, origin=base_url)


def _render_descriptor(contract: AutostartContract, platform: PlatformName) -> bytes:
    return {
        "linux": render_linux,
        "windows": render_windows,
        "macos": render_macos,
    }[platform](contract)


def _check_autostart(
    settings: ProxySettings,
    config: Path,
    platform: PlatformName,
    home: Path,
    *,
    expected: bool,
) -> DoctorCheck:
    if not expected:
        return DoctorCheck("autostart", True, {"expected": False, "status": "not-required"})
    target = descriptor_path(platform, home)
    try:
        _assert_no_symlink_components(target, "autostart descriptor")
        if _is_link_or_reparse(target) or not target.is_file():
            raise ValueError("managed autostart descriptor is missing or unsafe")
        contract = AutostartContract.load(config, python=sys.executable)
        expected_bytes = _render_descriptor(contract, platform)
        actual_bytes = target.read_bytes()
        ok = actual_bytes == expected_bytes
        return DoctorCheck(
            "autostart",
            ok,
            {
                "expected": True,
                "platform": platform,
                "path": str(target),
                "descriptor_matches": ok,
                "python": str(contract.python),
            },
        )
    except (OSError, ValueError) as exc:
        return _failure(
            "autostart", type(exc).__name__, expected=True, platform=platform, path=str(target)
        )


def run_doctor(
    config: str | os.PathLike[str],
    *,
    platform: PlatformName | None = None,
    home: str | os.PathLike[str] | None = None,
    expect_autostart: bool = True,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Run every read-only check and return a stable JSON-serializable report."""
    config_path = Path(config).expanduser().absolute()
    selected_platform = platform or _current_platform()
    selected_home = Path(home).expanduser().absolute() if home else Path.home()
    checks = [_check_versions()]
    config_check, settings = _check_config(config_path)
    checks.append(config_check)
    if settings is None:
        for name in ("database", "embedding_model", "runtime", "autostart"):
            checks.append(_failure(name, "config-invalid"))
    else:
        checks.extend(
            (
                _check_database(settings),
                _check_embedding_model(settings, timeout_seconds),
                _check_runtime(settings, timeout_seconds),
                _check_autostart(
                    settings,
                    config_path,
                    selected_platform,
                    selected_home,
                    expected=expect_autostart,
                ),
            )
        )
    return {
        "schema": REPORT_SCHEMA,
        "ok": all(check.ok for check in checks),
        "checks": [asdict(check) for check in checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-machine-doctor")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--platform", choices=("linux", "windows", "macos"))
    parser.add_argument("--home", type=Path)
    parser.add_argument("--no-autostart", action="store_true")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args(argv)
    if not 0.1 <= args.timeout <= 30:
        parser.error("--timeout must be between 0.1 and 30 seconds")
    report = run_doctor(
        args.config,
        platform=args.platform,
        home=args.home,
        expect_autostart=not args.no_autostart,
        timeout_seconds=args.timeout,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
