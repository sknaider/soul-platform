#!/usr/bin/env python3
"""Build the deterministic, checksum-bound Windows one-click bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import tomllib

INSTALLER_FILES = (
    "Install-Soul.ps1",
    "Soul-Installer-Recovery.psm1",
    "Instalar-SOUL-Windows.bat",
    "LEEME-WINDOWS.txt",
)
WHEELHOUSE_LOCK = "windows-wheelhouse.lock.json"
ZIP_TIMESTAMP = (2020, 2, 2, 0, 0, 0)
TAR_MTIME = 1_580_601_600
UNIX_DEPENDENCY_NOTICE = """SOUL Platform Unix online installer

The bundled SOUL Platform and SOUL Core wheels are SHA-256 bound.
Third-party dependencies are resolved online as binary wheels from
https://pypi.org/simple with isolated pip configuration. This archive is not an offline
or byte-locked third-party dependency closure.
"""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _zip_entry(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, payload)


def _load_wheelhouse_lock(root: Path) -> tuple[bytes, dict[str, str]]:
    path = root / "installer" / WHEELHOUSE_LOCK
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing safe wheelhouse lock: {WHEELHOUSE_LOCK}")
    payload = path.read_bytes()
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid Windows wheelhouse lock") from exc
    if not isinstance(value, dict) or value.get("schema") != "soul.windows-wheelhouse.v1":
        raise ValueError("invalid Windows wheelhouse lock schema")
    target = value.get("target")
    if target != {"python": "cp313", "platform": "win_amd64"}:
        raise ValueError("Windows wheelhouse lock must target cp313/win_amd64")
    wheels = value.get("wheels")
    if (
        not isinstance(wheels, list)
        or not wheels
        or any(
            not isinstance(item, dict)
            or set(item) != {"name", "sha256"}
            or not isinstance(item["name"], str)
            or not item["name"].endswith(".whl")
            or not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in item["sha256"])
            for item in wheels
        )
    ):
        raise ValueError("Windows wheelhouse lock must contain exact wheel hashes")
    names = [item["name"] for item in wheels]
    if len(names) != len(set(names)) or names != sorted(names, key=str.casefold):
        raise ValueError("Windows wheelhouse lock must contain unique sorted wheels")
    return payload, {item["name"]: item["sha256"] for item in wheels}


def _regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular {label}: {path.name}")
    return path.read_bytes()


def _exact_core_version(project: dict[str, object]) -> str:
    matches = [
        str(item).split("==", 1)[1]
        for item in project.get("dependencies", [])
        if str(item).startswith("soul-framework==")
    ]
    if len(matches) != 1 or not matches[0]:
        raise ValueError("project must pin exactly one soul-framework version")
    return matches[0]


def _locked_wheelhouse(root: Path, wheelhouse: Path) -> tuple[bytes, dict[str, bytes]]:
    lock_payload, locked = _load_wheelhouse_lock(root)
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ValueError("wheelhouse must be a regular directory, not a symlink")
    entries = sorted(wheelhouse.iterdir(), key=lambda item: item.name.casefold())
    if any(item.is_symlink() for item in entries):
        raise ValueError("wheelhouse symlinks are forbidden")
    actual_names = tuple(item.name for item in entries)
    if actual_names != tuple(locked):
        raise ValueError("wheelhouse does not match the exact Windows lock")
    payloads: dict[str, bytes] = {}
    for item in entries:
        payload = _regular_bytes(item, "locked wheel")
        if _sha256(payload) != locked[item.name]:
            raise ValueError(f"locked wheel hash mismatch: {item.name}")
        payloads[item.name] = payload
    return lock_payload, payloads


def build_bundle(
    root: Path,
    wheel: Path,
    core_wheel: Path,
    wheelhouse: Path,
    output: Path,
) -> dict[str, str]:
    root = root.resolve()
    output = output.resolve()
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    version = str(project["version"])
    core_version = _exact_core_version(project)
    expected_wheel = f"soul_platform-{version}-py3-none-any.whl"
    if wheel.name != expected_wheel:
        raise ValueError(f"expected regular release wheel {expected_wheel}")
    wheel_bytes = _regular_bytes(wheel, "release wheel")
    expected_core_wheel = f"soul_framework-{core_version}-py3-none-any.whl"
    if core_wheel.name != expected_core_wheel:
        raise ValueError(f"expected regular SOUL Core wheel {core_version}")
    core_wheel_bytes = _regular_bytes(core_wheel, f"SOUL Core wheel {core_version}")
    installer = root / "installer"
    payloads: dict[str, bytes] = {}
    for name in INSTALLER_FILES:
        path = installer / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing safe installer file: {name}")
        payloads[name] = path.read_bytes()
    if f"SOUL PLATFORM {version}" not in payloads["LEEME-WINDOWS.txt"].decode("utf-8"):
        raise ValueError("Windows guide version does not match pyproject")
    lock_payload, locked_payloads = _locked_wheelhouse(root, wheelhouse)
    payloads[WHEELHOUSE_LOCK] = lock_payload
    wheel_payloads = {
        wheel.name: wheel_bytes,
        core_wheel.name: core_wheel_bytes,
        **locked_payloads,
    }
    if len(wheel_payloads) != len(locked_payloads) + 2:
        raise ValueError("platform/core wheels must not be duplicated in wheelhouse")
    wheel_hash = _sha256(wheel_bytes)
    core_wheel_hash = _sha256(core_wheel_bytes)
    wheel_names = tuple(sorted(wheel_payloads, key=str.casefold))
    wheelhouse_lines: list[str] = []
    for name in wheel_names:
        payload = wheel_payloads[name]
        digest = _sha256(payload)
        payloads[name] = payload
        payloads[f"{name}.sha256"] = f"{digest}  {name}\n".encode()
        wheelhouse_lines.append(f"{digest}  {name}\n")
    payloads["WHEELHOUSE.sha256"] = "".join(wheelhouse_lines).encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        ordered_names = [*INSTALLER_FILES, WHEELHOUSE_LOCK]
        for wheel_name in wheel_names:
            ordered_names.extend((wheel_name, f"{wheel_name}.sha256"))
        ordered_names.append("WHEELHOUSE.sha256")
        for name in ordered_names:
            _zip_entry(archive, name, payloads[name])
    return {
        "version": version,
        "wheel_sha256": wheel_hash,
        "core_wheel_sha256": core_wheel_hash,
        "wheel_count": str(len(wheel_names)),
        "wheelhouse_sha256": _sha256(payloads["WHEELHOUSE.sha256"]),
        "bundle_sha256": _sha256(output.read_bytes()),
        "bundle": str(output),
    }


def build_unix_bundle(
    root: Path, wheel: Path, core_wheel: Path, output: Path
) -> dict[str, str]:
    """Build one deterministic Linux/macOS bundle rooted at ``bundle/``."""
    root = root.resolve()
    wheel = wheel.resolve()
    core_wheel = core_wheel.resolve()
    output = output.resolve()
    if not (output.name.endswith(".tar.gz") or output.name.endswith(".tgz")):
        raise ValueError("Unix bundle output must use .tar.gz or .tgz")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    version = str(project["version"])
    core_version = _exact_core_version(project)
    if wheel.name != f"soul_platform-{version}-py3-none-any.whl" or not wheel.is_file() or wheel.is_symlink():
        raise ValueError("expected regular release wheel")
    if core_wheel.name != f"soul_framework-{core_version}-py3-none-any.whl" or not core_wheel.is_file() or core_wheel.is_symlink():
        raise ValueError(f"expected regular SOUL Core wheel {core_version}")
    installer = root / "installer" / "soul-install.sh"
    if not installer.is_file() or installer.is_symlink():
        raise ValueError("missing safe Unix installer")
    wheel_bytes = wheel.read_bytes()
    core_bytes = core_wheel.read_bytes()
    payloads = {
        "bundle/soul-install.sh": (installer.read_bytes(), 0o755),
        "bundle/ONLINE-DEPENDENCIES.txt": (UNIX_DEPENDENCY_NOTICE.encode(), 0o644),
        f"bundle/{wheel.name}": (wheel_bytes, 0o644),
        f"bundle/{wheel.name}.sha256": (
            f"{_sha256(wheel_bytes)}  {wheel.name}\n".encode(), 0o644
        ),
        f"bundle/{core_wheel.name}": (core_bytes, 0o644),
        f"bundle/{core_wheel.name}.sha256": (
            f"{_sha256(core_bytes)}  {core_wheel.name}\n".encode(), 0o644
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, (payload, mode) in payloads.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    info.mode = mode
                    info.mtime = TAR_MTIME
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    archive.addfile(info, io.BytesIO(payload))
    return {
        "version": version,
        "wheel_sha256": _sha256(wheel_bytes),
        "core_wheel_sha256": _sha256(core_bytes),
        "unix_bundle_sha256": _sha256(output.read_bytes()),
        "dependency_mode": "online-pypi-binary",
        "unix_bundle": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--core-wheel", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--unix-output", type=Path)
    args = parser.parse_args()
    project = tomllib.loads((args.root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    output = (
        args.output
        or args.root / "dist" / f"SOUL-Platform-{project['version']}-Windows.zip"
    )
    result = build_bundle(
        args.root, args.wheel, args.core_wheel, args.wheelhouse, output
    )
    for key, value in result.items():
        print(f"{key}={value}")
    if args.unix_output:
        unix_result = build_unix_bundle(
            args.root, args.wheel, args.core_wheel, args.unix_output
        )
        for key, value in unix_result.items():
            print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
