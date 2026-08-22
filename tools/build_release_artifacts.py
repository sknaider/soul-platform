#!/usr/bin/env python3
"""Build the complete SOUL Platform release with one canonical epoch."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata as metadata
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import tomllib

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from build_windows_bundle import build_bundle, build_unix_bundle  # noqa: E402


RELEASE_EPOCH = 1_580_601_600
BUILD_VERSION = "1.5.0"
HATCHLING_VERSION = "1.32.0"
RECEIPT_SCHEMA = "soul.platform-release.v2"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _assert_no_symlink_components(path: Path, label: str) -> None:
    absolute = _absolute(path)
    for component in reversed((absolute, *absolute.parents)):
        if component.is_symlink():
            raise ValueError(f"{label} contains a symlink: {component}")


def _regular_file(path: Path, label: str) -> Path:
    _assert_no_symlink_components(path, label)
    resolved = _absolute(path)
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"expected regular {label}: {resolved}")
    return resolved


def _regular_directory(path: Path, label: str) -> Path:
    _assert_no_symlink_components(path, label)
    resolved = _absolute(path)
    if not resolved.is_dir() or resolved.is_symlink():
        raise ValueError(f"expected regular {label}: {resolved}")
    return resolved


def _prepare_output(output: Path) -> Path:
    output = _absolute(output)
    _assert_no_symlink_components(output, "output path")
    if output.exists():
        raise FileExistsError(f"release output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_symlink_components(output.parent, "output parent")
    return output


def _canonical_zip_timestamp() -> tuple[int, int, int, int, int, int]:
    value = dt.datetime.fromtimestamp(RELEASE_EPOCH, dt.UTC)
    return (value.year, value.month, value.day, value.hour, value.minute, value.second)


def _verify_build_timestamps(wheel: Path, sdist: Path) -> None:
    expected_zip = _canonical_zip_timestamp()
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        if not entries or any(entry.date_time != expected_zip for entry in entries):
            raise RuntimeError("wheel does not use the canonical release epoch")
    with sdist.open("rb") as handle:
        header = handle.read(10)
    if len(header) != 10 or header[:2] != b"\x1f\x8b":
        raise RuntimeError("sdist is not a valid gzip stream")
    if struct.unpack("<I", header[4:8])[0] != RELEASE_EPOCH:
        raise RuntimeError("sdist gzip header does not use the canonical release epoch")
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        if not members or any(member.mtime != RELEASE_EPOCH for member in members):
            raise RuntimeError("sdist members do not use the canonical release epoch")


def _artifact_record(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "sha256": _sha256(path),
        "size": path.stat().st_size,
    }


def _git_source_record(root: Path, *, required: bool) -> dict[str, str] | None:
    """Bind a release to one clean Git commit and tree when requested."""
    if not (root / ".git").exists():
        if required:
            raise RuntimeError("canonical release requires a Git worktree")
        return None
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if required:
            raise RuntimeError("canonical release requires a Git worktree") from None
        return None
    if Path(top).resolve() != root.resolve():
        raise RuntimeError("project root must be the Git worktree root")
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    if status:
        raise RuntimeError("canonical release requires a clean Git worktree")
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    return {"git_commit": commit, "git_tree": tree}


def build_release(
    *,
    root: Path,
    core_wheel: Path,
    wheelhouse: Path,
    output: Path,
    require_clean_git: bool = False,
) -> dict[str, object]:
    """Build all four artifacts and atomically publish one receipt-bound directory."""
    root = _regular_directory(root, "project root")
    pyproject = _regular_file(root / "pyproject.toml", "pyproject.toml")
    core_wheel = _regular_file(core_wheel, "SOUL Core wheel")
    wheelhouse = _regular_directory(wheelhouse, "Windows wheelhouse")
    output = _prepare_output(output)
    source = _git_source_record(root, required=require_clean_git)
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    if project.get("build-system", {}).get("requires") != [
        f"hatchling=={HATCHLING_VERSION}"
    ]:
        raise ValueError("build backend must be pinned to hatchling==1.32.0")
    try:
        installed_build = metadata.version("build")
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError("canonical release requires build==1.5.0") from exc
    if installed_build != BUILD_VERSION:
        raise RuntimeError(
            f"canonical release requires build=={BUILD_VERSION}; "
            f"found {installed_build}"
        )
    version = str(project["project"]["version"])
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.stage.", dir=output.parent)
    )
    try:
        environment = os.environ.copy()
        environment.update(
            {
                "SOURCE_DATE_EPOCH": str(RELEASE_EPOCH),
                "PYTHONHASHSEED": "0",
                "TZ": "UTC",
            }
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--sdist",
                "--outdir",
                str(stage),
                str(root),
            ],
            check=True,
            env=environment,
            timeout=300,
        )
        wheel = stage / f"soul_platform-{version}-py3-none-any.whl"
        sdist = stage / f"soul_platform-{version}.tar.gz"
        if not wheel.is_file() or wheel.is_symlink():
            raise RuntimeError("canonical Platform wheel was not produced")
        if not sdist.is_file() or sdist.is_symlink():
            raise RuntimeError("canonical Platform sdist was not produced")
        _verify_build_timestamps(wheel, sdist)
        windows = stage / f"SOUL-Platform-{version}-Windows.zip"
        unix = stage / f"SOUL-Platform-{version}-Unix.tar.gz"
        windows_result = build_bundle(
            root, wheel, core_wheel, wheelhouse, windows
        )
        unix_result = build_unix_bundle(root, wheel, core_wheel, unix)
        artifacts = {
            "platform_wheel": _artifact_record(wheel),
            "platform_sdist": _artifact_record(sdist),
            "windows_bundle": _artifact_record(windows),
            "unix_bundle": _artifact_record(unix),
        }
        if artifacts["platform_wheel"]["sha256"] != windows_result["wheel_sha256"]:
            raise RuntimeError("Windows bundle receipt does not bind the Platform wheel")
        if artifacts["platform_wheel"]["sha256"] != unix_result["wheel_sha256"]:
            raise RuntimeError("Unix bundle receipt does not bind the Platform wheel")
        receipt: dict[str, object] = {
            "schema": RECEIPT_SCHEMA,
            "version": version,
            "source_date_epoch": RELEASE_EPOCH,
            "build_frontend": f"build=={BUILD_VERSION}",
            "build_backend": f"hatchling=={HATCHLING_VERSION}",
            "inputs": {
                "core_wheel": _artifact_record(core_wheel),
                "windows_wheelhouse_lock_sha256": _sha256(
                    root / "installer" / "windows-wheelhouse.lock.json"
                ),
            },
            "artifacts": artifacts,
        }
        if source is not None:
            receipt["source"] = source
        receipt_path = stage / f"SOUL-Platform-{version}-release-receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        receipt_hash = _sha256(receipt_path)
        (stage / f"{receipt_path.name}.sha256").write_text(
            f"{receipt_hash}  {receipt_path.name}\n", encoding="ascii"
        )
        os.replace(stage, output)
        receipt["receipt"] = {
            "filename": receipt_path.name,
            "sha256": receipt_hash,
        }
        return receipt
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--core-wheel", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = build_release(
        root=args.root,
        core_wheel=args.core_wheel,
        wheelhouse=args.wheelhouse,
        output=args.output,
        require_clean_git=True,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
