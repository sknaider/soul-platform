from __future__ import annotations

import hashlib
import importlib.util
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_windows_bundle", ROOT / "tools" / "build_windows_bundle.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _fake_root(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    root = tmp_path / "package"
    installer = root / "installer"
    installer.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname="soul-platform"\nversion="9.8.7"\n'
        'dependencies=["soul-framework==8.7.6"]\n'
    )
    (installer / "Install-Soul.ps1").write_text("installer")
    (installer / "Soul-Installer-Recovery.psm1").write_text("recovery")
    (installer / "Instalar-SOUL-Windows.bat").write_text("launcher")
    (installer / "LEEME-WINDOWS.txt").write_text("SOUL PLATFORM 9.8.7")
    production_lock = json.loads(
        (ROOT / "installer" / MODULE.WHEELHOUSE_LOCK).read_text()
    )
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    locked = []
    for record in production_lock["wheels"]:
        name = record["name"]
        payload = f"locked:{name}".encode()
        (wheelhouse / name).write_bytes(payload)
        locked.append({"name": name, "sha256": hashlib.sha256(payload).hexdigest()})
    fake_lock = {
        "schema": production_lock["schema"],
        "target": production_lock["target"],
        "wheels": locked,
    }
    (installer / MODULE.WHEELHOUSE_LOCK).write_text(
        json.dumps(fake_lock, indent=2) + "\n"
    )
    wheel = tmp_path / "soul_platform-9.8.7-py3-none-any.whl"
    wheel.write_bytes(b"wheel-bytes")
    core_wheel = tmp_path / "soul_framework-8.7.6-py3-none-any.whl"
    core_wheel.write_bytes(b"core-wheel-bytes")
    return root, wheel, core_wheel, wheelhouse


def test_bundle_is_checksum_bound_and_deterministic(tmp_path):
    root, wheel, core_wheel, wheelhouse = _fake_root(tmp_path)
    first, second = tmp_path / "first.zip", tmp_path / "second.zip"
    result = MODULE.build_bundle(root, wheel, core_wheel, wheelhouse, first)
    MODULE.build_bundle(root, wheel, core_wheel, wheelhouse, second)
    assert first.read_bytes() == second.read_bytes()
    assert result["wheel_sha256"] == hashlib.sha256(b"wheel-bytes").hexdigest()
    assert result["core_wheel_sha256"] == hashlib.sha256(
        b"core-wheel-bytes"
    ).hexdigest()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        locked = [item["name"] for item in json.loads(
            (root / "installer" / MODULE.WHEELHOUSE_LOCK).read_text()
        )["wheels"]]
        wheel_names = sorted([wheel.name, core_wheel.name, *locked], key=str.casefold)
        expected = [*MODULE.INSTALLER_FILES, MODULE.WHEELHOUSE_LOCK]
        for name in wheel_names:
            expected.extend((name, f"{name}.sha256"))
        expected.append("WHEELHOUSE.sha256")
        assert names == expected
        checksum = archive.read(f"{wheel.name}.sha256").decode()
        assert result["wheel_sha256"] in checksum and wheel.name in checksum
        core_checksum = archive.read(f"{core_wheel.name}.sha256").decode()
        assert hashlib.sha256(b"core-wheel-bytes").hexdigest() in core_checksum
        assert core_wheel.name in core_checksum
        wheelhouse_manifest = archive.read("WHEELHOUSE.sha256").decode().splitlines()
        assert len(wheelhouse_manifest) == len(wheel_names)
        assert [line.split("  ", 1)[1] for line in wheelhouse_manifest] == wheel_names
        assert result["wheel_count"] == str(len(wheel_names))


def test_bundle_rejects_stale_wheel_or_stale_guide(tmp_path):
    root, wheel, core_wheel, wheelhouse = _fake_root(tmp_path)
    stale = tmp_path / "soul_platform-9.8.6-py3-none-any.whl"
    stale.write_bytes(b"stale")
    with pytest.raises(ValueError, match="expected regular release wheel"):
        MODULE.build_bundle(root, stale, core_wheel, wheelhouse, tmp_path / "bad.zip")
    (root / "installer" / "LEEME-WINDOWS.txt").write_text("SOUL PLATFORM 9.8.6")
    with pytest.raises(ValueError, match="guide version"):
        MODULE.build_bundle(
            root, wheel, core_wheel, wheelhouse, tmp_path / "bad-guide.zip"
        )


def test_bundle_rejects_wrong_core_wheel(tmp_path):
    root, wheel, _core_wheel, wheelhouse = _fake_root(tmp_path)
    wrong = tmp_path / "soul_framework-0.4.0-py3-none-any.whl"
    wrong.write_bytes(b"wrong")
    with pytest.raises(ValueError, match="Core wheel 8.7.6"):
        MODULE.build_bundle(root, wheel, wrong, wheelhouse, tmp_path / "bad-core.zip")


@pytest.mark.parametrize(
    "extra_name",
    (
        "unexpected-1.0-py3-none-any.whl",
        "six-1.17.0-copy-py3-none-any.whl",
        "dependency-1.0.tar.gz",
    ),
)
def test_bundle_rejects_extra_duplicate_or_sdist(tmp_path, extra_name):
    root, wheel, core_wheel, wheelhouse = _fake_root(tmp_path)
    (wheelhouse / extra_name).write_bytes(b"not-allowed")
    with pytest.raises(ValueError, match="exact Windows lock"):
        MODULE.build_bundle(root, wheel, core_wheel, wheelhouse, tmp_path / "bad.zip")


def test_bundle_rejects_missing_locked_wheel_and_symlink(tmp_path):
    root, wheel, core_wheel, wheelhouse = _fake_root(tmp_path)
    locked = [item["name"] for item in json.loads(
        (root / "installer" / MODULE.WHEELHOUSE_LOCK).read_text()
    )["wheels"]]
    (wheelhouse / locked[0]).unlink()
    with pytest.raises(ValueError, match="exact Windows lock"):
        MODULE.build_bundle(root, wheel, core_wheel, wheelhouse, tmp_path / "missing.zip")

    (wheelhouse / locked[0]).write_bytes(b"restored")
    target = tmp_path / "outside.whl"
    target.write_bytes(b"outside")
    (wheelhouse / locked[1]).unlink()
    try:
        (wheelhouse / locked[1]).symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlinks are forbidden"):
        MODULE.build_bundle(root, wheel, core_wheel, wheelhouse, tmp_path / "link.zip")


def test_bundle_rejects_locked_wheel_with_wrong_bytes(tmp_path):
    root, wheel, core_wheel, wheelhouse = _fake_root(tmp_path)
    locked = json.loads(
        (root / "installer" / MODULE.WHEELHOUSE_LOCK).read_text()
    )["wheels"]
    (wheelhouse / locked[0]["name"]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="locked wheel hash mismatch"):
        MODULE.build_bundle(root, wheel, core_wheel, wheelhouse, tmp_path / "bad-hash.zip")


def test_versioned_lock_is_exact_sorted_windows_cp313():
    lock = json.loads((ROOT / "installer" / MODULE.WHEELHOUSE_LOCK).read_text())
    assert lock["schema"] == "soul.windows-wheelhouse.v1"
    assert lock["target"] == {"python": "cp313", "platform": "win_amd64"}
    names_list = [item["name"] for item in lock["wheels"]]
    assert names_list == sorted(names_list, key=str.casefold)
    assert len(names_list) == len(set(names_list))
    assert all(
        len(item["sha256"]) == 64
        and set(item["sha256"]) <= set("0123456789abcdef")
        for item in lock["wheels"]
    )
    names = "\n".join(names_list)
    for required in (
        "aiosqlite-",
        "numpy-",
        "usearch-",
        "cryptography-",
        "colorama-",
        "fastapi-",
        "uvicorn-",
        "httpx-",
        "pystray-0.19.5-",
        "pillow-12.3.0-",
    ):
        assert required in names


def test_unix_bundle_is_deterministic_and_contains_verified_installer(tmp_path):
    root, wheel, core_wheel, _wheelhouse = _fake_root(tmp_path)
    (root / "installer" / "soul-install.sh").write_text("#!/bin/sh\necho SOUL\n")
    first, second = tmp_path / "first.tar.gz", tmp_path / "second.tar.gz"
    result = MODULE.build_unix_bundle(root, wheel, core_wheel, first)
    MODULE.build_unix_bundle(root, wheel, core_wheel, second)
    assert first.read_bytes() == second.read_bytes()
    assert result["unix_bundle_sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    with tarfile.open(first, "r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == [
            "bundle/soul-install.sh",
            "bundle/ONLINE-DEPENDENCIES.txt",
            f"bundle/{wheel.name}",
            f"bundle/{wheel.name}.sha256",
            f"bundle/{core_wheel.name}",
            f"bundle/{core_wheel.name}.sha256",
        ]
        notice = archive.extractfile("bundle/ONLINE-DEPENDENCIES.txt")
        assert notice is not None
        assert b"not an offline" in notice.read()
        assert result["dependency_mode"] == "online-pypi-binary"
        assert members[0].mode == 0o755
        checksum = archive.extractfile(f"bundle/{wheel.name}.sha256")
        assert checksum is not None
        assert checksum.read().decode().startswith(hashlib.sha256(b"wheel-bytes").hexdigest())


def test_unix_bundle_rejects_misleading_zip_extension(tmp_path):
    root, wheel, core_wheel, _wheelhouse = _fake_root(tmp_path)
    (root / "installer" / "soul-install.sh").write_text("#!/bin/sh\necho SOUL\n")
    with pytest.raises(ValueError, match="must use .tar.gz or .tgz"):
        MODULE.build_unix_bundle(root, wheel, core_wheel, tmp_path / "Unix.zip")
