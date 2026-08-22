from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_release_artifacts", ROOT / "tools" / "build_release_artifacts.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "project"
    installer = root / "installer"
    installer.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname="soul-platform"\nversion="9.8.7"\n'
        '[build-system]\nrequires=["hatchling==1.32.0"]\n'
        'build-backend="hatchling.build"\n'
    )
    (installer / "Install-Soul.ps1").write_text("installer")
    (installer / "Soul-Installer-Recovery.psm1").write_text("recovery")
    (installer / "Instalar-SOUL-Windows.bat").write_text("launcher")
    (installer / "LEEME-WINDOWS.txt").write_text("SOUL PLATFORM 9.8.7")
    (installer / "soul-install.sh").write_text("#!/bin/sh\nexit 0\n")
    dependency = "dependency-1.0-py3-none-any.whl"
    dependency_bytes = b"locked dependency"
    lock = {
        "schema": "soul.windows-wheelhouse.v1",
        "target": {"python": "cp313", "platform": "win_amd64"},
        "wheels": [
            {
                "name": dependency,
                "sha256": hashlib.sha256(dependency_bytes).hexdigest(),
            }
        ],
    }
    (installer / "windows-wheelhouse.lock.json").write_text(
        json.dumps(lock, indent=2) + "\n"
    )
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / dependency).write_bytes(dependency_bytes)
    core = tmp_path / "soul_framework-0.4.3-py3-none-any.whl"
    core.write_bytes(b"core")
    return root, core, wheelhouse


def _fake_build(command, *, check, env, timeout):
    assert check is True and timeout == 300
    assert env["SOURCE_DATE_EPOCH"] == str(MODULE.RELEASE_EPOCH)
    assert env["PYTHONHASHSEED"] == "0" and env["TZ"] == "UTC"
    output = Path(command[command.index("--outdir") + 1])
    timestamp = MODULE._canonical_zip_timestamp()
    wheel = output / "soul_platform-9.8.7-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("soul_platform/__init__.py", date_time=timestamp)
        archive.writestr(info, b'__version__ = "9.8.7"\n')
    sdist = output / "soul_platform-9.8.7.tar.gz"
    with sdist.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=MODULE.RELEASE_EPOCH
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                payload = b"source"
                info = tarfile.TarInfo("soul_platform-9.8.7/source.txt")
                info.size = len(payload)
                info.mtime = MODULE.RELEASE_EPOCH
                archive.addfile(info, io.BytesIO(payload))
    return subprocess.CompletedProcess(command, 0)


def test_release_build_forces_epoch_and_is_identical_across_host_environments(
    tmp_path, monkeypatch
):
    root, core, wheelhouse = _fixture(tmp_path)
    monkeypatch.setattr(MODULE.subprocess, "run", _fake_build)
    outputs = []
    for name, ambient_epoch in (("a", "1"), ("b", "1999999999")):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", ambient_epoch)
        output = tmp_path / name
        receipt = MODULE.build_release(
            root=root, core_wheel=core, wheelhouse=wheelhouse, output=output
        )
        assert receipt["source_date_epoch"] == MODULE.RELEASE_EPOCH
        assert receipt["build_frontend"] == "build==1.5.0"
        outputs.append(output)
    first = {path.name: path.read_bytes() for path in outputs[0].iterdir()}
    second = {path.name: path.read_bytes() for path in outputs[1].iterdir()}
    assert first == second
    assert len(first) == 6
    receipt_name = "SOUL-Platform-9.8.7-release-receipt.json"
    receipt_hash = hashlib.sha256(first[receipt_name]).hexdigest()
    assert first[f"{receipt_name}.sha256"].decode().startswith(receipt_hash)
    with zipfile.ZipFile(outputs[0] / "soul_platform-9.8.7-py3-none-any.whl") as wheel:
        assert {item.date_time for item in wheel.infolist()} == {
            MODULE._canonical_zip_timestamp()
        }
    with tarfile.open(outputs[0] / "soul_platform-9.8.7.tar.gz") as sdist:
        assert {item.mtime for item in sdist.getmembers()} == {MODULE.RELEASE_EPOCH}


def test_git_source_record_binds_clean_commit_and_rejects_dirty_tree(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@soul.local"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "SOUL Test"],
        check=True,
    )
    (root / "source.txt").write_text("frozen\n")
    subprocess.run(["git", "-C", str(root), "add", "source.txt"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "freeze"], check=True)

    record = MODULE._git_source_record(root, required=True)
    assert record == {
        "git_commit": subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "git_tree": subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
    }
    (root / "source.txt").write_text("dirty\n")
    with pytest.raises(RuntimeError, match="clean Git worktree"):
        MODULE._git_source_record(root, required=True)


@pytest.mark.parametrize("unsafe", ["root", "core", "wheelhouse"])
def test_release_build_rejects_symlinked_inputs(tmp_path, monkeypatch, unsafe):
    root, core, wheelhouse = _fixture(tmp_path)
    selected = {"root": root, "core": core, "wheelhouse": wheelhouse}[unsafe]
    real = selected.with_name(selected.name + "-real")
    selected.rename(real)
    selected.symlink_to(real, target_is_directory=real.is_dir())
    monkeypatch.setattr(MODULE.subprocess, "run", _fake_build)
    with pytest.raises(ValueError, match="symlink"):
        MODULE.build_release(
            root=root,
            core_wheel=core,
            wheelhouse=wheelhouse,
            output=tmp_path / "release",
        )
    assert not (tmp_path / "release").exists()


def test_release_build_failure_leaves_no_partial_output(tmp_path, monkeypatch):
    root, core, wheelhouse = _fixture(tmp_path)

    def fail(*_args, **_kwargs):
        raise subprocess.CalledProcessError(7, "python -m build")

    monkeypatch.setattr(MODULE.subprocess, "run", fail)
    output = tmp_path / "release"
    with pytest.raises(subprocess.CalledProcessError):
        MODULE.build_release(
            root=root, core_wheel=core, wheelhouse=wheelhouse, output=output
        )
    assert not output.exists()
    assert list(tmp_path.glob(".release.stage.*")) == []


def test_release_build_rejects_existing_or_symlinked_output(tmp_path, monkeypatch):
    root, core, wheelhouse = _fixture(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        MODULE.build_release(
            root=root, core_wheel=core, wheelhouse=wheelhouse, output=existing
        )
    link = tmp_path / "link"
    link.symlink_to(existing, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        MODULE.build_release(
            root=root, core_wheel=core, wheelhouse=wheelhouse, output=link
        )


def test_build_backend_is_pinned():
    text = (ROOT / "pyproject.toml").read_text()
    assert 'requires = ["hatchling==1.32.0"]' in text
    assert '"build==1.5.0"' in text
    assert '"twine==7.0.0"' in text


def test_release_build_rejects_wrong_frontend_version(tmp_path, monkeypatch):
    root, core, wheelhouse = _fixture(tmp_path)
    monkeypatch.setattr(MODULE.metadata, "version", lambda _name: "0.0.0")
    with pytest.raises(RuntimeError, match="requires build==1.5.0"):
        MODULE.build_release(
            root=root,
            core_wheel=core,
            wheelhouse=wheelhouse,
            output=tmp_path / "release",
        )
    assert not (tmp_path / "release").exists()
