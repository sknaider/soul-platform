from __future__ import annotations

import shutil
import os
from types import SimpleNamespace

import pytest

from soul_platform.sandbox import DockerSandbox, ImageTrustStore, SandboxDenied, SandboxPolicy


BUSYBOX = "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d"


@pytest.fixture
def trust_store(tmp_path):
    path = tmp_path / "trusted-images.txt"
    path.write_text(BUSYBOX + "\n")
    path.chmod(0o600)
    return ImageTrustStore.from_file(str(path))


def policy(trust_store, **changes):
    return SandboxPolicy(BUSYBOX, trust_store, **changes)


def test_policy_requires_trusted_digest_nonroot_and_positive_limits(tmp_path, trust_store):
    with pytest.raises(ValueError, match="digest"):
        SandboxPolicy("busybox:latest", trust_store)
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    empty.chmod(0o600)
    with pytest.raises(ValueError, match="invalid digest"):
        ImageTrustStore.from_file(str(empty))
    with pytest.raises(ValueError, match="memory"):
        policy(trust_store, memory="0m")
    with pytest.raises(ValueError, match="non-root"):
        policy(trust_store, user="0:0")
    with pytest.raises(ValueError, match="non-root"):
        policy(trust_store, user="65534:0")
    policy(trust_store)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")
async def test_external_kill_switch_stops_resistant_container_and_envelope(trust_store):
    sandbox = DockerSandbox(policy(trust_store, timeout_seconds=3))
    container = await sandbox.start(["sh", "-c", "while :; do :; done"])
    inspected = await sandbox.inspect(container)
    assert inspected["HostConfig"]["NetworkMode"] == "none"
    assert inspected["HostConfig"]["ReadonlyRootfs"] is True
    assert inspected["HostConfig"]["CapDrop"] == ["ALL"]
    assert "no-new-privileges" in inspected["HostConfig"]["SecurityOpt"]
    assert inspected["Config"]["User"] == "65534:65534"
    await sandbox.kill(container)
    with pytest.raises(SandboxDenied):
        await sandbox.inspect(container)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")
async def test_sandbox_runs_bounded_command(trust_store):
    sandbox = DockerSandbox(policy(trust_store, timeout_seconds=3))
    assert (await sandbox.run(["sh", "-c", "printf contained"])).strip() == "contained"


async def test_kill_switch_reports_residual_container(monkeypatch, trust_store):
    sandbox = DockerSandbox(policy(trust_store))
    async def fake_exec(*args, **_kwargs):
        if args[0] == "inspect": return 0, b"[]", b""
        return 1, b"", b"refused"
    monkeypatch.setattr(sandbox, "_exec", fake_exec)
    with pytest.raises(SandboxDenied, match="stable absence"):
        await sandbox.kill("resistant")


async def test_kill_switch_rejects_unknown_daemon_state(monkeypatch, trust_store):
    sandbox = DockerSandbox(policy(trust_store))
    async def fake_exec(*_args, **_kwargs): return 1, b"", b"daemon unreachable"
    monkeypatch.setattr(sandbox, "_exec", fake_exec)
    with pytest.raises(SandboxDenied, match="unknown"):
        await sandbox.kill("possibly-running")


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")
async def test_timeout_cleans_container_created_during_start(trust_store, monkeypatch):
    sandbox = DockerSandbox(policy(trust_store, timeout_seconds=0.05))
    suffix = f"timeoutcleanup{os.getpid()}"
    monkeypatch.setattr(
        "soul_platform.sandbox.uuid.uuid4", lambda: SimpleNamespace(hex=suffix)
    )
    with pytest.raises((TimeoutError, SandboxDenied)):
        await sandbox.run(["sh", "-c", "sleep 2"])
    await __import__("asyncio").sleep(0.3)
    rc, _, err = await sandbox._exec("inspect", f"soul-sandbox-{suffix}")
    assert rc != 0 and b"no such" in err.lower()
