"""External Docker containment for tools with host-impacting effects."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import stat
import uuid
from dataclasses import dataclass
from typing import Any


class SandboxDenied(RuntimeError):
    pass


_PINNED_IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")


class ImageTrustStore:
    """Immutable image allowlist loaded from an operator-owned config file."""

    __slots__ = ("images", "path", "_sealed")

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError("use ImageTrustStore.from_file()")

    @classmethod
    def from_file(cls, path: str) -> "ImageTrustStore":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError("image trust store must be a non-symlink regular file") from exc
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError("image trust store must be a regular operator-owned file")
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("image trust store cannot be group/world writable")
            images = frozenset(
                line.strip()
                for line in handle
                if line.strip() and not line.lstrip().startswith("#")
            )
        if not images or any(not _PINNED_IMAGE.fullmatch(image) for image in images):
            raise ValueError("image trust store contains an invalid digest")
        value = object.__new__(cls)
        object.__setattr__(value, "images", images)
        object.__setattr__(value, "path", os.path.realpath(path))
        object.__setattr__(value, "_sealed", True)
        return value

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("image trust store is immutable")

    def allows(self, image: str) -> bool:
        return image in self.images


@dataclass(frozen=True)
class SandboxPolicy:
    image: str
    trust_store: ImageTrustStore
    timeout_seconds: float = 15.0
    memory: str = "256m"
    cpus: float = 0.5
    pids_limit: int = 64
    max_output_bytes: int = 65_536
    user: str = "65534:65534"

    def __post_init__(self) -> None:
        if not _PINNED_IMAGE.fullmatch(self.image):
            raise ValueError("sandbox image must be pinned by sha256 digest")
        if type(self.trust_store) is not ImageTrustStore or not self.trust_store.allows(self.image):
            raise ValueError("sandbox image is not in the operator trust allowlist")
        if (
            not math.isfinite(self.timeout_seconds)
            or not math.isfinite(self.cpus)
            or self.timeout_seconds <= 0
            or self.cpus <= 0
            or self.pids_limit <= 0
            or self.max_output_bytes <= 0
        ):
            raise ValueError("sandbox resource limits must be positive")
        memory_match = re.fullmatch(r"([1-9][0-9]*)([kKmMgG])", self.memory)
        if memory_match is None:
            raise ValueError("memory must be a positive Docker size such as 256m")
        if not re.fullmatch(r"[0-9]+(?::[0-9]+)?", self.user):
            raise ValueError("sandbox must run as an explicit non-root uid[:gid]")
        uid, _, gid = self.user.partition(":")
        if int(uid) == 0 or (gid and int(gid) == 0):
            raise ValueError("sandbox uid and gid must both be non-root")


class DockerSandbox:
    def __init__(self, policy: SandboxPolicy, docker: str = "docker") -> None:
        self.policy = policy
        self.docker = docker

    async def _exec(self, *args: str, timeout: float = 30.0) -> tuple[int, bytes, bytes]:
        proc = await asyncio.create_subprocess_exec(
            self.docker, *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except BaseException:
            proc.kill()
            await proc.wait()
            raise
        return proc.returncode, out, err

    async def start(self, command: list[str], *, name: str | None = None) -> str:
        if not command or any("\x00" in part for part in command):
            raise ValueError("sandbox command must be a non-empty argv list")
        name = name or f"soul-sandbox-{uuid.uuid4().hex}"
        args = [
            "run", "--detach", "--name", name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(self.policy.pids_limit),
            "--user", self.policy.user,
            "--memory", self.policy.memory, "--cpus", str(self.policy.cpus),
            "--log-driver", "local", "--log-opt", f"max-size={self.policy.max_output_bytes}",
            "--log-opt", "max-file=1", "--log-opt", "compress=false",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            self.policy.image, *command,
        ]
        rc, out, err = await self._exec(*args)
        if rc != 0:
            raise SandboxDenied(f"sandbox failed to start ({err.decode(errors='replace')[:200]})")
        container_id = out.decode().strip()
        if not container_id:
            raise SandboxDenied("docker returned no container id")
        return container_id

    async def inspect(self, container_id: str) -> dict:
        rc, out, _ = await self._exec("inspect", container_id)
        if rc != 0:
            raise SandboxDenied("sandbox container is not inspectable")
        data = json.loads(out)
        return data[0]

    async def kill(self, container_id: str) -> None:
        errors = []
        try:
            rc, _, err = await self._exec("stop", "--time", "1", container_id, timeout=5)
            if rc != 0:
                errors.append(f"stop rc={rc}: {err.decode(errors='replace')[:120]}")
        except Exception as exc:
            errors.append(f"stop {type(exc).__name__}")
        try:
            rc, _, err = await self._exec("rm", "--force", container_id, timeout=5)
            if rc != 0:
                errors.append(f"rm rc={rc}: {err.decode(errors='replace')[:120]}")
        except Exception as exc:
            errors.append(f"rm {type(exc).__name__}")
        # Docker create is daemon-side. If the client is cancelled, the object may
        # materialize just after the first `rm`. Reconcile by stable name for one
        # bounded window and require repeated explicit absence.
        absent_samples = 0
        for attempt in range(10):
            rc, _, inspect_err = await self._exec("inspect", container_id, timeout=5)
            if rc == 0:
                absent_samples = 0
                await self._exec("rm", "--force", container_id, timeout=5)
            else:
                detail = inspect_err.decode(errors="replace").lower()
                if "no such object" not in detail and "no such container" not in detail:
                    raise SandboxDenied(
                        "kill-switch outcome unknown; absence was not confirmed; "
                        + "; ".join(errors)
                    )
                absent_samples += 1
                if absent_samples >= 5:
                    return
            if attempt < 9:
                await asyncio.sleep(0.1)
        raise SandboxDenied("kill-switch failed: stable absence was not confirmed")

    async def run(self, command: list[str]) -> str:
        # Generate the name before Docker starts so cancellation during `run`
        # still has a stable external handle for cleanup.
        container_id = f"soul-sandbox-{uuid.uuid4().hex}"
        try:
            await self.start(command, name=container_id)
            rc, out, _ = await self._exec(
                "wait", container_id, timeout=self.policy.timeout_seconds
            )
            if rc != 0:
                raise SandboxDenied("could not wait for sandbox completion")
            exit_code = int(out.decode().strip())
            _, logs, _ = await self._exec("logs", container_id)
            if len(logs) > self.policy.max_output_bytes:
                raise SandboxDenied("sandbox output exceeded policy limit")
            if exit_code != 0:
                raise SandboxDenied(f"sandboxed command exited {exit_code}")
            return logs.decode(errors="replace")
        finally:
            await self.kill(container_id)


@dataclass(frozen=True)
class DockerTool:
    """Sealed adapter: a static command executed only through DockerSandbox."""

    sandbox: DockerSandbox
    command: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.sandbox) is not DockerSandbox:  # exact type: no overridden fake boundary
            raise TypeError("DockerTool requires the built-in DockerSandbox boundary")
        if not self.command or any("\x00" in part for part in self.command):
            raise ValueError("DockerTool command must be a static non-empty argv tuple")

    async def run(self, args: dict[str, Any]) -> str:
        try:
            payload = json.dumps(
                args, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError):
            raise ValueError("DockerTool args must be strict JSON") from None
        return await self.sandbox.run([*self.command, payload])
