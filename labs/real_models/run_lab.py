#!/usr/bin/env python3
"""Run real Codex/Claude/Gemma continuity tests in hardened containers."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
IMAGE = "python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
INSTANCE = "soul-real-models-v1"
CONTAINER_NAME = re.compile(r"soul-real-models-[0-9]+-phase[12]")
EVIDENCE_FILES = (
    "README.md",
    "container_probe.py",
    "host_broker.py",
    "run_lab.py",
    "test_real_models_lab.py",
)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path) -> None:
        super().__init__("localhost", timeout=10)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.socket_path))


def broker_json(socket_path: Path, path: str, capability: str | None = None) -> dict[str, Any]:
    headers = {"X-SOUL-Instance": INSTANCE}
    if capability:
        headers["Authorization"] = f"Bearer {capability}"
    connection = UnixHTTPConnection(socket_path)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    if response.status != 200:
        raise RuntimeError(f"broker {path} returned {response.status}")
    return json.loads(raw)


def wait_broker(socket_path: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if socket_path.exists():
            try:
                if broker_json(socket_path, "/health").get("ok") is True:
                    return
            except OSError:
                pass
        time.sleep(0.1)
    raise RuntimeError("real-model broker did not become healthy")


def container_args(name: str, runtime: Path, state: Path, phase: str) -> list[str]:
    uid, gid = os.getuid(), os.getgid()
    return [
        "docker", "create", "--name", name,
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", "128",
        "--memory", "512m",
        "--user", f"{uid}:{gid}",
        "--tmpfs", "/tmp:size=32m,mode=1777",
        "--mount", f"type=bind,src={ROOT},dst=/lab,readonly",
        "--mount", f"type=bind,src={runtime},dst=/run/soul-lab,readonly",
        "--mount", f"type=bind,src={state},dst=/state",
        IMAGE,
        "python", "/lab/container_probe.py", phase,
    ]


def inspect_security(name: str) -> dict[str, Any]:
    inspected = json.loads(subprocess.check_output(["docker", "inspect", name], text=True))[0]
    host = inspected["HostConfig"]
    env_names = {entry.split("=", 1)[0].upper() for entry in inspected["Config"].get("Env") or []}
    provider_markers = ("OPENAI", "ANTHROPIC", "CLAUDE", "CODEX", "GROQ", "GEMINI", "GOOGLE_API")
    credential_markers = ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL")
    suspicious = sorted(
        name
        for name in env_names
        if any(provider in name for provider in provider_markers)
        and any(credential in name for credential in credential_markers)
    )
    mounts = {mount["Destination"]: mount for mount in inspected["Mounts"]}
    result = {
        "network_mode": host["NetworkMode"],
        "readonly_rootfs": host["ReadonlyRootfs"],
        "cap_drop": host.get("CapDrop"),
        "no_new_privileges": "no-new-privileges:true" in (host.get("SecurityOpt") or []),
        "user": inspected["Config"].get("User"),
        "provider_credentials_in_env": suspicious,
        "broker_mount_readonly": not mounts["/run/soul-lab"]["RW"],
        "lab_mount_readonly": not mounts["/lab"]["RW"],
        "state_mount_writable": mounts["/state"]["RW"],
    }
    assert result == {
        "network_mode": "none",
        "readonly_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "user": f"{os.getuid()}:{os.getgid()}",
        "provider_credentials_in_env": [],
        "broker_mount_readonly": True,
        "lab_mount_readonly": True,
        "state_mount_writable": True,
    }, result
    return result


def run_phase(name: str, runtime: Path, state: Path, phase: str) -> tuple[dict[str, Any], dict[str, Any]]:
    subprocess.run(container_args(name, runtime, state, phase), check=True, text=True, capture_output=True)
    security = inspect_security(name)
    completed = subprocess.run(
        ["docker", "start", "--attach", name],
        text=True,
        capture_output=True,
        timeout=900,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{phase} failed rc={completed.returncode}: {completed.stderr[-800:]}")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    return json.loads(lines[-1]), security


def remove_container(name: str) -> None:
    if CONTAINER_NAME.fullmatch(name) is None:
        raise ValueError(f"refusing unscoped container cleanup: {name!r}")
    subprocess.run(["docker", "rm", "--force", name], check=False, text=True, capture_output=True)
    remaining = subprocess.run(
        ["docker", "inspect", name], check=False, text=True, capture_output=True
    )
    if remaining.returncode == 0:
        raise RuntimeError(f"container cleanup did not remove {name}")


def cleanup_resources(
    names: list[str],
    broker: subprocess.Popen[bytes],
    broker_log_handle: Any,
    runtime: Path,
) -> list[str]:
    """Attempt every cleanup step and return all failures without short-circuiting."""
    errors: list[str] = []
    for name in names:
        try:
            remove_container(name)
        except Exception as exc:
            errors.append(f"container:{name}:{type(exc).__name__}:{exc}")
    try:
        if broker.poll() is None:
            broker.terminate()
            try:
                broker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)
    except Exception as exc:
        errors.append(f"broker:{type(exc).__name__}:{exc}")
    try:
        broker_log_handle.close()
    except Exception as exc:
        errors.append(f"broker_log:{type(exc).__name__}:{exc}")
    try:
        shutil.rmtree(runtime)
    except Exception as exc:
        errors.append(f"runtime:{type(exc).__name__}:{exc}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    runtime = Path(tempfile.mkdtemp(prefix="soul-real-models-"))
    state = runtime / "state"
    state.mkdir(mode=0o700)
    capability = secrets.token_urlsafe(48)
    capability_file = runtime / "client.cap"
    capability_file.write_text(capability, encoding="utf-8")
    capability_file.chmod(0o400)
    socket_path = runtime / "broker.sock"
    broker_log = runtime / "broker.log"
    broker_log_handle = broker_log.open("wb")
    broker = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "host_broker.py"),
            "--socket", str(socket_path),
            "--capability-file", str(capability_file),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=broker_log_handle,
    )
    names = [f"soul-real-models-{os.getpid()}-phase1", f"soul-real-models-{os.getpid()}-phase2"]
    try:
        wait_broker(socket_path)
        phase1, security1 = run_phase(names[0], runtime, state, "phase1")
        remove_container(names[0])
        phase2, security2 = run_phase(names[1], runtime, state, "phase2")
        stats = broker_json(socket_path, "/stats", capability)
        assert stats["count"] == 4, stats
        assert [call["provider"] for call in stats["calls"]] == ["codex", "claude", "gemma", "gemma"]
        receipt = {
            "schema": "soul.real-model-continuity.receipt.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "PASS",
            "phase1": phase1,
            "phase2": phase2,
            "broker": stats,
            "container_security": [security1, security2],
            "provider_credentials_inside_containers": 0,
            "lab_file_sha256": {
                name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in EVIDENCE_FILES
            },
        }
        print(json.dumps(receipt, indent=2, sort_keys=True))
        if args.receipt:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        cleanup_errors = cleanup_resources(names, broker, broker_log_handle, runtime)
        if cleanup_errors:
            active_error = sys.exception()
            detail = "lab cleanup failures: " + "; ".join(cleanup_errors)
            if active_error is not None:
                active_error.add_note(detail)
            else:
                raise RuntimeError(detail)


if __name__ == "__main__":
    main()
