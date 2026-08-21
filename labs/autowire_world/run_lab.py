#!/usr/bin/env python3
"""Run the complete Auto-Wire lab and remove only its ephemeral resources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]
PROVIDERS = [
    "qwen", "deepseek", "glm", "kimi", "ernie", "hunyuan", "doubao",
    "minimax", "claude", "gemini", "ollama", "flaky", "badjson", "redirect",
]
EVIDENCE_FILES = [
    "README.md",
    "autowire_lab.py",
    "compose.yaml",
    "mock_provider.py",
    "providers.json",
    "run_lab.py",
    "test_autowire_world_lab.py",
    "verify_lab.py",
]


def run(project: str, *args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    command = [*COMPOSE, "-p", project, *args]
    return subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=capture)


def wait_gateway(project: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        container = run(project, "ps", "-q", "gateway", capture=True).stdout.strip()
        if container:
            state = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]["State"]
            if state.get("Health", {}).get("Status") == "healthy":
                return
        time.sleep(0.5)
    raise RuntimeError("gateway did not become healthy")


def inspect_security(project: str) -> dict[str, object]:
    container = run(project, "ps", "-q", "gateway", capture=True).stdout.strip()
    inspected = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    host = inspected["HostConfig"]
    network_name = host["NetworkMode"]
    network = json.loads(subprocess.check_output(["docker", "network", "inspect", network_name], text=True))[0]
    result = {
        "user": inspected["Config"].get("User"),
        "readonly_rootfs": host["ReadonlyRootfs"],
        "cap_drop": host.get("CapDrop"),
        "no_new_privileges": "no-new-privileges:true" in (host.get("SecurityOpt") or []),
        "host_port_bindings": host.get("PortBindings"),
        "network_internal": network.get("Internal"),
    }
    assert result == {
        "user": "65532:65532",
        "readonly_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "host_port_bindings": {},
        "network_internal": True,
    }, result
    return result


def project_resources(project: str) -> dict[str, list[str]]:
    label = f"label=com.docker.compose.project={project}"
    commands = {
        "containers": ["docker", "ps", "-aq", "--filter", label],
        "volumes": ["docker", "volume", "ls", "-q", "--filter", label],
        "networks": ["docker", "network", "ls", "-q", "--filter", label],
    }
    return {
        kind: [line for line in subprocess.check_output(command, text=True).splitlines() if line]
        for kind, command in commands.items()
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--receipt",
        type=Path,
        help="write a secret-free, byte-bound JSON receipt after a passing run",
    )
    args = parser.parse_args()
    project = f"soul-autowire-ada-{os.getpid()}"
    try:
        run(project, "config", "--quiet")
        run(project, "run", "--rm", "init-state")
        run(project, "up", "-d", "--wait", "--wait-timeout", "60", *PROVIDERS)
        run(project, "run", "--rm", "reconcile")
        run(project, "up", "-d", "gateway")
        wait_gateway(project)
        run(project, "run", "--rm", "verifier", "python", "/lab/verify_lab.py", "phase1")
        security = inspect_security(project)
        run(project, "restart", "gateway")
        wait_gateway(project)
        phase2 = run(
            project,
            "run",
            "--rm",
            "verifier",
            "python",
            "/lab/verify_lab.py",
            "phase2",
            capture=True,
        )
        evidence = json.loads(phase2.stdout.strip().splitlines()[-1])
        print(json.dumps(evidence, sort_keys=True))
        print(json.dumps({"container_security": security, "status": "PASS"}, sort_keys=True))
        if args.receipt:
            receipt = {
                "schema": "soul.autowire-world-lab.receipt.v1",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "PASS",
                "git_head": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                ).strip(),
                "command": "python3 soul-platform/labs/autowire_world/run_lab.py --receipt <path>",
                "lab_file_sha256": {
                    name: _sha256(ROOT / name) for name in EVIDENCE_FILES
                },
                "evidence": evidence,
                "container_security": security,
            }
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(json.dumps({"receipt": str(args.receipt), "status": "WRITTEN"}, sort_keys=True))
    finally:
        cleanup = subprocess.run(
            [*COMPOSE, "-p", project, "down", "--volumes", "--remove-orphans"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        leftovers = project_resources(project)
        if cleanup.returncode != 0 or any(leftovers.values()):
            raise RuntimeError(
                f"ephemeral lab cleanup failed: rc={cleanup.returncode}; leftovers={leftovers}"
            )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"lab command failed: {exc}", file=sys.stderr)
        raise
