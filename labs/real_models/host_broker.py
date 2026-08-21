#!/usr/bin/env python3
"""Ephemeral host-side broker for real-model container acceptance tests.

Provider credentials stay in their native host clients.  The container receives
only a short-lived lab capability and can reach this broker through one Unix
socket while its network namespace remains disabled.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any


INSTANCE = "soul-real-models-v1"
MAX_BODY = 64 * 1024
CALL_TIMEOUT_SECONDS = 240
_CALL_LOCK = threading.Lock()


class BrokerError(RuntimeError):
    pass


class Runtime:
    def __init__(self, capability: str) -> None:
        self.capability = capability
        self.lock = threading.Lock()
        self.calls: list[dict[str, Any]] = []

    def record(self, provider: str, model: str, elapsed_ms: int, output: str) -> None:
        with self.lock:
            self.calls.append(
                {
                    "provider": provider,
                    "model": model,
                    "elapsed_ms": elapsed_ms,
                    "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
                }
            )


RUNTIME: Runtime


def _run_codex(prompt: str) -> tuple[str, str]:
    output_fd, output_name = tempfile.mkstemp(prefix="soul-codex-", suffix=".txt")
    os.close(output_fd)
    output_path = Path(output_name)
    try:
        command = [
            shutil.which("codex") or "codex",
            "exec",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--model",
            "gpt-5.6-sol",
            "--output-last-message",
            str(output_path),
            prompt,
        ]
        completed = subprocess.run(
            command,
            cwd="/tmp",
            text=True,
            capture_output=True,
            timeout=CALL_TIMEOUT_SECONDS,
            check=False,
        )
        if completed.returncode != 0:
            raise BrokerError(f"codex exited rc={completed.returncode}")
        return output_path.read_text(encoding="utf-8").strip(), "gpt-5.6-sol"
    finally:
        output_path.unlink(missing_ok=True)


def _run_claude(prompt: str) -> tuple[str, str]:
    command = [
        shutil.which("claude") or "claude",
        "--print",
        "--safe-mode",
        "--no-session-persistence",
        "--permission-mode",
        "dontAsk",
        "--model",
        "opus",
        prompt,
    ]
    completed = subprocess.run(
        command,
        cwd="/tmp",
        text=True,
        capture_output=True,
        timeout=CALL_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise BrokerError(f"claude exited rc={completed.returncode}")
    return completed.stdout.strip(), "claude-opus"


def _run_gemma(prompt: str) -> tuple[str, str]:
    payload = json.dumps(
        {
            "model": "gemma3:1b-it-qat",
            "stream": False,
            "messages": [{"role": "user", "content": prompt}],
            "options": {"temperature": 0},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=CALL_TIMEOUT_SECONDS) as response:
        result = json.loads(response.read(MAX_BODY))
    return str(result["message"]["content"]).strip(), str(result["model"])


def invoke(provider: str, prompt: str) -> tuple[str, str, int]:
    functions = {"codex": _run_codex, "claude": _run_claude, "gemma": _run_gemma}
    if provider not in functions:
        raise BrokerError("provider is not allowlisted")
    if not prompt or len(prompt.encode("utf-8")) > 16 * 1024:
        raise BrokerError("prompt size is invalid")
    started = time.monotonic()
    # The subscription-backed CLIs share host state.  Serialize calls so the
    # acceptance test cannot create an avoidable quota burst.
    with _CALL_LOCK:
        output, model = functions[provider](prompt)
    elapsed_ms = round((time.monotonic() - started) * 1000)
    RUNTIME.record(provider, model, elapsed_ms, output)
    return output, model, elapsed_ms


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3.0)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _authorized(self) -> bool:
        expected = f"Bearer {RUNTIME.capability}"
        supplied = self.headers.get("Authorization", "")
        instance = self.headers.get("X-SOUL-Instance", "")
        return hmac.compare_digest(supplied, expected) and hmac.compare_digest(instance, INSTANCE)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"ok": True, "instance": INSTANCE})
            return
        if self.path == "/stats":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            with RUNTIME.lock:
                calls = list(RUNTIME.calls)
            self._json(200, {"calls": calls, "count": len(calls)})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/invoke":
            self._json(404, {"error": "not_found"})
            return
        # Authenticate before reading the body: rejected clients cannot hold a
        # worker by slowly streaming an attacker-controlled Content-Length.
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self._json(400, {"error": "invalid_length"})
            return
        if length < 2 or length > MAX_BODY:
            self._json(413, {"error": "body_size"})
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise BrokerError("truncated body")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {"provider", "prompt"}:
                raise BrokerError("invalid request schema")
            output, model, elapsed_ms = invoke(str(payload["provider"]), str(payload["prompt"]))
            self._json(
                200,
                {
                    "provider": payload["provider"],
                    "model": model,
                    "elapsed_ms": elapsed_ms,
                    "output": output,
                },
            )
        except (BrokerError, json.JSONDecodeError) as exc:
            self._json(400, {"error": type(exc).__name__, "detail": str(exc)})
        except subprocess.TimeoutExpired:
            self._json(504, {"error": "provider_timeout"})
        except Exception as exc:  # fail closed without provider stderr or secrets
            self._json(502, {"error": type(exc).__name__})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--capability-file", type=Path, required=True)
    args = parser.parse_args()
    global RUNTIME
    RUNTIME = Runtime(args.capability_file.read_text(encoding="utf-8").strip())
    args.socket.unlink(missing_ok=True)
    server = UnixServer(str(args.socket), Handler)
    os.chmod(args.socket, 0o600)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
