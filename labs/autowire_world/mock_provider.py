#!/usr/bin/env python3
"""Protocol-faithful synthetic provider used by the SOUL Auto-Wire lab.

No real credential, memory or external network is used.  Requests travel over
the compose network so discovery, canaries and brain switching exercise real
HTTP serialization and process boundaries.
"""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PROVIDER_ID = os.environ.get("PROVIDER_ID", "provider")
MODEL_ID = os.environ.get("MODEL_ID", "model")
PROTOCOL = os.environ.get("PROTOCOL", "openai-chat")
BEHAVIOR = os.environ.get("BEHAVIOR", "honest")
PORT = int(os.environ.get("PORT", "8000"))
REQUESTS = 0
MAX_BODY = 1_048_576


def _response_text(body: dict) -> str:
    serialized = json.dumps(body, ensure_ascii=False)
    if "SOUL_CANARY_V1" in serialized:
        return "SOUL_CANARY_V1"
    soul = re.search(r"SOUL_ID=([0-9a-f-]{36})", serialized)
    memory = re.search(r"MEMORY=([^;\"\\]+)", serialized)
    return (
        f"provider={PROVIDER_ID};model={MODEL_ID};"
        f"soul={soul.group(1) if soul else 'NONE'};"
        f"memory={memory.group(1) if memory else 'NONE'}"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "SOULSyntheticProvider/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_json(self, status: int, payload: object) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        global REQUESTS
        if self.path == "/health":
            if BEHAVIOR == "flaky" and REQUESTS >= 2:
                self._send_json(503, {"ok": False})
            else:
                self._send_json(200, {"ok": True, "provider": PROVIDER_ID})
            return
        if BEHAVIOR == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/escape")
            self.end_headers()
            return
        if BEHAVIOR == "bad-json":
            payload = b'{"data":[],"data":[{"id":"duplicate"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path in {"/v1/models", "/v1beta/models"}:
            if PROTOCOL == "gemini-native":
                self._send_json(200, {"models": [{"name": f"models/{MODEL_ID}"}]})
            else:
                self._send_json(200, {"object": "list", "data": [{"id": MODEL_ID}]})
            return
        if self.path == "/api/tags":
            self._send_json(200, {"models": [{"name": MODEL_ID}]})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        global REQUESTS
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > MAX_BODY:
            self._send_json(413, {"error": "body_size"})
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid_json"})
            return
        REQUESTS += 1
        text = _response_text(body)
        if PROTOCOL == "openai-chat" and self.path == "/v1/chat/completions":
            self._send_json(
                200,
                {
                    "id": f"chatcmpl-{REQUESTS}",
                    "object": "chat.completion",
                    "model": MODEL_ID,
                    "choices": [{"message": {"role": "assistant", "content": text}}],
                },
            )
            return
        if PROTOCOL == "openai-responses" and self.path == "/v1/responses":
            self._send_json(200, {"id": f"resp-{REQUESTS}", "model": MODEL_ID, "output_text": text})
            return
        if PROTOCOL == "anthropic-messages" and self.path == "/v1/messages":
            self._send_json(
                200,
                {"id": f"msg-{REQUESTS}", "model": MODEL_ID, "content": [{"type": "text", "text": text}]},
            )
            return
        if PROTOCOL == "gemini-native" and self.path == f"/v1beta/models/{MODEL_ID}:generateContent":
            self._send_json(
                200,
                {"candidates": [{"content": {"parts": [{"text": text}], "role": "model"}}]},
            )
            return
        if PROTOCOL == "ollama-native" and self.path == "/api/chat":
            self._send_json(200, {"model": MODEL_ID, "message": {"role": "assistant", "content": text}})
            return
        self._send_json(404, {"error": "protocol_path_mismatch"})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
