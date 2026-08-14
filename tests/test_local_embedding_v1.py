from __future__ import annotations

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from soul_platform.local_embedding import LocalBgeM3Embedding


def test_embedding_never_inherits_http_proxy(monkeypatch):
    captured: list[bytes] = []

    class ProxyTrap(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            captured.append(self.rfile.read(length))
            payload = json.dumps({"embeddings": [[1.0, 0.0]]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    trap = ThreadingHTTPServer(("127.0.0.1", 0), ProxyTrap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{trap.server_port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{trap.server_port}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    provider = LocalBgeM3Embedding(
        url="http://127.0.0.1:9/api/embed", timeout=0.2, dimensions=2
    )
    try:
        with pytest.raises(RuntimeError, match="embedding request failed"):
            asyncio.run(provider.embed("MEMORIA-PRIVADA-WILLIAM"))
    finally:
        trap.shutdown()
        thread.join(timeout=2)
        trap.server_close()
    assert captured == []


def test_embedding_rejects_hostname_and_redirect_shape():
    with pytest.raises(ValueError, match="literal loopback"):
        LocalBgeM3Embedding(url="http://localhost:11434/api/embed")
    with pytest.raises(ValueError, match="literal loopback"):
        LocalBgeM3Embedding(url="http://127.0.0.1:11434/elsewhere")
