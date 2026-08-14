"""Loopback-only BGE-M3 transport that never inherits process proxies."""

from __future__ import annotations

import asyncio
import math
from typing import Any
from urllib.parse import urlsplit

import httpx


LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


class LocalBgeM3Embedding:
    """Normalized BGE-M3 embeddings over a literal loopback endpoint.

    ``urllib`` and many HTTP clients inherit ``HTTP_PROXY`` by default.  Memory
    text must never leave the device merely because the parent process has a
    corporate proxy configured, so this adapter uses ``trust_env=False`` and
    rejects redirects and hostnames.
    """

    def __init__(
        self,
        model: str = "bge-m3",
        *,
        url: str = "http://127.0.0.1:11434/api/embed",
        timeout: float = 60.0,
        dimensions: int = 1024,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in LOOPBACK_HOSTS
            or parsed.port is None
            or parsed.path != "/api/embed"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "BGE-M3 endpoint must be an uncredentialed literal loopback /api/embed URL"
            )
        if not model or timeout <= 0 or dimensions < 1:
            raise ValueError("model, timeout and dimensions must be valid")
        self._model = model
        self._url = url
        self._timeout = timeout
        self._dimensions = dimensions

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def model_name(self) -> str:
        return self._model

    async def embed(self, text: str) -> list[float]:
        return (await self.embed_batch([text]))[0]

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if not all(isinstance(text, str) for text in texts):
            raise TypeError("all texts must be strings")
        if not texts:
            return []
        payload = {"model": self._model, "input": [text or " " for text in texts]}
        response = await asyncio.to_thread(self._post_json, payload)
        vectors = response.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise RuntimeError("Ollama returned an invalid embedding batch")
        result = [[float(value) for value in vector] for vector in vectors]
        if any(len(vector) != self._dimensions for vector in result):
            raise RuntimeError("BGE-M3 returned an unexpected vector dimension")
        if any(not math.isfinite(value) for vector in result for value in vector):
            raise RuntimeError("BGE-M3 returned a non-finite embedding value")
        return result

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            with httpx.Client(
                timeout=self._timeout,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = client.post(self._url, json=payload)
                response.raise_for_status()
                decoded = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError("local BGE-M3 embedding request failed") from exc
        if not isinstance(decoded, dict):
            raise TypeError("Ollama returned an invalid embedding response")
        return decoded
