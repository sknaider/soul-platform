from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlsplit


MAX_DISCOVERY_BYTES = 1_048_576
MAX_DISCOVERED_MODELS = 100


class ProbeError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(raw: bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_strict_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON: {value}")
        ),
    )


def _default_open(request: urllib.request.Request, *, timeout: float):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()
    )
    return opener.open(request, timeout=timeout)


def get_json(
    url: str,
    *,
    timeout: float = 1.5,
    opener: Callable[..., Any] = _default_open,
) -> Any:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProbeError("probe target must be literal loopback HTTP")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener(request, timeout=timeout) as response:
            if int(getattr(response, "status", 200)) != 200:
                raise ProbeError(f"probe returned HTTP {response.status}")
            raw = response.read(MAX_DISCOVERY_BYTES + 1)
    except (OSError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise ProbeError("loopback probe failed") from exc
    if len(raw) > MAX_DISCOVERY_BYTES:
        raise ProbeError("probe response exceeds 1 MiB")
    try:
        return strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProbeError("probe returned invalid strict JSON") from exc
