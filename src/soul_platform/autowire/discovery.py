from __future__ import annotations

from collections.abc import Callable
from typing import Any

from soul_platform.autowire.probe import MAX_DISCOVERED_MODELS, ProbeError, get_json
from soul_platform.autowire.types import ProviderCandidate, safe_model_id


OpenJson = Callable[..., Any]


def _model_names(payload: Any) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ProbeError("OpenAI model listing has an invalid shape")
    if len(payload["data"]) > MAX_DISCOVERED_MODELS:
        raise ProbeError("model listing exceeds bounded cardinality")
    names: list[str] = []
    seen: set[str] = set()
    for item in payload["data"]:
        try:
            name = safe_model_id(item.get("id") if isinstance(item, dict) else None)
        except ValueError:
            continue
        if name not in seen:
            names.append(name)
            seen.add(name)
    return names


def discover_ollama(*, fetch: OpenJson = get_json) -> list[ProviderCandidate]:
    version = fetch("http://127.0.0.1:11434/api/version")
    payload = fetch("http://127.0.0.1:11434/api/tags")
    if not isinstance(version, dict) or not isinstance(version.get("version"), str):
        raise ProbeError("Ollama native version attestation failed")
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list) or len(models) > MAX_DISCOVERED_MODELS:
        raise ProbeError("Ollama model listing has an invalid shape")
    result: list[ProviderCandidate] = []
    seen: set[str] = set()
    for item in models:
        details = item.get("details") if isinstance(item, dict) else None
        families = details.get("families") if isinstance(details, dict) else None
        family = details.get("family") if isinstance(details, dict) else None
        normalized_families = {
            str(value).strip().casefold()
            for value in ([family] + (families if isinstance(families, list) else []))
            if value
        }
        # Embedders remain on the separately pinned BGE-M3 path; advertising
        # them as chat brains would create a broken activation option.
        if any("bert" in value for value in normalized_families):
            continue
        try:
            model = safe_model_id(item.get("name") if isinstance(item, dict) else None)
        except ValueError:
            continue
        if model in seen:
            continue
        seen.add(model)
        result.append(
            ProviderCandidate(
                source="ollama",
                kind="ollama",
                protocol="openai-chat",
                origin="http://127.0.0.1:11434",
                base_url="http://127.0.0.1:11434/v1",
                model=model,
                attestation="ollama-native-loopback-v1",
                detail=f"ollama/{version['version']}",
            )
        )
    return result


def discover_openai_loopback(
    source: str,
    port: int,
    *,
    fetch: OpenJson = get_json,
) -> list[ProviderCandidate]:
    if source not in {"lmstudio", "llamacpp"} or port not in {1234, 8080}:
        raise ValueError("unsupported fixed local discoverer")
    origin = f"http://127.0.0.1:{port}"
    models = _model_names(fetch(origin + "/v1/models"))
    if source == "llamacpp":
        health = fetch(origin + "/health")
        if not isinstance(health, dict):
            raise ProbeError("llama.cpp health response is invalid")
    return [
        ProviderCandidate(
            source=source,
            kind=source,
            protocol="openai-chat",
            origin=origin,
            base_url=origin + "/v1",
            model=model,
            attestation="unattested-openai-loopback-v1",
            detail="protocol-compatible; memory blocked",
        )
        for model in models
    ]


def discover_all(*, fetch: OpenJson = get_json) -> tuple[list[ProviderCandidate], dict[str, str]]:
    candidates: list[ProviderCandidate] = []
    errors: dict[str, str] = {}
    discoverers = (
        ("ollama", lambda: discover_ollama(fetch=fetch)),
        ("lmstudio", lambda: discover_openai_loopback("lmstudio", 1234, fetch=fetch)),
        ("llamacpp", lambda: discover_openai_loopback("llamacpp", 8080, fetch=fetch)),
    )
    for name, discover in discoverers:
        try:
            candidates.extend(discover())
        except (ProbeError, ValueError) as exc:
            errors[name] = type(exc).__name__
    return candidates, errors
