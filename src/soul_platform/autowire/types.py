from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import asdict, dataclass
from enum import StrEnum
from urllib.parse import urlsplit


class ProviderState(StrEnum):
    DISCOVERED = "DISCOVERED"
    IDENTITY_ATTESTED = "IDENTITY_ATTESTED"
    ACTIVE = "ACTIVE"
    ACTIVE_UNREACHABLE = "ACTIVE_UNREACHABLE"
    QUARANTINED = "QUARANTINED"
    STALE = "STALE"


def safe_model_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("model id must be text")
    result = value.strip()
    if not result or len(result.encode("utf-8")) > 512:
        raise ValueError("model id is empty or too large")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in result):
        raise ValueError("model id contains control or format characters")
    return result


@dataclass(frozen=True)
class ProviderCandidate:
    source: str
    kind: str
    protocol: str
    origin: str
    base_url: str
    model: str
    attestation: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.source not in {"ollama", "lmstudio", "llamacpp"}:
            raise ValueError("unsupported discovery source")
        if self.protocol != "openai-chat":
            raise ValueError("AutoWire A supports only OpenAI chat protocol")
        for value in (self.origin, self.base_url):
            parsed = urlsplit(value)
            if (
                parsed.scheme != "http"
                or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("AutoWire A origins must be literal loopback HTTP")
        safe_model_id(self.model)

    @property
    def provider_id(self) -> str:
        material = "\0".join((self.source, self.origin, self.model)).encode("utf-8")
        return f"{self.source}-{hashlib.sha256(material).hexdigest()[:20]}"

    @property
    def identity_attested(self) -> bool:
        return self.attestation == "ollama-native-loopback-v1"

    def as_dict(self) -> dict[str, object]:
        return {**asdict(self), "provider_id": self.provider_id}
