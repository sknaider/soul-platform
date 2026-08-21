#!/usr/bin/env python3
"""Container-only reference implementation of SOUL Model Auto-Wire v1.2.

This lab deliberately owns no production credentials and never opens Internet
egress.  It exercises the protocol spine, durable registry, attach sessions,
brain swaps and verified rollback against independent HTTP processes.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_BODY = 1_048_576
PROTOCOLS = {
    "openai-chat",
    "openai-responses",
    "anthropic-messages",
    "gemini-native",
    "ollama-native",
}


class LabError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


OPENER = build_opener(NoRedirect())


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
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON: {value}")),
    )


def http_json(method: str, url: str, payload: object | None = None) -> Any:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.query or parsed.fragment:
        raise LabError(f"non-canonical lab URL: {url}")
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode()
    request = Request(url, data=body, method=method)
    request.add_header("Accept", "application/json")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with OPENER.open(request, timeout=3) as response:
            if response.status != 200:
                raise LabError(f"HTTP {response.status} from {url}")
            raw = response.read(MAX_BODY + 1)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise LabError(f"request failed for {url}: {exc}") from exc
    if len(raw) > MAX_BODY:
        raise LabError(f"response too large from {url}")
    try:
        return strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise LabError(f"strict JSON failed for {url}: {exc}") from exc


@dataclass(frozen=True)
class Provider:
    provider_id: str
    model: str
    protocol: str
    origin: str
    region: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Provider":
        item = cls(**{key: str(value[key]) for key in cls.__annotations__})
        if item.protocol not in PROTOCOLS:
            raise LabError(f"unsupported protocol: {item.protocol}")
        parsed = urlsplit(item.origin)
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise LabError(f"non-canonical provider origin: {item.origin}")
        return item


def load_config(path: Path) -> dict[str, Any]:
    raw = strict_json(path.read_bytes())
    if raw.get("schema") != "soul.autowire-lab.providers.v1":
        raise LabError("unexpected provider config schema")
    ids = [item["provider_id"] for item in raw.get("providers", [])]
    if not ids or len(ids) != len(set(ids)):
        raise LabError("provider ids must be present and unique")
    if raw.get("initial_provider_id") not in ids:
        raise LabError("initial provider must exist")
    clients = raw.get("allowed_clients")
    if not isinstance(clients, list) or not clients or len(clients) != len(set(clients)):
        raise LabError("allowed clients must be present and unique")
    providers_from(raw)
    return raw


def providers_from(config: dict[str, Any]) -> list[Provider]:
    return [Provider.from_dict(item) for item in config["providers"]]


def _models_path(provider: Provider) -> str:
    if provider.protocol == "ollama-native":
        return "/api/tags"
    if provider.protocol == "gemini-native":
        return "/v1beta/models"
    return "/v1/models"


def _models(payload: dict[str, Any], protocol: str) -> set[str]:
    if protocol == "ollama-native":
        return {str(item["name"]) for item in payload.get("models", [])}
    if protocol == "gemini-native":
        return {str(item["name"]).removeprefix("models/") for item in payload.get("models", [])}
    return {str(item["id"]) for item in payload.get("data", [])}


def _request_for(provider: Provider, messages: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
    if provider.protocol == "openai-chat":
        return "/v1/chat/completions", {"model": provider.model, "messages": messages, "stream": False}
    if provider.protocol == "openai-responses":
        return "/v1/responses", {"model": provider.model, "input": messages, "stream": False}
    if provider.protocol == "anthropic-messages":
        system = "\n".join(item["content"] for item in messages if item["role"] == "system")
        rest = [item for item in messages if item["role"] != "system"]
        return "/v1/messages", {"model": provider.model, "system": system, "messages": rest, "max_tokens": 64}
    if provider.protocol == "gemini-native":
        text = "\n".join(item["content"] for item in messages)
        return f"/v1beta/models/{provider.model}:generateContent", {"contents": [{"parts": [{"text": text}]}]}
    if provider.protocol == "ollama-native":
        return "/api/chat", {"model": provider.model, "messages": messages, "stream": False}
    raise LabError(f"unsupported protocol: {provider.protocol}")


def _text_from(provider: Provider, payload: dict[str, Any]) -> str:
    try:
        if provider.protocol == "openai-chat":
            return str(payload["choices"][0]["message"]["content"])
        if provider.protocol == "openai-responses":
            return str(payload["output_text"])
        if provider.protocol == "anthropic-messages":
            return str(payload["content"][0]["text"])
        if provider.protocol == "gemini-native":
            return str(payload["candidates"][0]["content"]["parts"][0]["text"])
        if provider.protocol == "ollama-native":
            return str(payload["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise LabError(f"malformed {provider.protocol} response") from exc
    raise LabError(f"unsupported protocol: {provider.protocol}")


def call_provider(provider: Provider, messages: list[dict[str, str]]) -> str:
    path, body = _request_for(provider, messages)
    response = http_json("POST", urljoin(provider.origin + "/", path.lstrip("/")), body)
    return _text_from(provider, response)


def probe(provider: Provider) -> None:
    listing = http_json("GET", urljoin(provider.origin + "/", _models_path(provider).lstrip("/")))
    if provider.model not in _models(listing, provider.protocol):
        raise LabError(f"model {provider.model} absent from {provider.provider_id}")
    text = call_provider(
        provider,
        [
            {"role": "system", "content": "Return exactly SOUL_CANARY_V1."},
            {"role": "user", "content": "SOUL synthetic readiness probe"},
        ],
    )
    if text != "SOUL_CANARY_V1":
        raise LabError(f"canary mismatch from {provider.provider_id}")


class Registry:
    def __init__(self, path: Path, config: dict[str, Any]):
        self.path = path
        self.config = config
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS memories(id INTEGER PRIMARY KEY CHECK(id=1), content TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS providers(
                    provider_id TEXT PRIMARY KEY, model TEXT NOT NULL, protocol TEXT NOT NULL,
                    origin TEXT NOT NULL, region TEXT NOT NULL, state TEXT NOT NULL,
                    detail TEXT NOT NULL, evidence_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS binding(
                    id INTEGER PRIMARY KEY CHECK(id=1), provider_id TEXT NOT NULL,
                    generation INTEGER NOT NULL, previous_provider_id TEXT,
                    FOREIGN KEY(provider_id) REFERENCES providers(provider_id)
                );
                CREATE TABLE IF NOT EXISTS sessions(
                    session_id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
                    machine_soul_id TEXT NOT NULL, issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL, revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL,
                    subject TEXT NOT NULL, detail TEXT NOT NULL, created_at REAL NOT NULL
                );
                """
            )
            expected = str(self.config["machine_soul_id"])
            current = db.execute("SELECT value FROM meta WHERE key='machine_soul_id'").fetchone()
            if current is not None and current["value"] != expected:
                raise LabError("machine_soul_id invariant changed")
            db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('machine_soul_id',?)", (expected,))
            db.execute("INSERT OR IGNORE INTO memories(id,content) VALUES(1,?)", (self.config["memory_anchor"],))

    def upsert_provider(self, provider: Provider, state: str, detail: str) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO providers(provider_id,model,protocol,origin,region,state,detail,evidence_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(provider_id) DO UPDATE SET
                     model=excluded.model,protocol=excluded.protocol,origin=excluded.origin,
                     region=excluded.region,state=excluded.state,detail=excluded.detail,
                     evidence_at=excluded.evidence_at""",
                (provider.provider_id, provider.model, provider.protocol, provider.origin,
                 provider.region, state, detail[:400], time.time()),
            )

    def provider_state(self) -> dict[str, str]:
        with self.connect() as db:
            return {row["provider_id"]: row["state"] for row in db.execute("SELECT provider_id,state FROM providers")}

    def active_provider_id(self) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT provider_id FROM binding WHERE id=1").fetchone()
            return None if row is None else str(row["provider_id"])

    def generation(self) -> int:
        with self.connect() as db:
            row = db.execute("SELECT generation FROM binding WHERE id=1").fetchone()
            return 0 if row is None else int(row["generation"])

    def machine_soul_id(self) -> str:
        with self.connect() as db:
            return str(db.execute("SELECT value FROM meta WHERE key='machine_soul_id'").fetchone()[0])

    def memory(self) -> str:
        with self.connect() as db:
            return str(db.execute("SELECT content FROM memories WHERE id=1").fetchone()[0])

    def audit(self, event: str, subject: str, detail: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO audit(event,subject,detail,created_at) VALUES(?,?,?,?)", (event, subject, detail, time.time()))

    def activate(self, provider: Provider, *, expected_generation: int | None = None) -> bool:
        with self.connect() as db:
            row = db.execute("SELECT state FROM providers WHERE provider_id=?", (provider.provider_id,)).fetchone()
            if row is None or row["state"] != "CANARY_PASSED":
                raise LabError(f"provider not ready: {provider.provider_id}")
        probe(provider)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT provider_id,generation FROM binding WHERE id=1").fetchone()
            previous = None if current is None else str(current["provider_id"])
            observed_generation = 0 if current is None else int(current["generation"])
            if expected_generation is not None and observed_generation != expected_generation:
                db.execute(
                    "INSERT INTO audit(event,subject,detail,created_at) VALUES(?,?,?,?)",
                    (
                        "BINDING_CAS_REJECTED",
                        provider.provider_id,
                        f"expected={expected_generation};observed={observed_generation}",
                        time.time(),
                    ),
                )
                return False
            generation = observed_generation + 1
            db.execute(
                """INSERT INTO binding(id,provider_id,generation,previous_provider_id)
                   VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET
                   provider_id=excluded.provider_id,generation=excluded.generation,
                   previous_provider_id=excluded.previous_provider_id""",
                (provider.provider_id, generation, previous),
            )
            db.execute("INSERT INTO audit(event,subject,detail,created_at) VALUES(?,?,?,?)",
                       ("BINDING_COMMITTED", provider.provider_id, f"generation={generation}", time.time()))
        try:
            health = http_json("GET", provider.origin + "/health")
            if health.get("ok") is not True:
                raise LabError("post-activation health false")
        except Exception as exc:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                current = db.execute("SELECT provider_id,generation FROM binding WHERE id=1").fetchone()
                owns_failed_generation = bool(
                    current is not None
                    and current["provider_id"] == provider.provider_id
                    and int(current["generation"]) == generation
                )
                if owns_failed_generation:
                    if previous is None:
                        db.execute("DELETE FROM binding WHERE id=1")
                    else:
                        db.execute(
                            "UPDATE binding SET provider_id=?,generation=?,previous_provider_id=? WHERE id=1",
                            (previous, generation + 1, provider.provider_id),
                        )
                db.execute("INSERT INTO audit(event,subject,detail,created_at) VALUES(?,?,?,?)",
                           (
                               "BINDING_ROLLED_BACK" if owns_failed_generation else "ROLLBACK_FENCED",
                               provider.provider_id,
                               type(exc).__name__,
                               time.time(),
                           ))
            return False
        self.audit("BINDING_ACTIVE", provider.provider_id, f"generation={generation}")
        return True

    def issue_session(self, client_id: str) -> str:
        if client_id not in set(self.config["allowed_clients"]):
            raise LabError("client not allowlisted")
        session_id = str(uuid.uuid4())
        now = time.time()
        with self.connect() as db:
            db.execute(
                "INSERT INTO sessions(session_id,client_id,machine_soul_id,issued_at,expires_at) VALUES(?,?,?,?,?)",
                (session_id, client_id, self.machine_soul_id(), now, now + 3600),
            )
        return session_id

    def valid_session(self, session_id: str) -> bool:
        with self.connect() as db:
            row = db.execute(
                "SELECT expires_at,revoked_at,machine_soul_id FROM sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
        return bool(
            row is not None
            and row["revoked_at"] is None
            and float(row["expires_at"]) > time.time()
            and row["machine_soul_id"] == self.machine_soul_id()
        )

    def revoke_session(self, session_id: str) -> bool:
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE sessions SET revoked_at=? WHERE session_id=? AND revoked_at IS NULL",
                (time.time(), session_id),
            )
            return cursor.rowcount == 1

    def latest_session(self) -> str:
        with self.connect() as db:
            row = db.execute("SELECT session_id FROM sessions ORDER BY issued_at DESC LIMIT 1").fetchone()
            if row is None:
                raise LabError("no attach session")
            return str(row["session_id"])

    def audit_counts(self) -> dict[str, int]:
        with self.connect() as db:
            return {row["event"]: int(row["n"]) for row in db.execute("SELECT event,count(*) n FROM audit GROUP BY event")}


def reconcile(registry: Registry, config: dict[str, Any]) -> dict[str, str]:
    candidates = providers_from(config)
    for provider in candidates:
        try:
            probe(provider)
        except Exception as exc:
            registry.upsert_provider(provider, "QUARANTINED", type(exc).__name__)
            registry.audit("PROVIDER_QUARANTINED", provider.provider_id, type(exc).__name__)
        else:
            registry.upsert_provider(provider, "CANARY_PASSED", "protocol+model+canary")
            registry.audit("PROVIDER_READY", provider.provider_id, provider.protocol)
    if registry.active_provider_id() is None:
        initial = next(item for item in candidates if item.provider_id == config["initial_provider_id"])
        if not registry.activate(initial):
            raise LabError("initial provider failed post-activation verification")
    return registry.provider_state()


def _provider_by_id(config: dict[str, Any], provider_id: str) -> Provider:
    for provider in providers_from(config):
        if provider.provider_id == provider_id:
            return provider
    raise LabError(f"unknown provider: {provider_id}")


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "SOULAutoWireLab/1.2"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def registry(self) -> Registry:
        return self.server.registry  # type: ignore[attr-defined]

    @property
    def token(self) -> str:
        return self.server.token  # type: ignore[attr-defined]

    def send_json(self, status: int, payload: object) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {self.token}"

    def body(self) -> Any:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > MAX_BODY:
            raise LabError("invalid request size")
        return strict_json(self.rfile.read(length))

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self.send_json(200, {"ok": True})
            return
        if self.path == "/ready":
            ready = self.registry.active_provider_id() is not None
            self.send_json(200 if ready else 503, {"ready": ready})
            return
        if self.path == "/v1/models":
            if not self.authorized():
                self.send_json(401, {"error": "unauthorized"})
                return
            active = self.registry.active_provider_id()
            self.send_json(200, {"data": [{"id": active}], "machine_soul_id": self.registry.machine_soul_id()})
            return
        self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.authorized():
            self.send_json(401, {"error": "unauthorized"})
            return
        try:
            body = self.body()
        except Exception:
            self.send_json(400, {"error": "invalid_body"})
            return
        if self.path == "/v1/attach":
            try:
                session_id = self.registry.issue_session(str(body.get("client_id", "")))
            except LabError:
                self.send_json(403, {"error": "client_denied"})
                return
            self.send_json(200, {"session_id": session_id, "machine_soul_id": self.registry.machine_soul_id()})
            return
        if self.path == "/v1/chat/completions":
            session_id = self.headers.get("X-Soul-Attach-Session", "")
            if not self.registry.valid_session(session_id):
                self.send_json(403, {"error": "attach_session_denied"})
                return
            active_id = self.registry.active_provider_id()
            if active_id is None:
                self.send_json(503, {"error": "no_active_brain"})
                return
            provider = _provider_by_id(self.registry.config, active_id)
            messages = list(body.get("messages") or [])
            messages.insert(
                0,
                {
                    "role": "system",
                    "content": f"SOUL_ID={self.registry.machine_soul_id()}; MEMORY={self.registry.memory()};",
                },
            )
            try:
                text = call_provider(provider, messages)
            except LabError:
                self.send_json(502, {"error": "upstream_failed"})
                return
            self.send_json(
                200,
                {
                    "id": str(uuid.uuid4()),
                    "object": "chat.completion",
                    "model": provider.model,
                    "provider": provider.provider_id,
                    "machine_soul_id": self.registry.machine_soul_id(),
                    "choices": [{"message": {"role": "assistant", "content": text}}],
                },
            )
            return
        self.send_json(404, {"error": "not_found"})


def serve(registry: Registry, host: str, port: int) -> None:
    token = os.environ.get("SOUL_LAB_GATEWAY_TOKEN", "")
    if len(token) < 32:
        raise LabError("SOUL_LAB_GATEWAY_TOKEN must be synthetic but strong")
    server = ThreadingHTTPServer((host, port), GatewayHandler)
    server.registry = registry  # type: ignore[attr-defined]
    server.token = token  # type: ignore[attr-defined]
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("reconcile", "status", "activate", "serve"))
    parser.add_argument("--config", type=Path, default=Path("/lab/providers.json"))
    parser.add_argument("--db", type=Path, default=Path("/state/registry.sqlite3"))
    parser.add_argument("--provider")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=11435)
    args = parser.parse_args()
    config = load_config(args.config)
    registry = Registry(args.db, config)
    if args.command == "reconcile":
        print(json.dumps({"states": reconcile(registry, config), "active": registry.active_provider_id()}, sort_keys=True))
    elif args.command == "status":
        print(json.dumps({"states": registry.provider_state(), "active": registry.active_provider_id(), "generation": registry.generation()}, sort_keys=True))
    elif args.command == "activate":
        if not args.provider:
            raise SystemExit("--provider is required")
        ok = registry.activate(_provider_by_id(config, args.provider))
        print(json.dumps({"activated": ok, "active": registry.active_provider_id(), "generation": registry.generation()}))
        if not ok:
            raise SystemExit(2)
    else:
        serve(registry, args.host, args.port)


if __name__ == "__main__":
    main()
