#!/usr/bin/env python3
"""Container-side SOUL continuity probe over an authenticated Unix socket."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import sqlite3
from pathlib import Path
from typing import Any


SOUL_ID = "7f61858a-d0d3-4ca6-83f5-e4a6b3db9830"
IDENTITY_NAME = "VALERIA"
MEMORY_ANCHOR = "PISTA-5-ANOS-54K"
INSTANCE = "soul-real-models-v1"
DB = Path("/state/soul.sqlite3")
SOCKET = "/run/soul-lab/broker.sock"
CAPABILITY_FILE = Path("/run/soul-lab/client.cap")
_DEFAULT_CAPABILITY = object()


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost", timeout=250)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    capability: str | None | object = _DEFAULT_CAPABILITY,
) -> tuple[int, dict[str, Any]]:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-SOUL-Instance": INSTANCE}
    if capability is _DEFAULT_CAPABILITY:
        capability = CAPABILITY_FILE.read_text(encoding="utf-8").strip()
    if capability is not None:
        headers["Authorization"] = f"Bearer {capability}"
    connection = UnixHTTPConnection(SOCKET)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw)


def initialize() -> None:
    DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as db:
        db.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS soul_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS memories(id INTEGER PRIMARY KEY, content TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS switches(
                generation INTEGER PRIMARY KEY,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                output_sha256 TEXT NOT NULL
            );
            """
        )
        existing = dict(db.execute("SELECT key,value FROM soul_meta"))
        expected = {"soul_id": SOUL_ID, "identity_name": IDENTITY_NAME}
        if existing and existing != expected:
            raise AssertionError(f"SOUL identity drift: {existing!r}")
        db.executemany("INSERT OR IGNORE INTO soul_meta(key,value) VALUES(?,?)", expected.items())
        db.execute("INSERT OR IGNORE INTO memories(id,content) VALUES(1,?)", (MEMORY_ANCHOR,))


def soul_record() -> dict[str, str]:
    with sqlite3.connect(DB) as db:
        meta = dict(db.execute("SELECT key,value FROM soul_meta"))
        memory = db.execute("SELECT content FROM memories WHERE id=1").fetchone()[0]
    return {**meta, "memory_anchor": memory}


def parse_model_answer(raw: str) -> dict[str, str]:
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end <= start:
        raise AssertionError(f"model did not return JSON: {raw[:160]!r}")
    answer = json.loads(raw[start : end + 1])
    return {
        "soul_id": str(answer["id"]),
        "identity_name": str(answer["name"]),
        "memory_anchor": str(answer["note"]),
    }


def prompt(record: dict[str, str]) -> str:
    external_record = {
        "id": record["soul_id"],
        "name": record["identity_name"],
        "note": record["memory_anchor"],
    }
    return (
        "Do not use tools or add commentary. This is a JSON serialization test. "
        "Return exactly one JSON object with only the keys id, name, note. "
        "Copy the values byte-for-byte from this input: "
        + json.dumps(external_record, sort_keys=True)
    )


def invoke(provider: str, generation: int) -> dict[str, Any]:
    record = soul_record()
    status, result = request("POST", "/invoke", {"provider": provider, "prompt": prompt(record)})
    assert status == 200, (provider, status, result)
    try:
        answer = parse_model_answer(str(result["output"]))
    except (AssertionError, KeyError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{provider} invalid answer: {exc}") from exc
    assert answer == record, (provider, answer, record)
    digest = hashlib.sha256(str(result["output"]).encode("utf-8")).hexdigest()
    with sqlite3.connect(DB) as db:
        db.execute(
            "INSERT INTO switches(generation,provider,model,output_sha256) VALUES(?,?,?,?)",
            (generation, provider, result["model"], digest),
        )
    return {
        "generation": generation,
        "provider": provider,
        "model": result["model"],
        "elapsed_ms": result["elapsed_ms"],
        "answer_sha256": digest,
        "continuity": True,
    }


def phase1() -> None:
    initialize()
    before = request("POST", "/invoke", {"provider": "gemma", "prompt": "ignored"}, None)
    wrong = request("POST", "/invoke", {"provider": "gemma", "prompt": "ignored"}, "wrong")
    assert before[0] == wrong[0] == 401
    results = [invoke(provider, generation) for generation, provider in enumerate(("codex", "claude", "gemma"), 1)]
    receipt = {
        "phase": "cross_model",
        "soul_id": SOUL_ID,
        "memory_anchor_sha256": hashlib.sha256(MEMORY_ANCHOR.encode()).hexdigest(),
        "negative_auth": {"missing": before[0], "wrong": wrong[0]},
        "results": results,
    }
    Path("/state/phase1.json").write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))


def phase2() -> None:
    assert DB.exists()
    assert soul_record() == {
        "soul_id": SOUL_ID,
        "identity_name": IDENTITY_NAME,
        "memory_anchor": MEMORY_ANCHOR,
    }
    with sqlite3.connect(DB) as db:
        before = db.execute("SELECT COUNT(*) FROM switches").fetchone()[0]
    assert before == 3
    result = invoke("gemma", 4)
    with sqlite3.connect(DB) as db:
        after = db.execute("SELECT COUNT(*) FROM switches").fetchone()[0]
        providers = [row[0] for row in db.execute("SELECT provider FROM switches ORDER BY generation")]
    receipt = {
        "phase": "container_restart",
        "persisted_switches_before": before,
        "persisted_switches_after": after,
        "providers": providers,
        "recall_after_restart": result,
        "status": "PASS",
    }
    print(json.dumps(receipt, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("phase1", "phase2"))
    args = parser.parse_args()
    globals()[args.phase]()


if __name__ == "__main__":
    main()
