#!/usr/bin/env python3
"""Adversarial by-effect verifier for the containerized Auto-Wire lab."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from autowire_lab import Registry, _provider_by_id, load_config


CONFIG_PATH = Path("/lab/providers.json")
DB_PATH = Path("/state/registry.sqlite3")
BASE = "http://gateway:11435"
TOKEN = os.environ["SOUL_LAB_GATEWAY_TOKEN"]
CHINESE_PROVIDERS = {"qwen", "deepseek", "glm", "kimi", "ernie", "hunyuan", "doubao", "minimax"}


def request(method: str, path: str, payload: object | None = None, *, token: str | None = TOKEN, session: str | None = None) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode()
    req = Request(BASE + path, data=body, method=method)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    if session is not None:
        req.add_header("X-Soul-Attach-Session", session)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def chat(session: str) -> dict:
    status, payload = request(
        "POST",
        "/v1/chat/completions",
        {"messages": [{"role": "user", "content": "¿Qué recuerdas y quién eres?"}]},
        session=session,
    )
    assert status == 200, payload
    return payload


def assert_continuity(payload: dict, provider_id: str, soul_id: str) -> None:
    text = payload["choices"][0]["message"]["content"]
    assert payload["provider"] == provider_id
    assert payload["machine_soul_id"] == soul_id
    assert f"provider={provider_id}" in text
    assert f"soul={soul_id}" in text
    assert "memory=VALERIA-RECUERDA-AYER" in text


def phase1() -> None:
    config = load_config(CONFIG_PATH)
    registry = Registry(DB_PATH, config)
    states = registry.provider_state()
    assert len(states) == 14
    assert {name for name, state in states.items() if state == "QUARANTINED"} == {"badjson", "redirect"}
    assert all(states[name] == "CANARY_PASSED" for name in CHINESE_PROVIDERS)
    assert registry.active_provider_id() == "qwen"
    soul_id = registry.machine_soul_id()
    assert soul_id == config["machine_soul_id"]

    status, _ = request("GET", "/v1/models", token=None)
    assert status == 401
    status, _ = request("POST", "/v1/attach", {"client_id": "codex"}, token="wrong-token-that-is-long-enough")
    assert status == 401
    status, _ = request("POST", "/v1/attach", {"client_id": "unknown-app"})
    assert status == 403
    status, attached = request("POST", "/v1/attach", {"client_id": "codex"})
    assert status == 200 and attached["machine_soul_id"] == soul_id
    session = attached["session_id"]
    status, _ = request("POST", "/v1/chat/completions", {"messages": []})
    assert status == 403

    assert_continuity(chat(session), "qwen", soul_id)

    concurrent_generation = registry.generation()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda provider_id: registry.activate(
                    _provider_by_id(config, provider_id),
                    expected_generation=concurrent_generation,
                ),
                ("deepseek", "glm"),
            )
        )
    assert sorted(results) == [False, True]
    assert registry.generation() == concurrent_generation + 1
    assert registry.active_provider_id() in {"deepseek", "glm"}
    assert_continuity(chat(session), registry.active_provider_id(), soul_id)
    assert registry.activate(_provider_by_id(config, "qwen")) is True

    for provider_id in ("deepseek", "doubao", "minimax", "gemini", "ollama", "qwen"):
        assert registry.activate(_provider_by_id(config, provider_id)) is True
        assert_continuity(chat(session), provider_id, soul_id)

    generation_before = registry.generation()
    assert registry.activate(_provider_by_id(config, "flaky")) is False
    assert registry.active_provider_id() == "qwen"
    assert registry.generation() == generation_before + 2
    assert_continuity(chat(session), "qwen", soul_id)
    assert registry.machine_soul_id() == soul_id
    assert registry.memory() == "VALERIA-RECUERDA-AYER"
    counts = registry.audit_counts()
    assert counts.get("BINDING_ROLLED_BACK") == 1

    with sqlite3.connect(DB_PATH) as db:
        dump = "\n".join(db.iterdump())
    assert TOKEN not in dump
    Path("/state/phase1.json").write_text(
        json.dumps({"session": session, "soul": soul_id, "generation": registry.generation()}, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps({"phase": 1, "providers": len(states), "quarantined": 2, "protocols": 5, "sequential_swaps": 7, "concurrent_claims": 2, "concurrent_winners": 1, "rollback": 1, "status": "PASS"}, sort_keys=True))


def phase2() -> None:
    config = load_config(CONFIG_PATH)
    registry = Registry(DB_PATH, config)
    before = json.loads(Path("/state/phase1.json").read_text(encoding="utf-8"))
    session = registry.latest_session()
    assert session == before["session"]
    assert registry.valid_session(session)
    assert registry.machine_soul_id() == before["soul"]
    assert registry.generation() == before["generation"]
    assert registry.active_provider_id() == "qwen"
    assert_continuity(chat(session), "qwen", before["soul"])
    evidence = {
        "schema": "soul.autowire-world-lab.evidence.v1",
        "status": "PASS",
        "providers_total": len(registry.provider_state()),
        "providers_quarantined": 2,
        "chinese_provider_canaries": len(CHINESE_PROVIDERS),
        "protocol_families": 5,
        "sequential_brain_swaps_verified": 7,
        "concurrent_brain_switch_claims": 2,
        "concurrent_single_winner_verified": True,
        "rollback_verified": True,
        "gateway_restart_persisted": True,
        "attach_auth_negative_verified": True,
        "memory_continuity_verified": True,
        "machine_soul_id": before["soul"],
        "active_provider": registry.active_provider_id(),
        "binding_generation": registry.generation(),
        "audit_counts": registry.audit_counts(),
    }
    Path("/state/evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2), encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"phase1", "phase2"}:
        raise SystemExit("usage: verify_lab.py phase1|phase2")
    globals()[sys.argv[1]]()
