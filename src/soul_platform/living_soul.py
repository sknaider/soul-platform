"""Living SOUL profile bootstrap and candidate-first memory governance.

This module deliberately separates three authorities:

* profile bootstrap may only fill missing fields;
* model-facing clients may only propose memory candidates;
* canonical promotion is an explicit local-owner CLI operation.

The candidate database never participates in recall.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soul_framework import Soul
from soul_framework.backend.schema import SCHEMA_SQL

from soul_platform.proxy import ProxySettings


PROFILE_SCHEMA = "soul.profile.v1"
BOOT_SCHEMA = "soul.boot.public.v1"
CANDIDATE_SCHEMA = "soul.memory-candidate.v1"
PROFILE_PROPOSAL_SCHEMA = "soul.profile-proposal.v1"
DEFAULT_OCEAN = {"O": 0.5, "C": 0.5, "E": 0.5, "A": 0.5, "N": 0.5}
DEFAULT_PERSONALITY = (
    "Persistent local identity. Preserve continuity across model changes, distinguish "
    "verified memories from proposals, and say when personal context is unknown."
)
DEFAULT_PHILOSOPHY = (
    "The brain may change; the soul, memory, and identity remain."
)
DEFAULT_BOOT_CONTEXT = (
    "Search approved memory before asserting personal history. Never invent a memory, "
    "relationship, rule, or owner preference."
)
DEFAULT_RULES = {
    "memory_truth": "Use only approved memory as remembered fact; uncertainty must be explicit.",
    "owner_controlled_identity": (
        "Identity, rules, relationships, and canonical memory change only through owner-governed review."
    ),
}
_FORBIDDEN_CANDIDATE_MARKERS = (
    "<system-reminder",
    "ignore previous",
    "ignore all previous",
    "BEGIN " + "PRIVATE KEY",
    "api_key=",
    "authorization: bearer",
)
_QUESTION_PREFIX = re.compile(
    r"^(qu[eé]|qui[eé]n|c[oó]mo|cu[aá]ndo|d[oó]nde|por qu[eé]|can|could|do|does|did|what|who|how|when|where|why)\b",
    re.IGNORECASE,
)
_SECRET_CANDIDATE = re.compile(
    r"(?:\b(?:password|passwd|contrase(?:n|ñ)a|api[ _-]?key|access[ _-]?token|secret)\b"
    r"\s*(?:is|es|[:=])\s*\S+|\b(?:sk[-_](?:ant[-_]|proj[-_])?|gsk" r"_)"
    r"[A-Za-z0-9_-]{12,})",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _governance_db(settings: ProxySettings) -> Path:
    return settings.soul_db.parent / "MachineSoul.governance.sqlite3"


def _connect_governance(settings: ProxySettings) -> sqlite3.Connection:
    path = _governance_db(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS memory_candidates (
            candidate_id TEXT PRIMARY KEY,
            schema_name TEXT NOT NULL,
            machine_soul_id TEXT NOT NULL,
            soul_name TEXT NOT NULL,
            client_id TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            content TEXT NOT NULL,
            normalized_sha256 TEXT NOT NULL,
            importance INTEGER NOT NULL,
            provenance_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','promoting','promoted','rejected','stale')),
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewer TEXT,
            promoted_memory_id TEXT,
            UNIQUE(machine_soul_id, client_id, source_event_id, normalized_sha256)
        );
        CREATE INDEX IF NOT EXISTS idx_memory_candidates_status
            ON memory_candidates(machine_soul_id, status, created_at);
        CREATE TABLE IF NOT EXISTS profile_state (
            machine_soul_id TEXT PRIMARY KEY,
            schema_name TEXT NOT NULL,
            revision INTEGER NOT NULL,
            initialized_at TEXT NOT NULL,
            last_verified_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS profile_proposals (
            proposal_id TEXT PRIMARY KEY,
            schema_name TEXT NOT NULL,
            machine_soul_id TEXT NOT NULL,
            soul_name TEXT NOT NULL,
            client_id TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            change_kind TEXT NOT NULL CHECK(change_kind IN ('identity','ocean','rule','relationship')),
            target_key TEXT NOT NULL,
            patch_json TEXT NOT NULL,
            before_sha256 TEXT NOT NULL,
            after_sha256 TEXT NOT NULL,
            proposal_sha256 TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','applying','applied','rejected','stale')),
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewer TEXT,
            UNIQUE(machine_soul_id, client_id, source_event_id, proposal_sha256)
        );
        CREATE INDEX IF NOT EXISTS idx_profile_proposals_status
            ON profile_proposals(machine_soul_id, status, created_at);
        """
    )
    if os.name != "nt":
        os.chmod(path, 0o600)
    return connection


def _validate_candidate(content: object, importance: object) -> tuple[str, int]:
    if not isinstance(content, str):
        raise ValueError("candidate content must be text")
    normalized = " ".join(content.strip().split())
    if not 1 <= len(normalized) <= 2048:
        raise ValueError("candidate content must contain 1..2048 characters")
    lowered = normalized.casefold()
    if "?" in normalized or _QUESTION_PREFIX.match(normalized):
        raise ValueError("questions are not memory candidates")
    if (
        normalized.startswith("```")
        or any(marker.casefold() in lowered for marker in _FORBIDDEN_CANDIDATE_MARKERS)
        or _SECRET_CANDIDATE.search(normalized)
    ):
        raise ValueError("instructions, secrets, and tool payloads are not memory candidates")
    if not isinstance(importance, int) or isinstance(importance, bool) or not 1 <= importance <= 10:
        raise ValueError("importance must be an integer from 1 to 10")
    return normalized, importance


def propose_memory_candidate(
    settings: ProxySettings,
    *,
    client_id: str,
    source_event_id: str,
    content: object,
    importance: object = 5,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append an idempotent candidate without mutating canonical SOUL memory."""

    if not isinstance(source_event_id, str) or not 1 <= len(source_event_id.strip()) <= 200:
        raise ValueError("source_event_id is required")
    normalized, checked_importance = _validate_candidate(content, importance)
    normalized_sha = _sha256_text(normalized.casefold())
    source_digest = _sha256_text(source_event_id.strip())
    candidate_id = str(
        uuid.uuid5(
            uuid.UUID(settings.machine_soul_id),
            "\x1f".join((client_id, source_digest, normalized_sha)),
        )
    )
    safe_provenance = {
        "client_id": client_id,
        "source_event_sha256": source_digest,
        "extractor": "explicit-owner-or-client-proposal",
        "taint": "untrusted-pending-review",
    }
    if provenance:
        safe_provenance["declared"] = {
            key: value
            for key, value in provenance.items()
            if key in {"session_id", "turn_id", "surface"} and isinstance(value, str)
        }
    with _connect_governance(settings) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT OR IGNORE INTO memory_candidates(
                   candidate_id,schema_name,machine_soul_id,soul_name,client_id,
                   source_event_id,source_digest,content,normalized_sha256,importance,
                   provenance_json,status,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?)""",
            (
                candidate_id,
                CANDIDATE_SCHEMA,
                settings.machine_soul_id,
                settings.soul_name,
                client_id,
                source_event_id.strip(),
                source_digest,
                normalized,
                normalized_sha,
                checked_importance,
                _canonical_json(safe_provenance),
                _utc_now(),
            ),
        )
        row = connection.execute(
            "SELECT candidate_id,status,normalized_sha256 FROM memory_candidates WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        connection.commit()
    return dict(row)


def list_memory_candidates(
    settings: ProxySettings, *, status: str = "pending", limit: int = 50
) -> list[dict[str, Any]]:
    if status not in {"pending", "promoting", "promoted", "rejected", "stale"}:
        raise ValueError("invalid candidate status")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise ValueError("candidate limit must be 1..200")
    with _connect_governance(settings) as connection:
        rows = connection.execute(
            """SELECT candidate_id,client_id,source_digest,content,normalized_sha256,
                      importance,status,created_at,promoted_memory_id
               FROM memory_candidates
               WHERE machine_soul_id=? AND status=? ORDER BY created_at LIMIT ?""",
            (settings.machine_soul_id, status, limit),
        ).fetchall()
    return [dict(row) for row in rows]


async def promote_memory_candidate(
    settings: ProxySettings,
    *,
    candidate_id: str,
    expected_sha256: str,
) -> dict[str, Any]:
    """Promote one exact reviewed candidate; competing approvals fail closed."""

    from soul_platform.mcp_stdio import _soul_config

    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate_id is required")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ValueError("exact candidate digest is required")
    with _connect_governance(settings) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM memory_candidates WHERE candidate_id=? AND machine_soul_id=?",
            (candidate_id, settings.machine_soul_id),
        ).fetchone()
        if row is None:
            connection.rollback()
            raise ValueError("candidate is unavailable")
        if not hmac_compare(str(row["normalized_sha256"]), expected_sha256):
            connection.rollback()
            raise ValueError("candidate digest mismatch")
        if row["status"] == "promoted":
            promoted_memory_id = str(row["promoted_memory_id"])
            connection.commit()
            await _bind_promoted_memory(settings, promoted_memory_id)
            return {
                "candidate_id": candidate_id,
                "status": "promoted",
                "memory_id": promoted_memory_id,
                "idempotent": True,
            }
        if row["status"] == "promoting":
            # Recovery arm for a crash after Core committed the memory but
            # before governance wrote its terminal receipt.  Never create a
            # second canonical row; reconcile only the exact candidate id.
            connection.commit()
            with sqlite3.connect(settings.soul_db) as canonical:
                try:
                    recovered = canonical.execute(
                        """SELECT id FROM memories WHERE agent=? AND invalid_at IS NULL
                           AND json_extract(metadata,'$.candidate_id')=? LIMIT 1""",
                        (settings.soul_name, candidate_id),
                    ).fetchone()
                except sqlite3.OperationalError as exc:
                    if "no such table" not in str(exc):
                        raise
                    recovered = None
            if recovered is None:
                raise RuntimeError(
                    "candidate promotion is in progress; retry after recovery lease"
                )
            await _bind_promoted_memory(settings, str(recovered[0]))
            with _connect_governance(settings) as recovery:
                recovery.execute("BEGIN IMMEDIATE")
                changed = recovery.execute(
                    """UPDATE memory_candidates
                       SET status='promoted',promoted_memory_id=?
                       WHERE candidate_id=? AND status='promoting'""",
                    (str(recovered[0]), candidate_id),
                ).rowcount
                if changed != 1:
                    recovery.rollback()
                    raise RuntimeError("candidate recovery lost its compare-and-swap")
                recovery.commit()
            return {
                "candidate_id": candidate_id,
                "status": "promoted",
                "memory_id": str(recovered[0]),
                "idempotent": True,
                "recovered": True,
            }
        if row["status"] != "pending":
            connection.rollback()
            raise RuntimeError(f"candidate is {row['status']}; recovery/review required")
        updated = connection.execute(
            """UPDATE memory_candidates SET status='promoting',reviewed_at=?,reviewer=?
               WHERE candidate_id=? AND status='pending'""",
            (_utc_now(), "local-owner-cli", candidate_id),
        ).rowcount
        if updated != 1:
            connection.rollback()
            raise RuntimeError("candidate approval lost its compare-and-swap")
        connection.commit()
        content = str(row["content"])
        importance = int(row["importance"])

    # Cross-database exactly-once recovery: the candidate id is written into
    # canonical metadata, and an exact prior promotion is reused on retry.
    with sqlite3.connect(settings.soul_db) as canonical:
        try:
            prior = canonical.execute(
                """SELECT id FROM memories WHERE agent=? AND invalid_at IS NULL
                   AND json_extract(metadata,'$.candidate_id')=? LIMIT 1""",
                (settings.soul_name, candidate_id),
            ).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
            prior = None
    try:
        if prior is None:
            async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
                memory_id = await soul.memory.store(
                    content,
                    importance=importance,
                    source="owner-reviewed-candidate",
                    scope="private",
                    metadata={
                        "candidate_id": candidate_id,
                        "candidate_sha256": expected_sha256,
                        "governance": CANDIDATE_SCHEMA,
                    },
                )
        else:
            memory_id = int(prior[0])
        # Promotion is not terminal until T5 knows the immutable authenticated
        # owner provenance. This keeps a just-approved memory searchable in
        # the same live proxy process and leaves recovery fail-closed.
        await _bind_promoted_memory(settings, str(memory_id))
    except Exception:
        with _connect_governance(settings) as connection:
            connection.execute(
                """UPDATE memory_candidates SET status='pending',reviewed_at=NULL,reviewer=NULL
                   WHERE candidate_id=? AND status='promoting'""",
                (candidate_id,),
            )
        raise
    with _connect_governance(settings) as connection:
        connection.execute("BEGIN IMMEDIATE")
        changed = connection.execute(
            """UPDATE memory_candidates
               SET status='promoted',promoted_memory_id=?
               WHERE candidate_id=? AND status='promoting'""",
            (str(memory_id), candidate_id),
        ).rowcount
        if changed != 1:
            connection.rollback()
            raise RuntimeError("candidate promotion receipt lost its compare-and-swap")
        connection.commit()
    return {
        "candidate_id": candidate_id,
        "status": "promoted",
        "memory_id": str(memory_id),
        "idempotent": prior is not None,
    }


async def _bind_promoted_memory(settings: ProxySettings, memory_id: str) -> None:
    from soul_platform.t5_memory_egress import SQLiteT5EgressStore

    egress = SQLiteT5EgressStore(settings.t5_state_path)
    await egress.initialize()
    await egress.bind_memory(
        soul_id=settings.machine_soul_id,
        memory_id=memory_id,
        tenant=settings.t5_tenant,
        owner_subject=settings.t5_owner_subject,
        scope="private",
        origin="authenticated-write",
    )


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _profile_target_from_connection(
    connection: sqlite3.Connection,
    *,
    soul_name: str,
    change_kind: str,
    target_key: str,
) -> dict[str, Any] | None:
    """Read one canonical profile target inside the caller's transaction."""

    if change_kind == "identity":
        row = connection.execute(
            "SELECT personality,philosophy,boot_context FROM identity WHERE agent=?",
            (soul_name,),
        ).fetchone()
        if row is None:
            return None
        return {
            "personality": str(row[0] or ""),
            "philosophy": str(row[1] or ""),
            "boot_context": str(row[2] or ""),
        }
    if change_kind == "ocean":
        row = connection.execute(
            "SELECT ocean_scores FROM identity WHERE agent=?", (soul_name,)
        ).fetchone()
        if row is None:
            return None
        try:
            scores = json.loads(str(row[0] or "{}"))
        except json.JSONDecodeError:
            scores = {}
        return {key: float(scores[key]) for key in sorted(scores) if key in DEFAULT_OCEAN}
    if change_kind == "rule":
        row = connection.execute(
            """SELECT rule_key,content,priority,active FROM rules
               WHERE agent=? AND rule_key=?""",
            (soul_name, target_key),
        ).fetchone()
        if row is None:
            return None
        return {
            "rule_key": str(row[0]),
            "content": str(row[1]),
            "priority": str(row[2]),
            "active": bool(row[3]),
        }
    if change_kind == "relationship":
        row = connection.execute(
            """SELECT person,trust_level,style,dynamic FROM relationships
               WHERE agent=? AND person=?""",
            (soul_name, target_key),
        ).fetchone()
        if row is None:
            return None
        return {
            "person": str(row[0]),
            "trust_level": float(row[1]),
            "style": str(row[2] or "default"),
            "dynamic": str(row[3] or ""),
        }
    raise ValueError("unsupported profile change kind")


def _validate_profile_patch(
    change_kind: object, patch: object
) -> tuple[str, dict[str, Any], str]:
    if change_kind not in {"identity", "ocean", "rule", "relationship"}:
        raise ValueError("change_kind must be identity, ocean, rule, or relationship")
    if not isinstance(patch, dict) or not patch:
        raise ValueError("profile patch must be a non-empty object")
    kind = str(change_kind)
    if kind == "identity":
        allowed = {"personality", "philosophy", "boot_context"}
        if not set(patch) <= allowed:
            raise ValueError("identity patch contains unsupported fields")
        normalized: dict[str, Any] = {}
        for key, value in patch.items():
            if not isinstance(value, str) or not 1 <= len(value.strip()) <= 4096:
                raise ValueError(f"identity field {key} must contain 1..4096 characters")
            normalized[key] = value.strip()
        return kind, normalized, settings_target(kind, normalized)
    if kind == "ocean":
        if not set(patch) <= set(DEFAULT_OCEAN):
            raise ValueError("OCEAN patch contains unsupported dimensions")
        normalized = {}
        for key, value in patch.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"OCEAN {key} must be numeric")
            number = float(value)
            if not 0.0 <= number <= 1.0:
                raise ValueError(f"OCEAN {key} must be in [0,1]")
            normalized[key] = number
        return kind, normalized, "ocean"
    if kind == "rule":
        if not set(patch) <= {"rule_key", "content", "priority", "active"}:
            raise ValueError("rule patch contains unsupported fields")
        rule_key = patch.get("rule_key")
        if not isinstance(rule_key, str) or not 1 <= len(rule_key.strip()) <= 120:
            raise ValueError("rule_key must contain 1..120 characters")
        active = patch.get("active", True)
        if not isinstance(active, bool):
            raise ValueError("rule active must be boolean")
        content = patch.get("content", "")
        if active and (not isinstance(content, str) or not 1 <= len(content.strip()) <= 4096):
            raise ValueError("active rule content must contain 1..4096 characters")
        if not isinstance(content, str):
            raise ValueError("rule content must be text")
        priority = patch.get("priority", "normal")
        if priority not in {"normal", "critical"}:
            raise ValueError("rule priority must be normal or critical")
        normalized = {
            "rule_key": rule_key.strip(),
            "content": content.strip(),
            "priority": str(priority),
            "active": active,
        }
        return kind, normalized, normalized["rule_key"]
    if not set(patch) <= {"person", "trust_level", "style", "dynamic"}:
        raise ValueError("relationship patch contains unsupported fields")
    person = patch.get("person")
    if not isinstance(person, str) or not 1 <= len(person.strip()) <= 200:
        raise ValueError("relationship person must contain 1..200 characters")
    trust = patch.get("trust_level", 0.5)
    if isinstance(trust, bool) or not isinstance(trust, (int, float)):
        raise ValueError("relationship trust_level must be numeric")
    trust_value = float(trust)
    if not 0.0 <= trust_value <= 1.0:
        raise ValueError("relationship trust_level must be in [0,1]")
    style, dynamic = patch.get("style", "default"), patch.get("dynamic", "")
    if not isinstance(style, str) or not 1 <= len(style.strip()) <= 200:
        raise ValueError("relationship style must contain 1..200 characters")
    if not isinstance(dynamic, str) or len(dynamic.strip()) > 4096:
        raise ValueError("relationship dynamic must contain at most 4096 characters")
    normalized = {
        "person": person.strip(),
        "trust_level": trust_value,
        "style": style.strip(),
        "dynamic": dynamic.strip(),
    }
    return kind, normalized, normalized["person"]


def settings_target(change_kind: str, patch: dict[str, Any]) -> str:
    """Stable target label for profile-wide identity changes."""

    if change_kind != "identity":
        raise ValueError("settings_target is only valid for identity")
    return "+".join(sorted(patch))


def _desired_profile_target(
    before: dict[str, Any] | None,
    *,
    change_kind: str,
    patch: dict[str, Any],
) -> dict[str, Any] | None:
    if change_kind == "identity":
        result = {
            "personality": "",
            "philosophy": "",
            "boot_context": "",
            **(before or {}),
        }
        result.update(patch)
        return result
    if change_kind == "ocean":
        result = {**DEFAULT_OCEAN, **(before or {})}
        result.update(patch)
        return {key: float(result[key]) for key in sorted(DEFAULT_OCEAN)}
    if change_kind == "rule" and patch["active"] is False:
        if before is None:
            raise ValueError("cannot deactivate a rule that does not exist")
        result = dict(before)
        result["active"] = False
        return result
    return dict(patch)


def propose_profile_change(
    settings: ProxySettings,
    *,
    client_id: str,
    source_event_id: str,
    change_kind: object,
    patch: object,
) -> dict[str, Any]:
    """Stage an exact profile change. This never mutates canonical SOUL state."""

    if not isinstance(client_id, str) or not 1 <= len(client_id.strip()) <= 120:
        raise ValueError("client_id is required")
    if not isinstance(source_event_id, str) or not 1 <= len(source_event_id.strip()) <= 200:
        raise ValueError("source_event_id is required")
    kind, normalized, target_key = _validate_profile_patch(change_kind, patch)
    with sqlite3.connect(settings.soul_db) as canonical:
        canonical.row_factory = sqlite3.Row
        before = _profile_target_from_connection(
            canonical,
            soul_name=settings.soul_name,
            change_kind=kind,
            target_key=target_key,
        )
    desired = _desired_profile_target(before, change_kind=kind, patch=normalized)
    before_sha = _sha256_text(_canonical_json(before))
    after_sha = _sha256_text(_canonical_json(desired))
    source_digest = _sha256_text(source_event_id.strip())
    envelope = {
        "schema": PROFILE_PROPOSAL_SCHEMA,
        "machine_soul_id": settings.machine_soul_id,
        "soul_name": settings.soul_name,
        "client_id": client_id.strip(),
        "source_digest": source_digest,
        "change_kind": kind,
        "target_key": target_key,
        "patch": normalized,
        "before_sha256": before_sha,
        "after_sha256": after_sha,
    }
    proposal_sha = _sha256_text(_canonical_json(envelope))
    proposal_id = str(
        uuid.uuid5(
            uuid.UUID(settings.machine_soul_id),
            "\x1f".join((client_id.strip(), source_digest, proposal_sha)),
        )
    )
    with _connect_governance(settings) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT OR IGNORE INTO profile_proposals(
                   proposal_id,schema_name,machine_soul_id,soul_name,client_id,
                   source_event_id,source_digest,change_kind,target_key,patch_json,
                   before_sha256,after_sha256,proposal_sha256,status,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?)""",
            (
                proposal_id,
                PROFILE_PROPOSAL_SCHEMA,
                settings.machine_soul_id,
                settings.soul_name,
                client_id.strip(),
                source_event_id.strip(),
                source_digest,
                kind,
                target_key,
                _canonical_json(normalized),
                before_sha,
                after_sha,
                proposal_sha,
                _utc_now(),
            ),
        )
        row = connection.execute(
            """SELECT proposal_id,change_kind,target_key,proposal_sha256,before_sha256,
                      after_sha256,status FROM profile_proposals WHERE proposal_id=?""",
            (proposal_id,),
        ).fetchone()
        connection.commit()
    return dict(row)


def list_profile_proposals(
    settings: ProxySettings, *, status: str = "pending", limit: int = 50
) -> list[dict[str, Any]]:
    if status not in {"pending", "applying", "applied", "rejected", "stale"}:
        raise ValueError("invalid profile proposal status")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise ValueError("profile proposal limit must be 1..200")
    with _connect_governance(settings) as connection:
        rows = connection.execute(
            """SELECT proposal_id,client_id,source_digest,change_kind,target_key,
                      patch_json,before_sha256,after_sha256,proposal_sha256,status,
                      created_at,reviewed_at,reviewer
               FROM profile_proposals WHERE machine_soul_id=? AND status=?
               ORDER BY created_at LIMIT ?""",
            (settings.machine_soul_id, status, limit),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["patch"] = json.loads(item.pop("patch_json"))
        result.append(item)
    return result


def _apply_profile_patch(
    connection: sqlite3.Connection,
    *,
    soul_name: str,
    change_kind: str,
    target_key: str,
    patch: dict[str, Any],
) -> None:
    now = _utc_now()
    if change_kind == "identity":
        current = _profile_target_from_connection(
            connection, soul_name=soul_name, change_kind=change_kind, target_key=target_key
        ) or {"personality": "", "philosophy": "", "boot_context": ""}
        current.update(patch)
        connection.execute(
            """INSERT INTO identity(agent,personality,philosophy,boot_context,ocean_scores,updated_at)
               VALUES(?,?,?,?,?,?) ON CONFLICT(agent) DO UPDATE SET
               personality=excluded.personality,philosophy=excluded.philosophy,
               boot_context=excluded.boot_context,updated_at=excluded.updated_at""",
            (
                soul_name,
                current["personality"],
                current["philosophy"],
                current["boot_context"],
                "{}",
                now,
            ),
        )
    elif change_kind == "ocean":
        current = _profile_target_from_connection(
            connection, soul_name=soul_name, change_kind=change_kind, target_key=target_key
        ) or DEFAULT_OCEAN
        scores = {**DEFAULT_OCEAN, **current, **patch}
        connection.execute(
            """INSERT INTO identity(agent,ocean_scores,updated_at) VALUES(?,?,?)
               ON CONFLICT(agent) DO UPDATE SET ocean_scores=excluded.ocean_scores,
               updated_at=excluded.updated_at""",
            (soul_name, _canonical_json(scores), now),
        )
    elif change_kind == "rule":
        if patch["active"]:
            connection.execute(
                """INSERT INTO rules(agent,rule_key,content,set_by,priority,active,created_at)
                   VALUES(?,?,?,?,?,1,?) ON CONFLICT(agent,rule_key) DO UPDATE SET
                   content=excluded.content,set_by=excluded.set_by,
                   priority=excluded.priority,active=1""",
                (
                    soul_name,
                    patch["rule_key"],
                    patch["content"],
                    "local-owner-governance",
                    patch["priority"],
                    now,
                ),
            )
        else:
            connection.execute(
                "UPDATE rules SET active=0 WHERE agent=? AND rule_key=?",
                (soul_name, patch["rule_key"]),
            )
    else:
        connection.execute(
            """INSERT INTO relationships(agent,person,trust_level,style,dynamic,updated_at)
               VALUES(?,?,?,?,?,?) ON CONFLICT(agent,person) DO UPDATE SET
               trust_level=excluded.trust_level,style=excluded.style,
               dynamic=excluded.dynamic,updated_at=excluded.updated_at""",
            (
                soul_name,
                patch["person"],
                patch["trust_level"],
                patch["style"],
                patch["dynamic"],
                now,
            ),
        )


async def approve_profile_proposal(
    settings: ProxySettings,
    *,
    proposal_id: str,
    expected_sha256: str,
) -> dict[str, Any]:
    """Apply one exact owner-reviewed proposal with a canonical SQLite CAS."""

    if not isinstance(proposal_id, str) or not proposal_id:
        raise ValueError("proposal_id is required")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ValueError("exact proposal digest is required")
    with _connect_governance(settings) as governance:
        governance.execute("BEGIN IMMEDIATE")
        row = governance.execute(
            "SELECT * FROM profile_proposals WHERE proposal_id=? AND machine_soul_id=?",
            (proposal_id, settings.machine_soul_id),
        ).fetchone()
        if row is None:
            governance.rollback()
            raise ValueError("profile proposal is unavailable")
        if not hmac_compare(str(row["proposal_sha256"]), expected_sha256):
            governance.rollback()
            raise ValueError("profile proposal digest mismatch")
        if row["status"] == "applied":
            governance.commit()
            return {"proposal_id": proposal_id, "status": "applied", "idempotent": True}
        if row["status"] == "applying":
            # Reconcile a crash between the canonical commit and the terminal
            # governance receipt.  Exact hashes distinguish committed, not-yet
            # committed and genuinely divergent state without guessing.
            governance.commit()
            with sqlite3.connect(settings.soul_db) as canonical:
                current = _profile_target_from_connection(
                    canonical,
                    soul_name=settings.soul_name,
                    change_kind=str(row["change_kind"]),
                    target_key=str(row["target_key"]),
                )
            current_sha = _sha256_text(_canonical_json(current))
            if hmac_compare(current_sha, str(row["after_sha256"])):
                with _connect_governance(settings) as recovery:
                    recovery.execute("BEGIN IMMEDIATE")
                    changed = recovery.execute(
                        "UPDATE profile_proposals SET status='applied' "
                        "WHERE proposal_id=? AND status='applying'",
                        (proposal_id,),
                    ).rowcount
                    if changed != 1:
                        recovery.rollback()
                        raise RuntimeError("profile recovery lost its compare-and-swap")
                    recovery.execute(
                        "UPDATE profile_state SET revision=revision+1,last_verified_at=? "
                        "WHERE machine_soul_id=?",
                        (_utc_now(), settings.machine_soul_id),
                    )
                    recovery.commit()
                return {
                    "proposal_id": proposal_id,
                    "status": "applied",
                    "idempotent": True,
                    "recovered": True,
                }
            if hmac_compare(current_sha, str(row["before_sha256"])):
                raise RuntimeError(
                    "profile proposal is in progress; retry after recovery lease"
                )
            with _connect_governance(settings) as recovery:
                recovery.execute(
                    "UPDATE profile_proposals SET status='stale' "
                    "WHERE proposal_id=? AND status='applying'",
                    (proposal_id,),
                )
            raise RuntimeError("profile proposal recovery found divergent canonical state")
        if row["status"] != "pending":
            governance.rollback()
            raise RuntimeError(f"profile proposal is {row['status']}; recovery/review required")
        changed = governance.execute(
            """UPDATE profile_proposals SET status='applying',reviewed_at=?,reviewer=?
               WHERE proposal_id=? AND status='pending'""",
            (_utc_now(), "local-owner-cli", proposal_id),
        ).rowcount
        if changed != 1:
            governance.rollback()
            raise RuntimeError("profile approval lost its compare-and-swap")
        governance.commit()

    patch = json.loads(str(row["patch_json"]))
    try:
        with sqlite3.connect(settings.soul_db, timeout=15, isolation_level=None) as canonical:
            canonical.execute("PRAGMA foreign_keys=ON")
            canonical.execute("BEGIN IMMEDIATE")
            current = _profile_target_from_connection(
                canonical,
                soul_name=settings.soul_name,
                change_kind=str(row["change_kind"]),
                target_key=str(row["target_key"]),
            )
            current_sha = _sha256_text(_canonical_json(current))
            if not hmac_compare(current_sha, str(row["before_sha256"])):
                canonical.rollback()
                with _connect_governance(settings) as governance:
                    governance.execute(
                        "UPDATE profile_proposals SET status='stale' WHERE proposal_id=? AND status='applying'",
                        (proposal_id,),
                    )
                raise RuntimeError("profile proposal is stale; canonical state changed")
            _apply_profile_patch(
                canonical,
                soul_name=settings.soul_name,
                change_kind=str(row["change_kind"]),
                target_key=str(row["target_key"]),
                patch=patch,
            )
            after = _profile_target_from_connection(
                canonical,
                soul_name=settings.soul_name,
                change_kind=str(row["change_kind"]),
                target_key=str(row["target_key"]),
            )
            after_sha = _sha256_text(_canonical_json(after))
            if not hmac_compare(after_sha, str(row["after_sha256"])):
                canonical.rollback()
                raise RuntimeError("profile proposal post-write verification failed")
            canonical.commit()
    except Exception:
        with _connect_governance(settings) as governance:
            governance.execute(
                """UPDATE profile_proposals SET status='pending',reviewed_at=NULL,reviewer=NULL
                   WHERE proposal_id=? AND status='applying'""",
                (proposal_id,),
            )
        raise
    with _connect_governance(settings) as governance:
        governance.execute("BEGIN IMMEDIATE")
        finalized = governance.execute(
            "UPDATE profile_proposals SET status='applied' WHERE proposal_id=? AND status='applying'",
            (proposal_id,),
        ).rowcount
        if finalized != 1:
            governance.rollback()
            raise RuntimeError("profile proposal receipt lost its compare-and-swap")
        governance.execute(
            "UPDATE profile_state SET revision=revision+1,last_verified_at=? WHERE machine_soul_id=?",
            (_utc_now(), settings.machine_soul_id),
        )
        governance.commit()
    return {"proposal_id": proposal_id, "status": "applied", "idempotent": False}


async def ensure_initial_profile(settings: ProxySettings) -> dict[str, Any]:
    """Fill only missing profile fields; never overwrite customized state."""
    changed: list[str] = []

    # Bootstrap must not initialize the configured ANN index.  Apart from making
    # ``soul-machine init`` unnecessarily expensive, doing so couples identity
    # creation to optional native search dependencies.  The canonical Platform
    # store is SQLite, so initialize its portable Core schema and seed only
    # missing profile fields in one local transaction.
    settings.soul_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(settings.soul_db, timeout=15, isolation_level=None) as canonical:
        canonical.execute("PRAGMA foreign_keys=ON")
        canonical.executescript(SCHEMA_SQL)
        canonical.execute("BEGIN IMMEDIATE")
        now = _utc_now()
        identity = canonical.execute(
            "SELECT personality,philosophy,boot_context,ocean_scores "
            "FROM identity WHERE agent=?",
            (settings.soul_name,),
        ).fetchone()
        if identity is None:
            canonical.execute(
                """INSERT INTO identity(
                       agent,personality,philosophy,boot_context,ocean_scores,updated_at
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    settings.soul_name,
                    DEFAULT_PERSONALITY,
                    DEFAULT_PHILOSOPHY,
                    DEFAULT_BOOT_CONTEXT,
                    _canonical_json(DEFAULT_OCEAN),
                    now,
                ),
            )
            changed.extend(("personality", "philosophy", "boot_context", "ocean"))
        else:
            identity_fields = {
                "personality": DEFAULT_PERSONALITY,
                "philosophy": DEFAULT_PHILOSOPHY,
                "boot_context": DEFAULT_BOOT_CONTEXT,
            }
            for index, (field, default) in enumerate(identity_fields.items()):
                if not str(identity[index] or "").strip():
                    canonical.execute(
                        f"UPDATE identity SET {field}=?,updated_at=? WHERE agent=?",
                        (default, now, settings.soul_name),
                    )
                    changed.append(field)
            try:
                ocean = json.loads(str(identity[3] or "{}"))
            except (TypeError, json.JSONDecodeError):
                ocean = {}
            if not ocean:
                canonical.execute(
                    "UPDATE identity SET ocean_scores=?,updated_at=? WHERE agent=?",
                    (_canonical_json(DEFAULT_OCEAN), now, settings.soul_name),
                )
                changed.append("ocean")
        for key, content in DEFAULT_RULES.items():
            if canonical.execute(
                "SELECT 1 FROM rules WHERE agent=? AND rule_key=?",
                (settings.soul_name, key),
            ).fetchone() is None:
                canonical.execute(
                    """INSERT INTO rules(
                           agent,rule_key,content,set_by,priority,active,created_at
                       ) VALUES(?,?,?,?,?,1,?)""",
                    (
                        settings.soul_name,
                        key,
                        content,
                        "platform-bootstrap",
                        "critical",
                        now,
                    ),
                )
                changed.append(f"rule:{key}")
        canonical.commit()
    if os.name != "nt":
        os.chmod(settings.soul_db, 0o600)

    now = _utc_now()
    with _connect_governance(settings) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT revision,initialized_at FROM profile_state WHERE machine_soul_id=?",
            (settings.machine_soul_id,),
        ).fetchone()
        if row is None:
            revision, initialized_at = 1, now
            connection.execute(
                "INSERT INTO profile_state VALUES(?,?,?,?,?)",
                (settings.machine_soul_id, PROFILE_SCHEMA, revision, initialized_at, now),
            )
        else:
            revision, initialized_at = int(row["revision"]), str(row["initialized_at"])
            connection.execute(
                "UPDATE profile_state SET last_verified_at=? WHERE machine_soul_id=?",
                (now, settings.machine_soul_id),
            )
        connection.commit()
    return {
        "schema": PROFILE_SCHEMA,
        "machine_soul_id": settings.machine_soul_id,
        "revision": revision,
        "initialized_at": initialized_at,
        "changed": changed,
    }


async def public_boot_projection(settings: ProxySettings) -> dict[str, Any]:
    """Return non-secret readiness metadata safe for an unconsented cloud client."""

    from soul_platform.mcp_stdio import _soul_config

    async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
        identity = await soul.identity.get()
        ocean = await soul.identity.get_ocean()
        rules = await soul.rules.list()
        relationships = await soul.identity.get_relationships()
        last_thought = await soul._reflection.get_last_thought()
    # Boot is the hot path. Count canonical rows without loading or embedding
    # their content, keeping the public projection independent of corpus size.
    with sqlite3.connect(f"file:{settings.soul_db.resolve()}?mode=ro", uri=True) as soul_db:
        memory_count = int(
            soul_db.execute(
                "SELECT count(*) FROM memories WHERE agent=? AND invalid_at IS NULL",
                (settings.soul_name,),
            ).fetchone()[0]
        )
    with _connect_governance(settings) as connection:
        profile = connection.execute(
            "SELECT revision FROM profile_state WHERE machine_soul_id=?",
            (settings.machine_soul_id,),
        ).fetchone()
        pending = connection.execute(
            "SELECT count(*) FROM memory_candidates WHERE machine_soul_id=? AND status='pending'",
            (settings.machine_soul_id,),
        ).fetchone()[0]
    initialized = bool(identity and str(identity.get("personality") or "").strip() and ocean)
    return {
        "schema": BOOT_SCHEMA,
        "machine_soul_id": settings.machine_soul_id,
        "soul_name": settings.soul_name,
        "profile_revision": int(profile["revision"]) if profile else 0,
        "profile_initialized": initialized,
        "state": {
            "memory_count": memory_count,
            "rule_count": len(rules),
            "relationship_count": len(relationships),
            "has_last_reflection": bool(last_thought),
            "pending_memory_candidates": int(pending),
            "embedding_provider": settings.embedding_provider,
            "embedding_dimensions": settings.embedding_dimensions,
            "vector_index": settings.memory_vector_index,
        },
        "generated_at": _utc_now(),
    }


async def private_boot_context(settings: ProxySettings) -> tuple[str, dict[str, Any]]:
    """Return the consent-gated identity projection, excluding inner thought/history."""

    from soul_platform.mcp_stdio import _soul_config

    async with Soul.create(settings.soul_name, config=_soul_config(settings)) as soul:
        identity = await soul.identity.get() or {}
        ocean = await soul.identity.get_ocean() or {}
        relationships = await soul.identity.get_relationships()
        rules = await soul.rules.get_critical(limit=5)
    projection = {
        "schema": "soul.boot.private.v1",
        "machine_soul_id": settings.machine_soul_id,
        "soul_name": settings.soul_name,
        "identity": {
            "personality": str(identity.get("personality") or ""),
            "philosophy": str(identity.get("philosophy") or ""),
            "boot_context": str(identity.get("boot_context") or ""),
            "ocean": ocean,
        },
        "relationships": [
            {
                "person": str(row.get("person") or ""),
                "trust_level": float(row.get("trust_level", 0.5)),
                "style": str(row.get("style") or "default"),
            }
            for row in relationships
        ],
        "critical_rules": [
            {"rule_key": str(row["rule_key"]), "content": str(row["content"])}
            for row in rules
        ],
        "generated_at": _utc_now(),
    }
    lines = [
        "SOUL LOCAL PRIVATE PROFILE (owner-consented cloud release).",
        f"machine_soul_id={settings.machine_soul_id}",
        f"## Identity: {settings.soul_name}",
        projection["identity"]["personality"],
        f"Philosophy: {projection['identity']['philosophy']}",
        f"Boot context: {projection['identity']['boot_context']}",
        "OCEAN: " + ", ".join(f"{key}={value}" for key, value in sorted(ocean.items())),
    ]
    if projection["relationships"]:
        lines.append("## Relationships")
        lines.extend(
            f"- {row['person']}: trust={row['trust_level']}, style={row['style']}"
            for row in projection["relationships"]
        )
    if projection["critical_rules"]:
        lines.append("## Critical Rules")
        lines.extend(
            f"- {row['rule_key']}: {row['content']}" for row in projection["critical_rules"]
        )
    lines.append("Memory contents are not part of boot; recall only approved excerpts per prompt.")
    return "\n".join(line for line in lines if line), projection


def public_boot_text(projection: dict[str, Any]) -> str:
    state = projection["state"]
    return (
        "SOUL LOCAL CONNECTED (public projection).\n"
        f"machine_soul_id={projection['machine_soul_id']}\n"
        f"soul_name={projection['soul_name']}\n"
        f"profile_initialized={str(projection['profile_initialized']).lower()}\n"
        f"profile_revision={projection['profile_revision']}\n"
        f"approved_memory_count={state['memory_count']}\n"
        "Private identity, relationships, rules, reflections, and memory contents were not released. "
        "Use approved MCP tools; do not infer missing personal context."
    )


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
