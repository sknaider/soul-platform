from __future__ import annotations

import hashlib
import asyncio
import json
import os
import sqlite3
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import soul_platform.embedding_cutover as cutover
from soul_framework import Soul
from soul_framework.config import SoulConfig
from soul_framework.backend.schema import SCHEMA_SQL

from soul_platform.bootstrap import initialize
from soul_platform.embedding_cutover import (
    _exclusive_sqlite_probe,
    activate,
    prepare,
    rollback,
    verify_candidate,
)
from soul_platform.proxy import ProxySettings


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _db(path: Path, marker: str) -> None:
    # Cutover exercises a deliberately legacy database.  initialize() now
    # creates a live profile, so rebuild this temporary fixture from a clean
    # Core schema instead of accidentally comparing seeded vs unseeded stores.
    path.unlink(missing_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA_SQL)
        connection.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker VALUES (?)", (marker,))


def _checkpoint(source: Path, candidate: Path, checkpoint: Path) -> dict:
    with sqlite3.connect(source) as connection:
        source_nonvector = cutover._migration_hash(
            connection, include_vectors=False
        )
        source_vector = cutover._migration_hash(connection, include_vectors=True)
    state = {
        "version": 1,
        "status": "completed",
        "plan": {
            "source": str(source.resolve()),
            "candidate": str(candidate.resolve()),
            "checkpoint": str(checkpoint.resolve()),
            "source_dimensions": 128,
            "target_dimensions": 1024,
            "source_sha256": _sha(source),
            "source_nonvector_sha256": source_nonvector,
            "source_vector_sha256": source_vector,
            "rows": {"memories": 0, "procedural_memories": 0},
        },
        "candidate_sha256": _sha(candidate),
    }
    checkpoint.write_text(json.dumps(state))
    return state


def _legacy_install(tmp_path: Path):
    result = initialize(
        root=tmp_path / "SOUL",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    text = result.config.read_text()
    start, end = text.index("[embedding]"), text.index("[proxy]")
    result.config.write_text(text[:start] + text[end:])
    _db(result.soul_db, "original-128")
    # Recreate the live profile that a real initialized legacy installation
    # carries.  The migration candidate must start with identical non-vector
    # content or the cutover verifier correctly rejects it.
    initialize(
        root=result.root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    with sqlite3.connect(result.soul_db) as connection:
        connection.execute("PRAGMA user_version=128")
    candidate = result.root / "MachineSoul.bge-m3.candidate.db"
    checkpoint = result.root / "MachineSoul.bge-m3.checkpoint.json"
    shutil.copy2(result.soul_db, candidate)
    with sqlite3.connect(candidate) as connection:
        connection.execute("PRAGMA user_version=1024")
    return result, candidate, checkpoint


def _marker(path: Path) -> str:
    with sqlite3.connect(path) as connection:
        return str(connection.execute("SELECT value FROM marker").fetchone()[0])


def test_activate_and_rollback_preserve_both_database_generations(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    original_config = result.config.read_bytes()
    original_sha = _sha(result.soul_db)
    candidate_sha = _sha(candidate)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)

    active = activate(result.config, checkpoint)
    assert active["activation"]["status"] == "active"
    assert _marker(result.soul_db) == "original-128"
    assert _marker(candidate) == "original-128"
    assert _sha(candidate) == candidate_sha
    assert Path(active["activation"]["source_backup"]).is_file()
    settings = ProxySettings.from_toml(result.config)
    assert settings.soul_db == candidate.resolve()
    assert (settings.embedding_provider, settings.embedding_dimensions) == ("bge-m3", 1024)
    assert settings.memory_vector_index == "auto"

    # Re-running the product initializer after cutover must preserve the
    # active pointer instead of silently returning the legacy filename.
    initialized_again = initialize(
        root=result.root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    assert initialized_again.created is False
    assert initialized_again.soul_db == candidate.resolve()
    assert initialized_again.machine_soul_id == result.machine_soul_id

    restored = rollback(result.config, checkpoint)
    assert restored["activation"]["status"] == "rolled-back"
    assert _marker(result.soul_db) == "original-128"
    assert _sha(result.soul_db) == original_sha
    assert result.config.read_bytes() == original_config
    retained = Path(restored["activation"]["retained_candidate"])
    assert retained.is_file() and _sha(retained) == candidate_sha
    legacy = ProxySettings.from_toml(result.config)
    assert (legacy.embedding_provider, legacy.embedding_dimensions) == ("simple", 128)

    async def startup_smoke():
        config = SoulConfig(
            backend="sqlite",
            backend_url=str(legacy.soul_db),
            embedding_provider="simple",
            embedding_dimensions=128,
            memory_vector_index="exact",
            dni_credential_path=str(legacy.dni_credential_file),
            dni_trust_store_path=str(legacy.dni_trust_store_file),
            dni_trust_store_sha256=legacy.dni_trust_store_sha256,
            machine_soul_id=legacy.machine_soul_id,
        )
        async with Soul.create(legacy.soul_name, config=config) as soul:
            assert isinstance(await soul.boot(), str)

    asyncio.run(startup_smoke())


def test_explicit_legacy_embedding_block_is_replaced_and_rollback_is_exact(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    legacy_block = (
        '[embedding]\nprovider = "simple"\ndimensions = 128\nmodel = "simple"\n'
        'url = "http://127.0.0.1:11434/api/embed"\ntimeout_seconds = 60\n'
        'vector_index = "exact"\n\n'
    )
    config_text = result.config.read_text()
    insertion = config_text.index("[proxy]")
    result.config.write_text(config_text[:insertion] + legacy_block + config_text[insertion:])
    original = result.config.read_bytes()
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)

    activate(result.config, checkpoint)
    active = ProxySettings.from_toml(result.config)
    assert (
        active.embedding_provider,
        active.embedding_dimensions,
        active.embedding_model,
        active.memory_vector_index,
    ) == ("bge-m3", 1024, "bge-m3", "auto")
    assert result.config.read_text().count("[embedding]") == 1

    rollback(result.config, checkpoint)
    assert result.config.read_bytes() == original
    restored = ProxySettings.from_toml(result.config)
    assert (
        restored.embedding_provider,
        restored.embedding_dimensions,
        restored.embedding_model,
        restored.memory_vector_index,
    ) == ("simple", 128, "simple", "exact")


def test_candidate_or_source_byte_mismatch_fails_before_any_move(tmp_path):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    candidate.write_bytes(candidate.read_bytes() + b"tamper")
    source_before = _sha(result.soul_db)
    with pytest.raises(ValueError, match="candidate bytes"):
        activate(result.config, checkpoint)
    assert _sha(result.soul_db) == source_before
    assert candidate.is_file()
    assert not list(result.root.glob("*.backup"))


def test_corrupt_wal_sidecar_fails_before_activation(tmp_path):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    Path(f"{result.soul_db}-wal").write_bytes(b"live")
    with pytest.raises(RuntimeError, match="stop SOUL Platform"):
        activate(result.config, checkpoint)
    assert _marker(result.soul_db) == "original-128"
    assert candidate.is_file()


def test_clean_stopped_wal_is_checkpointed_before_fingerprinting(tmp_path):
    result, _candidate, _checkpoint = _legacy_install(tmp_path)
    crash_db = tmp_path / "crash-source.db"
    shutil.copy2(result.soul_db, crash_db)
    connection = sqlite3.connect(crash_db)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute(
        "INSERT INTO memories(agent, content, embedding, valid_from, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "MachineSoul",
            "committed before cutover",
            b"x" * 512,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
    )
    connection.commit()
    shutil.copy2(crash_db, result.soul_db)
    shutil.copy2(f"{crash_db}-wal", f"{result.soul_db}-wal")
    shutil.copy2(f"{crash_db}-shm", f"{result.soul_db}-shm")
    connection.close()

    _exclusive_sqlite_probe(result.soul_db, checkpoint_wal=True)
    with sqlite3.connect(result.soul_db) as verified:
        count = verified.execute(
            "SELECT COUNT(*) FROM memories WHERE content='committed before cutover'"
        ).fetchone()[0]
    assert count == 1
    assert not Path(f"{result.soul_db}-wal").exists() or not Path(
        f"{result.soul_db}-wal"
    ).stat().st_size


def test_activation_rejects_wal_committed_after_candidate_fingerprint(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    with sqlite3.connect(result.soul_db) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
    _checkpoint(result.soul_db, candidate, checkpoint)

    script = """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute(
    "INSERT INTO memories(agent, content, embedding, valid_from, created_at) "
    "VALUES (?, ?, ?, ?, ?)",
    ('MachineSoul', 'late committed row', b'x' * 512,
     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
)
connection.commit()
os._exit(0)
    """
    subprocess.run([sys.executable, "-c", script, str(result.soul_db)], check=True)
    with sqlite3.connect(result.soul_db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM memories WHERE content='late committed row'"
        ).fetchone()[0] == 1
    source_before = _sha(result.soul_db)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)

    # Depending on whether SQLite has checkpointed the committed WAL into the
    # main file, the byte preflight raises ValueError or the fenced logical
    # comparison raises RuntimeError.  Both are the intended fail-closed path.
    with pytest.raises((ValueError, RuntimeError), match="source changed"):
        activate(result.config, checkpoint)

    assert _sha(result.soul_db) == source_before
    assert _marker(result.soul_db) == "original-128"
    assert candidate.is_file()
    assert not list(result.root.glob("*.backup"))


def test_activation_rejects_write_that_arrives_during_slow_bge_probe(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    with sqlite3.connect(result.soul_db) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
    _checkpoint(result.soul_db, candidate, checkpoint)

    script = """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute(
    "INSERT INTO memories(agent, content, embedding, valid_from, created_at) "
    "VALUES (?, ?, ?, ?, ?)",
    ('MachineSoul', 'arrived during BGE probe', b'x' * 512,
     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
)
connection.commit()
os._exit(0)
"""

    def probe_with_concurrent_write():
        subprocess.run(
            [sys.executable, "-c", script, str(result.soul_db)], check=True
        )
        with sqlite3.connect(result.soul_db) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM memories "
                "WHERE content='arrived during BGE probe'"
            ).fetchone()[0] == 1

    monkeypatch.setattr(
        "soul_platform.embedding_cutover._probe_bge", probe_with_concurrent_write
    )
    with pytest.raises(RuntimeError, match="source changed"):
        activate(result.config, checkpoint)

    assert _marker(result.soul_db) == "original-128"
    assert candidate.is_file()
    assert not list(result.root.glob("*.backup"))


def test_rollback_after_core_enables_wal_restores_original_without_data_loss(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    original_sha = _sha(result.soul_db)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    activate(result.config, checkpoint)

    # Soul Framework opens SQLite in WAL mode.  That page-layout change must
    # not disable installer recovery when the logical database is untouched.
    with sqlite3.connect(candidate) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"

    restored = rollback(result.config, checkpoint)
    retained = Path(restored["activation"]["retained_candidate"])
    assert restored["activation"]["status"] == "rolled-back"
    assert _marker(result.soul_db) == "original-128"
    assert _marker(retained) == "original-128"


def test_rollback_refuses_to_discard_a_post_cutover_logical_write(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    activate(result.config, checkpoint)

    with sqlite3.connect(candidate) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO marker VALUES ('post-cutover-write')")

    with pytest.raises(RuntimeError, match="differs from the recorded candidate"):
        rollback(result.config, checkpoint)
    with sqlite3.connect(candidate) as connection:
        assert {row[0] for row in connection.execute("SELECT value FROM marker")} == {
            "original-128",
            "post-cutover-write",
        }
    assert Path(json.loads(checkpoint.read_text())["activation"]["source_backup"]).is_file()


def test_rollback_rejects_mutated_inactive_source_and_preserves_active_pointer(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    activate(result.config, checkpoint)
    active_config = result.config.read_bytes()

    with sqlite3.connect(result.soul_db) as connection:
        connection.execute("INSERT INTO marker VALUES ('mutated-legacy-source')")

    with pytest.raises(RuntimeError, match="preserved source differs"):
        rollback(result.config, checkpoint)
    assert result.config.read_bytes() == active_config
    assert ProxySettings.from_toml(result.config).soul_db == candidate.resolve()
    with sqlite3.connect(result.soul_db) as connection:
        assert "mutated-legacy-source" in {
            str(row[0]) for row in connection.execute("SELECT value FROM marker")
        }


@pytest.mark.parametrize(
    "schema_mutation",
    (
        "CREATE INDEX unexpected_marker_index ON marker(value)",
        "CREATE TRIGGER unexpected_marker_trigger AFTER INSERT ON marker "
        "BEGIN UPDATE marker SET value=value; END",
    ),
)
def test_rollback_rejects_inactive_source_schema_mutation(
    tmp_path, monkeypatch, schema_mutation
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    activate(result.config, checkpoint)
    active_config = result.config.read_bytes()

    with sqlite3.connect(result.soul_db) as connection:
        connection.execute(schema_mutation)

    with pytest.raises(RuntimeError, match="preserved source differs"):
        rollback(result.config, checkpoint)
    assert result.config.read_bytes() == active_config
    assert ProxySettings.from_toml(result.config).soul_db == candidate.resolve()


def test_rollback_fences_source_and_candidate_through_pointer_switch(
    tmp_path, monkeypatch
):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    activate(result.config, checkpoint)
    attempts = []
    transactions = []
    script = """
import sqlite3, sys
try:
    connection = sqlite3.connect(sys.argv[1], timeout=0)
    connection.execute("INSERT INTO marker VALUES ('rollback-race')")
    connection.commit()
except sqlite3.OperationalError:
    raise SystemExit(23)
raise SystemExit(0)
"""

    def attack_while_fenced(source_connection, candidate_connection):
        transactions.append(
            (source_connection.in_transaction, candidate_connection.in_transaction)
        )
        for path in (result.soul_db, candidate):
            attempts.append(
                subprocess.run(
                    [sys.executable, "-c", script, str(path)], check=False
                ).returncode
            )

    monkeypatch.setattr(cutover, "_after_rollback_journal", attack_while_fenced)
    restored = rollback(result.config, checkpoint)

    assert restored["activation"]["status"] == "rolled-back"
    assert transactions == [(True, True)]
    assert attempts == [23, 23]
    assert ProxySettings.from_toml(result.config).soul_db == result.soul_db.resolve()
    for path in (result.soul_db, candidate):
        with sqlite3.connect(path) as connection:
            assert "rollback-race" not in {
                str(row[0]) for row in connection.execute("SELECT value FROM marker")
            }


def test_mixed_128d_candidate_is_rejected_even_with_matching_checkpoint(tmp_path):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    with sqlite3.connect(candidate) as connection:
        connection.execute(
            "INSERT INTO memories(agent, content, embedding, valid_from, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "MachineSoul",
                "legacy vector",
                b"x" * 512,
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
    state = _checkpoint(result.soul_db, candidate, checkpoint)
    state["plan"]["rows"]["memories"] = 1
    checkpoint.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="embedding gate failed"):
        verify_candidate(checkpoint)


def test_source_symlink_is_rejected_before_probe_or_move(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    real_source = result.root / "real-source.db"
    result.soul_db.rename(real_source)
    result.soul_db.symlink_to(real_source)
    state = _checkpoint(real_source, candidate, checkpoint)
    state["plan"]["source"] = str(result.soul_db.absolute())
    checkpoint.write_text(json.dumps(state))
    called = False

    def probe():
        nonlocal called
        called = True

    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", probe)
    with pytest.raises(ValueError, match="symlink/reparse"):
        activate(result.config, checkpoint)
    assert called is False
    assert candidate.is_file() and real_source.is_file()


def test_parent_symlink_is_rejected_before_resolve(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    source = real / "source.db"
    candidate = real / "candidate.db"
    checkpoint = real / "checkpoint.json"
    _db(source, "source")
    _db(candidate, "candidate")
    _checkpoint(source, candidate, checkpoint)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    state = json.loads(checkpoint.read_text())
    state["plan"]["source"] = str(linked / "source.db")
    checkpoint.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="symlink/reparse path component"):
        verify_candidate(checkpoint)


def test_bge_readiness_failure_prevents_activation(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)

    def fail():
        raise RuntimeError("local BGE-M3 readiness probe failed")

    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", fail)
    with pytest.raises(RuntimeError, match="readiness"):
        activate(result.config, checkpoint)
    assert _marker(result.soul_db) == "original-128"
    assert candidate.is_file()


def test_late_source_writer_is_blocked_by_activation_fence(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    attempts = []
    script = """
import sqlite3, sys
try:
    connection = sqlite3.connect(sys.argv[1], timeout=0)
    connection.execute("INSERT INTO marker VALUES ('late-writer')")
    connection.commit()
except sqlite3.OperationalError:
    raise SystemExit(23)
raise SystemExit(0)
"""

    def attack_source(_source_connection, _candidate_connection):
        attempts.append(
            subprocess.run(
                [sys.executable, "-c", script, str(result.soul_db)], check=False
            ).returncode
        )

    monkeypatch.setattr(cutover, "_after_activation_journal", attack_source)
    active = activate(result.config, checkpoint)
    assert active["activation"]["status"] == "active"
    assert attempts == [23]
    with sqlite3.connect(result.soul_db) as connection:
        values = {str(row[0]) for row in connection.execute("SELECT value FROM marker")}
    assert values == {"original-128"}


def test_candidate_writer_is_blocked_after_activation_journal(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    attempts = []
    script = """
import sqlite3, sys
try:
    connection = sqlite3.connect(sys.argv[1], timeout=0)
    connection.execute("INSERT INTO marker VALUES ('candidate-race')")
    connection.commit()
except sqlite3.OperationalError:
    raise SystemExit(23)
raise SystemExit(0)
"""

    transactions = []

    def attack_while_fenced(source_connection, candidate_connection):
        transactions.append(
            (source_connection.in_transaction, candidate_connection.in_transaction)
        )
        attempts.append(
            subprocess.run(
                [sys.executable, "-c", script, str(candidate)], check=False
            ).returncode
        )

    monkeypatch.setattr(cutover, "_after_activation_journal", attack_while_fenced)
    before_baseline = ProxySettings.from_toml(result.config).baseline_hash
    active = activate(result.config, checkpoint)
    after = ProxySettings.from_toml(result.config)

    assert active["activation"]["status"] == "active"
    assert transactions == [(True, True)]
    assert attempts == [23]
    assert _marker(candidate) == "original-128"
    assert after.soul_db == candidate.resolve()
    assert after.baseline_hash == before_baseline


def test_cutover_rejects_source_candidate_hardlink_alias(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    _checkpoint(result.soul_db, candidate, checkpoint)
    candidate.unlink()
    os.link(result.soul_db, candidate)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)

    with pytest.raises(ValueError, match="must not alias"):
        activate(result.config, checkpoint)


def test_failed_activation_checkpoint_is_retriable(tmp_path, monkeypatch):
    result, candidate, checkpoint = _legacy_install(tmp_path)
    state = _checkpoint(result.soul_db, candidate, checkpoint)
    state["activation"] = {"status": "activation-failed-rolled-back"}
    checkpoint.write_text(json.dumps(state))
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    activated = activate(result.config, checkpoint)
    assert activated["activation"]["status"] == "active"


class _SimulatedProcessDeath(BaseException):
    """Bypass normal exception cleanup just like SIGKILL/power loss would."""


def _generation_digests(*paths: Path) -> list[str]:
    return [_sha(path) for path in paths if path.exists()]


def test_activation_process_death_is_unambiguous_and_retryable(tmp_path, monkeypatch):
    boundary = "activate-config"
    result, candidate, checkpoint = _legacy_install(tmp_path)
    original_config = result.config.read_bytes()
    original_sha = _sha(result.soul_db)
    candidate_sha = _sha(candidate)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)

    def die_after_replace(observed):
        if observed == boundary:
            raise _SimulatedProcessDeath(boundary)

    monkeypatch.setattr(
        "soul_platform.embedding_cutover._after_durable_replace",
        die_after_replace,
    )
    with pytest.raises(_SimulatedProcessDeath, match=boundary):
        activate(result.config, checkpoint)

    interrupted = json.loads(checkpoint.read_text())
    activation = interrupted["activation"]
    assert activation["status"] == "activating"
    source_backup = Path(activation["source_backup"])
    config_backup = Path(activation["config_backup"])
    assert _sha(result.soul_db) == original_sha
    assert _sha(source_backup) == original_sha
    assert _sha(candidate) == candidate_sha
    assert _sha(config_backup) == hashlib.sha256(original_config).hexdigest()
    assert _sha(result.config) in {
        hashlib.sha256(original_config).hexdigest(),
        activation["target_config_sha256"],
    }

    monkeypatch.setattr(
        "soul_platform.embedding_cutover._after_durable_replace", lambda _name: None
    )
    recovered = activate(result.config, checkpoint)
    assert recovered["activation"]["status"] == "active"
    assert _sha(result.soul_db) == original_sha
    assert _sha(candidate) == candidate_sha
    assert ProxySettings.from_toml(result.config).soul_db == candidate.resolve()
    assert activate(result.config, checkpoint) == recovered


def test_rollback_process_death_is_unambiguous_and_retryable(tmp_path, monkeypatch):
    boundary = "rollback-config"
    result, candidate, checkpoint = _legacy_install(tmp_path)
    original_config = result.config.read_bytes()
    original_sha = _sha(result.soul_db)
    candidate_sha = _sha(candidate)
    _checkpoint(result.soul_db, candidate, checkpoint)
    monkeypatch.setattr("soul_platform.embedding_cutover._probe_bge", lambda: None)
    active = activate(result.config, checkpoint)

    def die_after_replace(observed):
        if observed == boundary:
            raise _SimulatedProcessDeath(boundary)

    monkeypatch.setattr(
        "soul_platform.embedding_cutover._after_durable_replace",
        die_after_replace,
    )
    with pytest.raises(_SimulatedProcessDeath, match=boundary):
        rollback(result.config, checkpoint)

    interrupted = json.loads(checkpoint.read_text())
    activation = interrupted["activation"]
    assert activation["status"] == "rolling-back"
    source_backup = Path(activation["source_backup"])
    retained = Path(activation["retained_candidate"])
    assert _sha(result.soul_db) == original_sha
    assert _sha(source_backup) == original_sha
    assert _sha(retained) == candidate_sha
    assert _sha(result.config) in {
        active["activation"]["previous_config_sha256"],
        active["activation"]["target_config_sha256"],
    }

    monkeypatch.setattr(
        "soul_platform.embedding_cutover._after_durable_replace", lambda _name: None
    )
    restored = rollback(result.config, checkpoint)
    assert restored["activation"]["status"] == "rolled-back"
    assert _sha(result.soul_db) == original_sha
    assert result.config.read_bytes() == original_config
    assert _sha(Path(restored["activation"]["retained_candidate"])) == candidate_sha
    assert rollback(result.config, checkpoint) == restored


def test_durable_replace_fsyncs_bytes_and_directory(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_bytes(b"durable")
    events = []
    real_fsync_file = cutover._fsync_file
    real_fsync_directory = cutover._fsync_directory

    def record_file(path):
        events.append(("file", Path(path)))
        real_fsync_file(path)

    def record_directory(path):
        events.append(("directory", Path(path)))
        real_fsync_directory(path)

    monkeypatch.setattr(cutover, "_fsync_file", record_file)
    monkeypatch.setattr(cutover, "_fsync_directory", record_directory)
    cutover._durable_replace(source, target)

    assert target.read_bytes() == b"durable"
    assert events == [
        ("file", source),
        ("file", target),
        ("directory", tmp_path),
    ]


async def test_prepare_delegates_exact_128_to_1024_contract(tmp_path, monkeypatch):
    captured = {}

    class Provider:
        dimensions = 1024

    async def fake_migrate(source, provider, **kwargs):
        captured.update(source=source, provider=provider, **kwargs)
        return {"status": "completed"}

    monkeypatch.setattr(
        "soul_platform.embedding_cutover.LocalBgeM3Embedding", lambda **_kwargs: Provider()
    )
    monkeypatch.setattr(
        "soul_platform.embedding_cutover.migrate_sqlite_embeddings", fake_migrate
    )
    source = tmp_path / "source.db"
    source.touch()
    candidate = tmp_path / "candidate.db"
    checkpoint = tmp_path / "checkpoint.json"
    result = await prepare(
        source,
        candidate=candidate,
        checkpoint=checkpoint,
        batch_size=512,
        resume=True,
    )
    assert result == {"status": "completed"}
    assert captured["source_dimensions"] == 128
    assert captured["target_dimensions"] == 1024
    assert captured["batch_size"] == 512
    assert captured["resume"] is True
    assert captured["provider_name"] == "bge-m3:bge-m3"


def test_verify_rejects_non_completed_checkpoint(tmp_path):
    source, candidate, checkpoint = (
        tmp_path / "source.db",
        tmp_path / "candidate.db",
        tmp_path / "checkpoint.json",
    )
    _db(source, "source")
    _db(candidate, "candidate")
    state = _checkpoint(source, candidate, checkpoint)
    state["status"] = "paused"
    checkpoint.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="not completed"):
        verify_candidate(checkpoint)
