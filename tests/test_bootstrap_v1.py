from __future__ import annotations

from pathlib import Path
import os
import hashlib
import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from soul_framework.identity.dni import canonical_credential_bytes, canonical_trust_store_bytes
from soul_platform.bootstrap import enroll_dni, initialize, renew_dni, switch_upstream
from soul_platform.proxy import ProxySettings


def _signed_generation(result, private, root: Path, sequence: int):
    credential = json.loads((result.root / "soul-dni.json").read_text(encoding="utf-8"))
    trust = json.loads((result.root / "soul-dni-trust.json").read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for document in (credential, trust):
        document["sequence"] = sequence
        document["issued_at"] = (now - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        document["expires_at"] = (now + timedelta(days=1)).isoformat().replace(
            "+00:00", "Z"
        )
    credential["trust_sequence"] = sequence
    trust["signature"] = base64.b64encode(
        private.sign(canonical_trust_store_bytes(trust))
    ).decode("ascii")
    credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(credential))
    ).decode("ascii")
    root.mkdir()
    credential_path, trust_path = root / "credential.json", root / "trust.json"
    credential_path.write_text(json.dumps(credential, sort_keys=True), encoding="utf-8")
    trust_path.write_text(json.dumps(trust, sort_keys=True), encoding="utf-8")
    credential_path.chmod(0o600)
    trust_path.chmod(0o600)
    return credential_path, trust_path, hashlib.sha256(trust_path.read_bytes()).hexdigest()


def test_init_refuses_to_create_core_or_platform_without_soul_issued_dni(
    tmp_path, monkeypatch
):
    for key in (
        "SOUL_DNI_CREDENTIAL",
        "SOUL_DNI_TRUST_STORE",
        "SOUL_DNI_TRUST_STORE_SHA256",
    ):
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "no-dni"
    with pytest.raises(PermissionError, match="Identity Authority"):
        initialize(
            root=root,
            upstream_kind="ollama",
            upstream_base_url="http://127.0.0.1:11434/v1",
            upstream_model="brain",
            enable_autostart=False,
        )
    assert not (root / "proxy.toml").exists()
    assert not (root / "MachineSoul.db").exists()


def test_tampered_or_copied_dni_blocks_platform_before_database_open(tmp_path):
    root = tmp_path / "tampered"
    credential = Path(os.environ["SOUL_DNI_CREDENTIAL"])
    trust = Path(os.environ["SOUL_DNI_TRUST_STORE"])
    forged = tmp_path / "forged.json"
    forged.write_bytes(credential.read_bytes().replace(b'"active"', b'"revoked"'))
    forged.chmod(0o600)
    with pytest.raises(ValueError, match="signature|lifecycle"):
        initialize(
            root=root,
            upstream_kind="ollama",
            upstream_base_url="http://127.0.0.1:11434/v1",
            upstream_model="brain",
            enable_autostart=False,
            dni_credential=forged,
            dni_trust_store=trust,
            dni_trust_store_sha256=os.environ["SOUL_DNI_TRUST_STORE_SHA256"],
        )
    assert not (root / "MachineSoul.db").exists()


def test_initialize_installs_exact_dni_bytes_verified_before_source_swap(
    tmp_path, _soul_dni_test_authority, monkeypatch
):
    from soul_platform import bootstrap

    source_credential = Path(os.environ["SOUL_DNI_CREDENTIAL"])
    source_trust = Path(os.environ["SOUL_DNI_TRUST_STORE"])
    credential = json.loads(source_credential.read_text())
    trust = json.loads(source_trust.read_text())
    old_credential = source_credential.read_bytes()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for document in (credential, trust):
        document["sequence"] = 2
        document["issued_at"] = (now - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        document["expires_at"] = (now + timedelta(days=1)).isoformat().replace(
            "+00:00", "Z"
        )
    credential["trust_sequence"] = 2
    private = _soul_dni_test_authority["private"]
    trust["signature"] = base64.b64encode(
        private.sign(canonical_trust_store_bytes(trust))
    ).decode("ascii")
    credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(credential))
    ).decode("ascii")
    incoming = tmp_path / "init-source"
    incoming.mkdir()
    incoming_credential, incoming_trust = incoming / "credential.json", incoming / "trust.json"
    incoming_credential.write_text(json.dumps(credential, sort_keys=True))
    incoming_trust.write_text(json.dumps(trust, sort_keys=True))
    incoming_credential.chmod(0o600)
    incoming_trust.chmod(0o600)
    expected_bytes = incoming_credential.read_bytes()
    digest = hashlib.sha256(incoming_trust.read_bytes()).hexdigest()
    real_verify = bootstrap.verify_soul_dni

    def swap_after_verify(credential_path, trust_path, **kwargs):
        verified = real_verify(credential_path, trust_path, **kwargs)
        if Path(credential_path) == incoming_credential:
            incoming_credential.write_bytes(old_credential)
        return verified

    monkeypatch.setattr(bootstrap, "verify_soul_dni", swap_after_verify)
    result = initialize(
        root=tmp_path / "initialized",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
        dni_credential=incoming_credential,
        dni_trust_store=incoming_trust,
        dni_trust_store_sha256=digest,
    )
    assert (result.root / "soul-dni.json").read_bytes() == expected_bytes
    assert json.loads((result.root / "soul-dni.json").read_text())["sequence"] == 2


def test_legacy_install_enrolls_dni_without_touching_existing_soul(tmp_path):
    root = tmp_path / "legacy"
    result = initialize(
        root=root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    with sqlite3.connect(result.soul_db) as connection:
        before_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("identity", "rules", "memories")
        }
        connection.execute("DROP TABLE soul_identity_binding")
    legacy_lines = [
        line
        for line in result.config.read_text(encoding="utf-8").splitlines()
        if not line.startswith("dni")
    ]
    legacy_text = "\n".join(legacy_lines) + "\n"
    result.config.write_text(legacy_text, encoding="utf-8")
    result.config.chmod(0o600)
    (root / "soul-dni.json").unlink()
    (root / "soul-dni-trust.json").unlink()

    settings = enroll_dni(
        result.config,
        dni_credential=Path(os.environ["SOUL_DNI_CREDENTIAL"]),
        dni_trust_store=Path(os.environ["SOUL_DNI_TRUST_STORE"]),
        dni_trust_store_sha256=os.environ["SOUL_DNI_TRUST_STORE_SHA256"],
    )
    assert settings.machine_soul_id == result.machine_soul_id
    with sqlite3.connect(result.soul_db) as connection:
        after_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before_counts
        }
        binding = connection.execute(
            "SELECT soul_dni, machine_soul_id FROM soul_identity_binding"
        ).fetchone()
    assert after_counts == before_counts
    assert binding == (settings.soul_dni, result.machine_soul_id)
    backups = list(root.glob("proxy.toml.pre-dni-*.bak"))
    assert len(backups) == 1 and backups[0].read_text(encoding="utf-8") == legacy_text


def test_legacy_enrollment_installs_exact_verified_bytes_if_source_is_swapped(
    tmp_path, _soul_dni_test_authority, monkeypatch
):
    from soul_platform import bootstrap

    root = tmp_path / "legacy-swap"
    result = initialize(
        root=root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    with sqlite3.connect(result.soul_db) as connection:
        connection.execute("DROP TABLE soul_identity_binding")
    legacy_text = "\n".join(
        line
        for line in result.config.read_text(encoding="utf-8").splitlines()
        if not line.startswith("dni")
    ) + "\n"
    result.config.write_text(legacy_text, encoding="utf-8")
    (root / "soul-dni.json").unlink()
    (root / "soul-dni-trust.json").unlink()
    source_credential = Path(os.environ["SOUL_DNI_CREDENTIAL"])
    source_trust = Path(os.environ["SOUL_DNI_TRUST_STORE"])
    expected_bytes = source_credential.read_bytes()
    real_verify = bootstrap.verify_soul_dni

    def swap_after_verify(credential_path, trust_path, **kwargs):
        verified = real_verify(credential_path, trust_path, **kwargs)
        Path(credential_path).write_text('{"schema":"swapped-after-verify"}')
        return verified

    incoming_credential = tmp_path / "legacy-incoming-credential.json"
    incoming_trust = tmp_path / "legacy-incoming-trust.json"
    incoming_credential.write_bytes(expected_bytes)
    incoming_trust.write_bytes(source_trust.read_bytes())
    incoming_credential.chmod(0o600)
    incoming_trust.chmod(0o600)
    monkeypatch.setattr(bootstrap, "verify_soul_dni", swap_after_verify)
    settings = enroll_dni(
        result.config,
        dni_credential=incoming_credential,
        dni_trust_store=incoming_trust,
        dni_trust_store_sha256=hashlib.sha256(incoming_trust.read_bytes()).hexdigest(),
    )
    assert settings.soul_dni == os.environ["SOUL_DNI_VALUE"]
    assert (root / "soul-dni.json").read_bytes() == expected_bytes


def test_legacy_enrollment_rerun_repairs_config_promoted_before_db_binding(tmp_path):
    result = initialize(
        root=tmp_path / "legacy-crash-recovery",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    with sqlite3.connect(result.soul_db) as connection:
        connection.execute("DROP TABLE soul_identity_binding")
    settings = enroll_dni(
        result.config,
        dni_credential=Path(os.environ["SOUL_DNI_CREDENTIAL"]),
        dni_trust_store=Path(os.environ["SOUL_DNI_TRUST_STORE"]),
        dni_trust_store_sha256=os.environ["SOUL_DNI_TRUST_STORE_SHA256"],
    )
    with sqlite3.connect(result.soul_db) as connection:
        binding = connection.execute(
            "SELECT soul_dni, machine_soul_id FROM soul_identity_binding"
        ).fetchone()
    assert binding == (settings.soul_dni, settings.machine_soul_id)


def test_dni_renewal_preserves_soul_and_requires_monotonic_sequence(
    tmp_path, _soul_dni_test_authority
):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    before_db = hashlib.sha256(result.soul_db.read_bytes()).hexdigest()
    private = _soul_dni_test_authority["private"]
    credential = json.loads((result.root / "soul-dni.json").read_text(encoding="utf-8"))
    trust = json.loads((result.root / "soul-dni-trust.json").read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for document in (credential, trust):
        document["sequence"] = 2
        document["issued_at"] = (now - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        document["expires_at"] = (now + timedelta(days=30) - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
    credential["trust_sequence"] = 2
    trust["signature"] = base64.b64encode(
        private.sign(canonical_trust_store_bytes(trust))
    ).decode("ascii")
    credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(credential))
    ).decode("ascii")
    incoming = tmp_path / "renewal"
    incoming.mkdir()
    new_credential = incoming / "soul-dni.json"
    new_trust = incoming / "soul-dni-trust.json"
    new_credential.write_text(json.dumps(credential, sort_keys=True), encoding="utf-8")
    new_trust.write_text(json.dumps(trust, sort_keys=True), encoding="utf-8")
    new_credential.chmod(0o600)
    new_trust.chmod(0o600)
    digest = hashlib.sha256(new_trust.read_bytes()).hexdigest()
    renewed = renew_dni(
        result.config,
        dni_credential=new_credential,
        dni_trust_store=new_trust,
        dni_trust_store_sha256=digest,
    )
    assert renewed.soul_dni == credential["soul_dni"]
    assert renewed.machine_soul_id == result.machine_soul_id
    assert hashlib.sha256(result.soul_db.read_bytes()).hexdigest() == before_db
    with pytest.raises(PermissionError, match="sequence must increase"):
        renew_dni(
            result.config,
            dni_credential=new_credential,
            dni_trust_store=new_trust,
            dni_trust_store_sha256=digest,
        )


def test_dni_renewal_rolls_back_public_files_if_config_promotion_fails(
    tmp_path, _soul_dni_test_authority, monkeypatch
):
    from soul_platform import bootstrap

    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    originals = {
        path: path.read_bytes()
        for path in (
            result.config,
            result.root / "soul-dni.json",
            result.root / "soul-dni-trust.json",
            result.soul_db,
        )
    }
    private = _soul_dni_test_authority["private"]
    credential = json.loads((result.root / "soul-dni.json").read_text())
    trust = json.loads((result.root / "soul-dni-trust.json").read_text())
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for document in (credential, trust):
        document["sequence"] = 2
        document["issued_at"] = (now - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        document["expires_at"] = (now + timedelta(days=1)).isoformat().replace(
            "+00:00", "Z"
        )
    credential["trust_sequence"] = 2
    trust["signature"] = base64.b64encode(
        private.sign(canonical_trust_store_bytes(trust))
    ).decode("ascii")
    credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(credential))
    ).decode("ascii")
    incoming = tmp_path / "renewal-failure"
    incoming.mkdir()
    new_credential, new_trust = incoming / "soul-dni.json", incoming / "trust.json"
    new_credential.write_text(json.dumps(credential, sort_keys=True))
    new_trust.write_text(json.dumps(trust, sort_keys=True))
    new_credential.chmod(0o600)
    new_trust.chmod(0o600)
    digest = hashlib.sha256(new_trust.read_bytes()).hexdigest()

    real_atomic = bootstrap._atomic_config
    calls = 0

    def fail_config_promotion(path, text):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("injected config promotion failure")
        return real_atomic(path, text)

    monkeypatch.setattr(bootstrap, "_atomic_config", fail_config_promotion)
    with pytest.raises(OSError, match="injected config promotion failure"):
        renew_dni(
            result.config,
            dni_credential=new_credential,
            dni_trust_store=new_trust,
            dni_trust_store_sha256=digest,
        )
    for path, original in originals.items():
        assert path.read_bytes() == original


def test_dni_renewal_publishes_the_exact_verified_bytes_if_source_is_swapped(
    tmp_path, _soul_dni_test_authority, monkeypatch
):
    from soul_platform import bootstrap

    result = initialize(
        root=tmp_path / "soul-swap",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    old_credential = (result.root / "soul-dni.json").read_bytes()
    incoming_credential, incoming_trust, digest = _signed_generation(
        result, _soul_dni_test_authority["private"], tmp_path / "incoming-swap", 2
    )
    verified_credential = incoming_credential.read_bytes()
    real_verify = bootstrap.verify_soul_dni

    def swap_after_verify(credential_path, trust_path, **kwargs):
        verified = real_verify(credential_path, trust_path, **kwargs)
        if Path(credential_path) == incoming_credential:
            incoming_credential.write_bytes(old_credential)
        return verified

    monkeypatch.setattr(bootstrap, "verify_soul_dni", swap_after_verify)
    renew_dni(
        result.config,
        dni_credential=incoming_credential,
        dni_trust_store=incoming_trust,
        dni_trust_store_sha256=digest,
    )
    assert (result.root / "soul-dni.json").read_bytes() == verified_credential
    assert json.loads((result.root / "soul-dni.json").read_text())["sequence"] == 2


def test_dni_renewal_rejects_tampered_current_sequence_before_rollback(
    tmp_path, _soul_dni_test_authority
):
    result = initialize(
        root=tmp_path / "soul-current-tamper",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    original_credential = tmp_path / "archived-generation-1.json"
    original_trust = tmp_path / "archived-trust-1.json"
    original_credential.write_bytes((result.root / "soul-dni.json").read_bytes())
    original_trust.write_bytes((result.root / "soul-dni-trust.json").read_bytes())
    original_credential.chmod(0o600)
    original_trust.chmod(0o600)
    original_digest = hashlib.sha256(original_trust.read_bytes()).hexdigest()
    current = json.loads((result.root / "soul-dni.json").read_text())
    current["sequence"] = 0
    (result.root / "soul-dni.json").write_text(json.dumps(current, sort_keys=True))

    with pytest.raises(ValueError, match="signature|sequence"):
        renew_dni(
            result.config,
            dni_credential=original_credential,
            dni_trust_store=original_trust,
            dni_trust_store_sha256=original_digest,
        )
    assert json.loads((result.root / "soul-dni.json").read_text())["sequence"] == 0


def test_concurrent_dni_renewals_finish_at_the_highest_generation(
    tmp_path, _soul_dni_test_authority
):
    result = initialize(
        root=tmp_path / "soul-concurrent",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    generation_2 = _signed_generation(
        result, _soul_dni_test_authority["private"], tmp_path / "generation-2", 2
    )
    generation_3 = _signed_generation(
        result, _soul_dni_test_authority["private"], tmp_path / "generation-3", 3
    )

    def promote(generation):
        try:
            renew_dni(
                result.config,
                dni_credential=generation[0],
                dni_trust_store=generation[1],
                dni_trust_store_sha256=generation[2],
            )
            return "accepted"
        except PermissionError:
            return "stale-rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(promote, (generation_2, generation_3)))
    assert "accepted" in outcomes
    assert json.loads((result.root / "soul-dni.json").read_text())["sequence"] == 3
    assert json.loads((result.root / "soul-dni-trust.json").read_text())["sequence"] == 3


def test_dni_renewal_rejects_signed_revocation_snapshot_rollback(
    tmp_path, _soul_dni_test_authority
):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    private = _soul_dni_test_authority["private"]
    credential_path = result.root / "soul-dni.json"
    trust_path = result.root / "soul-dni-trust.json"
    credential = json.loads(credential_path.read_text())
    old_trust_text = trust_path.read_text()
    old_trust = json.loads(old_trust_text)
    old_digest = hashlib.sha256(trust_path.read_bytes()).hexdigest()

    revoked_trust = dict(old_trust)
    revoked_trust["sequence"] = 2
    revoked_trust["revoked_soul_dnis"] = [credential["soul_dni"]]
    revoked_trust["signature"] = base64.b64encode(
        private.sign(canonical_trust_store_bytes(revoked_trust))
    ).decode("ascii")
    trust_path.write_text(json.dumps(revoked_trust, sort_keys=True))
    new_digest = hashlib.sha256(trust_path.read_bytes()).hexdigest()
    result.config.write_text(
        result.config.read_text().replace(old_digest, new_digest), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="revoked"):
        ProxySettings.from_toml(result.config)

    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    replay_trust = replay_dir / "trust.json"
    replay_trust.write_text(old_trust_text)
    replay_trust.chmod(0o600)
    replay_credential = dict(credential)
    replay_credential["sequence"] = 2
    replay_credential["trust_sequence"] = 1
    replay_credential["signature"] = base64.b64encode(
        private.sign(canonical_credential_bytes(replay_credential))
    ).decode("ascii")
    replay_credential_path = replay_dir / "credential.json"
    replay_credential_path.write_text(json.dumps(replay_credential, sort_keys=True))
    replay_credential_path.chmod(0o600)
    replay_digest = hashlib.sha256(replay_trust.read_bytes()).hexdigest()

    # Normal renewal never revives a currently revoked identity.  Recovery
    # requires the separate owner/SIA recovery ceremony.
    with pytest.raises(ValueError, match="revoked"):
        renew_dni(
            result.config,
            dni_credential=replay_credential_path,
            dni_trust_store=replay_trust,
            dni_trust_store_sha256=replay_digest,
        )
    assert json.loads(trust_path.read_text())["sequence"] == 2
    assert json.loads(trust_path.read_text())["revoked_soul_dnis"] == [
        credential["soul_dni"]
    ]


def test_init_is_user_space_idempotent_and_preserves_identity(tmp_path):
    root, home = tmp_path / "SOUL Root", tmp_path / "home"
    first = initialize(
        root=root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="gemma-test",
        python=str(Path(__import__("sys").executable)),
        platform="linux",
        home=home,
        activate_autostart=False,
    )
    token_before = first.token_file.read_bytes()
    second = initialize(
        root=root,
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="ignored-on-idempotent-init",
        python=str(Path(__import__("sys").executable)),
        platform="linux",
        home=home,
        activate_autostart=False,
    )
    assert first.created is True and second.created is False
    assert first.machine_soul_id == second.machine_soul_id
    assert second.token_file.read_bytes() == token_before
    assert first.autostart == second.autostart
    settings = ProxySettings.from_toml(first.config)
    assert settings.embedding_provider == "bge-m3"
    assert settings.embedding_dimensions == 1024
    assert settings.memory_vector_index == "auto"
    assert settings.t5_mode == "compatibility-single-owner"
    assert settings.t5_tenant == "local-machine"
    assert settings.t5_owner_subject == f"local-owner:{settings.machine_soul_id}"
    assert settings.t5_state_path == root / "MachineSoul.t5-egress.sqlite3"


def test_legacy_config_has_only_safe_128d_exact_compatibility(tmp_path):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    text = result.config.read_text()
    start, end = text.index("[embedding]"), text.index("[proxy]")
    result.config.write_text(text[:start] + text[end:])
    settings = ProxySettings.from_toml(result.config)
    assert (
        settings.embedding_provider,
        settings.embedding_dimensions,
        settings.memory_vector_index,
    ) == ("simple", 128, "exact")


def test_config_without_memory_egress_section_fails_closed_in_locked_mode(tmp_path):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="brain",
        enable_autostart=False,
    )
    text = result.config.read_text()
    start, end = text.index("[memory_egress]"), text.index("[upstream]")
    result.config.write_text(text[:start] + text[end:])
    settings = ProxySettings.from_toml(result.config)
    assert settings.t5_mode == "locked"
    assert settings.t5_tenant == ""
    assert settings.t5_owner_subject == ""


def test_switch_changes_only_brain(tmp_path):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="gemma-test",
        enable_autostart=False,
    )
    before = ProxySettings.from_toml(result.config)
    after = switch_upstream(
        result.config,
        upstream_kind="lmstudio",
        upstream_base_url="http://127.0.0.1:1234/v1",
        upstream_model="qwen-test",
    )
    assert after.upstream_model != before.upstream_model
    assert after.machine_soul_id == before.machine_soul_id
    assert after.baseline_hash == before.baseline_hash
    assert after.soul_db == before.soul_db
    assert after.token_file == before.token_file


def test_partial_or_symlinked_install_fails_closed(tmp_path):
    root = tmp_path / "soul"
    root.mkdir()
    (root / "proxy.token").write_text("orphan")
    with pytest.raises(ValueError, match="partial"):
        initialize(
            root=root,
            upstream_kind="ollama",
            upstream_base_url="http://127.0.0.1:11434/v1",
            upstream_model="gemma-test",
            enable_autostart=False,
        )
    target, link = tmp_path / "real", tmp_path / "link"
    target.mkdir()
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked"):
        initialize(
            root=link,
            upstream_kind="ollama",
            upstream_base_url="http://127.0.0.1:11434/v1",
            upstream_model="gemma-test",
            enable_autostart=False,
        )


def test_remote_upstream_and_public_bind_remain_rejected(tmp_path):
    with pytest.raises(ValueError, match="disabled"):
        initialize(
            root=tmp_path / "soul",
            upstream_kind="remote",
            upstream_base_url="https://example.com/v1",
            upstream_model="remote-model",
            enable_autostart=False,
        )
    assert not (tmp_path / "soul" / "proxy.token").exists()


def test_switch_rolls_back_config_when_managed_restart_fails(tmp_path, monkeypatch):
    result = initialize(
        root=tmp_path / "soul",
        upstream_kind="ollama",
        upstream_base_url="http://127.0.0.1:11434/v1",
        upstream_model="old-model",
        enable_autostart=False,
    )
    before = result.config.read_text()
    monkeypatch.setattr(
        "soul_platform.bootstrap.restart_descriptor",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("restart failed")),
    )
    with pytest.raises(RuntimeError, match="restart failed"):
        switch_upstream(
            result.config,
            upstream_kind="ollama",
            upstream_base_url="http://127.0.0.1:11434/v1",
            upstream_model="new-model",
            restart=True,
            platform="linux",
            home=tmp_path / "home",
        )
    assert result.config.read_text() == before
