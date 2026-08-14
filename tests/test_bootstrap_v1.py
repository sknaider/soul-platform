from __future__ import annotations

from pathlib import Path

import pytest

from soul_platform.bootstrap import initialize, switch_upstream
from soul_platform.proxy import ProxySettings


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
