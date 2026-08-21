"""Hermetic tests for the real-model lab boundary (no provider calls)."""

from __future__ import annotations

import importlib.util
import hmac
import json
import socket
import sys
import threading
from pathlib import Path
from types import ModuleType

import pytest


LAB = Path(__file__).resolve().parent


def _load(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, LAB / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


container_probe = _load("soul_real_models_container_probe", "container_probe.py")
host_broker = _load("soul_real_models_host_broker", "host_broker.py")
run_lab = _load("soul_real_models_run_lab", "run_lab.py")

REQUIRED_RECEIPT_SUBJECTS = frozenset(
    {
        "soul-platform/labs/real_models/README.md",
        "soul-platform/labs/real_models/container_probe.py",
        "soul-platform/labs/real_models/evidence/real-run-20260821.json",
        "soul-platform/labs/real_models/host_broker.py",
        "soul-platform/labs/real_models/run_lab.py",
        "soul-platform/labs/real_models/test_real_models_lab.py",
    }
)
EXPECTED_OUTPUT_SHA256 = {
    "codex": "86580b60de1cfbd99bec3ac912c0e9c5bbec931ff73b834aa333afd65772f0ec",
    "claude": "c03e19a1d99e1cddd808aa3c570b851a3d88dae473dddbe4305c471589278731",
    "gemma": "5f89c768cc2e486a754b35cc82fa430520fc42ddbdfa5ab022cfb1c7579bcfb3",
}


def _load_gstack() -> ModuleType:
    root = LAB.parents[2]
    path = root / ".agents" / "skills" / "soul-gstack" / "scripts" / "soul_gstack.py"
    spec = importlib.util.spec_from_file_location("soul_real_models_gstack", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_model_answer_parser_accepts_wrapped_json_but_requires_all_fields() -> None:
    expected = {
        "soul_id": container_probe.SOUL_ID,
        "identity_name": container_probe.IDENTITY_NAME,
        "memory_anchor": container_probe.MEMORY_ANCHOR,
    }
    wire = {
        "id": container_probe.SOUL_ID,
        "name": container_probe.IDENTITY_NAME,
        "note": container_probe.MEMORY_ANCHOR,
    }
    assert container_probe.parse_model_answer("```json\n" + json.dumps(wire) + "\n```") == expected
    with pytest.raises((KeyError, json.JSONDecodeError, AssertionError)):
        container_probe.parse_model_answer('{"id":"only"}')


def test_prompt_contains_exact_record_and_no_provider_secret() -> None:
    record = {
        "soul_id": container_probe.SOUL_ID,
        "identity_name": container_probe.IDENTITY_NAME,
        "memory_anchor": container_probe.MEMORY_ANCHOR,
    }
    rendered = container_probe.prompt(record)
    assert all(value in rendered for value in record.values())
    assert "ANTHROPIC_API_KEY" not in rendered
    assert "OPENAI_API_KEY" not in rendered


def test_recorded_real_delivery_evidence_is_byte_bound() -> None:
    evidence = json.loads((LAB / "evidence" / "real-run-20260821.json").read_text(encoding="utf-8"))
    assert evidence["status"] == "PASS"
    assert evidence["phase1"]["negative_auth"] == {"missing": 401, "wrong": 401}
    assert all(row["network_mode"] == "none" for row in evidence["container_security"])
    assert evidence["provider_credentials_inside_containers"] == 0
    assert [row["provider"] for row in evidence["phase1"]["results"]] == ["codex", "claude", "gemma"]
    for name, expected in evidence["lab_file_sha256"].items():
        assert host_broker.hashlib.sha256((LAB / name).read_bytes()).hexdigest() == expected


def _verify_signed_real_execution_receipt(receipt_path: Path, root: Path) -> dict[str, object]:
    """Verify local integrity without coupling validity to a later Git commit.

    The upstream SOUL-GStack verifier intentionally binds receipts to HEAD and
    git-status.  That is useful before commit but makes the receipt stale as an
    unavoidable consequence of committing the exact tested bytes.  This
    delivery check retains the local HMAC, command, output and exact subject-byte
    binding; only mutable repository bookkeeping is excluded.  The HMAC key is
    held by the shared host UID, so this is tamper detection, not independent
    signer identity or remote attestation.
    """

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    gstack = _load_gstack()

    assert receipt["schema"] == "seal.soul-gstack.execution-receipt.v1"
    assert receipt["actor_assurance"] == "local_environment_claim_not_cryptographic_identity"
    assert receipt["claim_scope"] == "execution_observed_not_semantic_closure"
    expected_signature = gstack._signed_payload(
        receipt,
        gstack._secret(gstack._default_state_root(), "ADA"),
    )["signature"]
    assert hmac.compare_digest(receipt["signature"], expected_signature)
    assert receipt["expected_exit_code"] == receipt["observed_exit_code"] == 0
    assert receipt["argv"] == [
        "python3",
        "soul-platform/labs/real_models/run_lab.py",
        "--receipt",
        "/tmp/soul-real-models-live-final2.json",
    ]
    assert set(receipt["before"]["file_sha256"]) == REQUIRED_RECEIPT_SUBJECTS
    assert set(receipt["after"]["file_sha256"]) == REQUIRED_RECEIPT_SUBJECTS
    assert receipt["before"]["file_sha256"] == receipt["after"]["file_sha256"]
    for relative, expected_hash in receipt["after"]["file_sha256"].items():
        assert host_broker.hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected_hash

    observed = json.loads(receipt["stdout"])
    assert observed["status"] == "PASS"
    calls = observed["broker"]["calls"]
    assert observed["broker"]["count"] == len(calls) == 4
    assert [row["provider"] for row in calls] == [
        "codex",
        "claude",
        "gemma",
        "gemma",
    ]
    assert [row["model"] for row in calls] == [
        "gpt-5.6-sol",
        "claude-opus",
        "gemma3:1b-it-qat",
        "gemma3:1b-it-qat",
    ]
    assert all(row["output_sha256"] == EXPECTED_OUTPUT_SHA256[row["provider"]] for row in calls)
    assert observed["phase1"]["negative_auth"] == {"missing": 401, "wrong": 401}
    results = observed["phase1"]["results"]
    assert len(results) == 3
    assert [row["provider"] for row in results] == ["codex", "claude", "gemma"]
    assert [row["model"] for row in results] == [
        "gpt-5.6-sol",
        "claude-opus",
        "gemma3:1b-it-qat",
    ]
    assert [row["generation"] for row in results] == [1, 2, 3]
    assert all(row["continuity"] is True for row in results)
    assert all(row["answer_sha256"] == EXPECTED_OUTPUT_SHA256[row["provider"]] for row in results)
    assert observed["phase2"]["status"] == "PASS"
    assert observed["phase2"]["providers"] == ["codex", "claude", "gemma", "gemma"]
    assert observed["phase2"]["persisted_switches_before"] == 3
    assert observed["phase2"]["persisted_switches_after"] == 4
    recall = observed["phase2"]["recall_after_restart"]
    assert recall["provider"] == "gemma"
    assert recall["model"] == "gemma3:1b-it-qat"
    assert recall["generation"] == 4
    assert recall["continuity"] is True
    assert recall["answer_sha256"] == EXPECTED_OUTPUT_SHA256["gemma"]
    security = observed["container_security"]
    assert len(security) == 2
    for row in security:
        assert row["network_mode"] == "none"
        assert row["readonly_rootfs"] is True
        assert row["cap_drop"] == ["ALL"]
        assert row["no_new_privileges"] is True
        assert row["broker_mount_readonly"] is True
        assert row["lab_mount_readonly"] is True
        assert row["state_mount_writable"] is True
        assert row["provider_credentials_in_env"] == []
    assert observed["provider_credentials_inside_containers"] == 0
    return observed


def test_signed_real_execution_receipt_is_authentic_and_byte_current() -> None:
    root = LAB.parents[2]
    receipt_path = root / "quality" / "receipts" / "soul-real-models-container-lab-20260821.json"
    _verify_signed_real_execution_receipt(receipt_path, root)


def test_signed_receipt_rejects_valid_hmac_with_omitted_subject_or_fabricated_output(
    tmp_path: Path,
) -> None:
    root = LAB.parents[2]
    source = root / "quality" / "receipts" / "soul-real-models-container-lab-20260821.json"
    original = json.loads(source.read_text(encoding="utf-8"))
    gstack = _load_gstack()
    secret = gstack._secret(gstack._default_state_root(), "ADA")

    omitted = json.loads(json.dumps(original))
    missing = "soul-platform/labs/real_models/host_broker.py"
    omitted["before"]["file_sha256"].pop(missing)
    omitted["after"]["file_sha256"].pop(missing)
    omitted = gstack._signed_payload(omitted, secret)
    omitted_path = tmp_path / "omitted.json"
    omitted_path.write_text(json.dumps(omitted), encoding="utf-8")
    with pytest.raises(AssertionError):
        _verify_signed_real_execution_receipt(omitted_path, root)

    fabricated = json.loads(json.dumps(original))
    stdout = json.loads(fabricated["stdout"])
    stdout["broker"]["calls"][0]["output_sha256"] = "0" * 64
    fabricated["stdout"] = json.dumps(stdout)
    fabricated = gstack._signed_payload(fabricated, secret)
    fabricated_path = tmp_path / "fabricated.json"
    fabricated_path.write_text(json.dumps(fabricated), encoding="utf-8")
    with pytest.raises(AssertionError):
        _verify_signed_real_execution_receipt(fabricated_path, root)

    vacuous = json.loads(json.dumps(original))
    stdout = json.loads(vacuous["stdout"])
    stdout["phase1"]["results"] = []
    stdout["container_security"] = []
    vacuous["stdout"] = json.dumps(stdout)
    vacuous = gstack._signed_payload(vacuous, secret)
    vacuous_path = tmp_path / "vacuous.json"
    vacuous_path.write_text(json.dumps(vacuous), encoding="utf-8")
    with pytest.raises(AssertionError):
        _verify_signed_real_execution_receipt(vacuous_path, root)


def test_broker_provider_allowlist_rejects_unknown_without_execution() -> None:
    with pytest.raises(host_broker.BrokerError, match="allowlisted"):
        host_broker.invoke("attacker", "hello")


def test_broker_rejects_before_body_and_slow_client_cannot_block_health(tmp_path: Path) -> None:
    socket_path = tmp_path / "broker.sock"
    host_broker.RUNTIME = host_broker.Runtime("A" * 48)
    server = host_broker.UnixServer(str(socket_path), host_broker.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        denied = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        denied.settimeout(1)
        denied.connect(str(socket_path))
        denied.sendall(
            b"POST /invoke HTTP/1.1\r\nHost: local\r\n"
            b"Content-Length: 100\r\nX-SOUL-Instance: soul-real-models-v1\r\n\r\n"
        )
        assert b" 401 " in denied.recv(256)
        denied.close()

        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.settimeout(1)
        slow.connect(str(socket_path))
        slow.sendall(
            b"POST /invoke HTTP/1.1\r\nHost: local\r\n"
            b"Authorization: Bearer " + b"A" * 48 + b"\r\n"
            b"X-SOUL-Instance: soul-real-models-v1\r\n"
            b"Content-Length: 100\r\n\r\n{"
        )
        connection = run_lab.UnixHTTPConnection(socket_path)
        connection.request("GET", "/health")
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["ok"] is True
        connection.close()
        slow.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_container_contract_is_network_none_readonly_and_non_root(tmp_path: Path) -> None:
    args = run_lab.container_args("probe", tmp_path, tmp_path, "phase1")
    joined = " ".join(args)
    assert "--network none" in joined
    assert "--read-only" in args
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges:true" in joined
    assert f"--user {run_lab.os.getuid()}:{run_lab.os.getgid()}" in joined
    assert "ANTHROPIC_API_KEY" not in joined
    assert "OPENAI_API_KEY" not in joined


def test_cleanup_is_forceful_verified_and_scoped_to_runner_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    class Result:
        def __init__(self, returncode: int) -> None:
            self.returncode = returncode

    def fake_run(command: list[str], **_kwargs: object) -> Result:
        seen.append(command)
        return Result(1 if command[1] == "inspect" else 0)

    monkeypatch.setattr(run_lab.subprocess, "run", fake_run)
    run_lab.remove_container("soul-real-models-123-phase1")
    assert seen == [
        ["docker", "rm", "--force", "soul-real-models-123-phase1"],
        ["docker", "inspect", "soul-real-models-123-phase1"],
    ]
    with pytest.raises(ValueError, match="unscoped"):
        run_lab.remove_container("unrelated-production-container")


def test_cleanup_continues_after_first_resource_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    removed: list[str] = []
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    def fake_remove(name: str) -> None:
        removed.append(name)
        if name.endswith("phase1"):
            raise RuntimeError("simulated verification failure")

    class Broker:
        terminated = False
        waited = False

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int) -> None:
            assert timeout == 5
            self.waited = True

    class Log:
        closed = False

        def close(self) -> None:
            self.closed = True

    broker, log = Broker(), Log()
    monkeypatch.setattr(run_lab, "remove_container", fake_remove)
    errors = run_lab.cleanup_resources(
        ["soul-real-models-123-phase1", "soul-real-models-123-phase2"],
        broker,
        log,
        runtime,
    )
    assert removed == ["soul-real-models-123-phase1", "soul-real-models-123-phase2"]
    assert broker.terminated and broker.waited
    assert log.closed and not runtime.exists()
    assert len(errors) == 1 and "phase1" in errors[0]


def test_provider_invocation_commands_avoid_shell_and_sessions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[list[str]] = []

    class Result:
        returncode = 0
        stdout = "CLAUDE"
        stderr = ""

    def fake_run(command: list[str], **_kwargs: object) -> Result:
        seen.append(command)
        output_flag = command.index("--output-last-message") if "--output-last-message" in command else -1
        if output_flag >= 0:
            Path(command[output_flag + 1]).write_text("CODEX", encoding="utf-8")
        return Result()

    monkeypatch.setattr(host_broker.subprocess, "run", fake_run)
    monkeypatch.setattr(host_broker.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert host_broker._run_codex("safe")[0] == "CODEX"
    assert host_broker._run_claude("safe") == ("CLAUDE", "claude-opus")
    assert seen[0][0] == "/usr/bin/codex" and "--ephemeral" in seen[0]
    assert seen[1][0] == "/usr/bin/claude" and "--no-session-persistence" in seen[1]
    assert seen[1][seen[1].index("--model") + 1] == "opus"
    assert all(isinstance(command, list) for command in seen)
