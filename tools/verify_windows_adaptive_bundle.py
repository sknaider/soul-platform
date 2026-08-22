from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path


REQUIRED = {
    "python_bootstrap": '"Python.Python.3.13"',
    "ollama_bootstrap": '"Ollama.Ollama"',
    "user_scope": '"--exact", "--source", "winget", "--scope", "user"',
    "bootstrap_opt_out": "[switch]$NoBootstrap",
    "python_skip": 'Skip "Python 3.13 x64 ya existe"',
    "ollama_skip": 'Skip "Ollama ya existe"',
    "bundle_byte_skip": "function Test-ExactBundledInstall(",
    "record_hash_check": "distribution.read_text('RECORD')",
    "dependency_repair": "Reparando solo dependencias ausentes o incompatibles",
    "embedding_model": 'pull", "bge-m3"',
    "bootstrap_brain": '"gemma3:1b"',
    "receipt": 'install-receipt.json',
    "mcp": "function Install-SoulClientMcp(",
    "session_start": "function Install-CodexSessionStartHook(",
    "identity_acl": "Set-SoulPrivateAcl $soulRoot",
    "free_space": "function Assert-MinimumFreeSpace",
    "bge_digest": "function Assert-BgeM3Digest",
    "wheelhouse_lock": 'Join-Path $PSScriptRoot "WHEELHOUSE.sha256"',
    "offline_pip": 'Good "Dependencias Python instaladas desde wheelhouse, sin PyPI"',
    "inventory": "function Get-SoulComponentInventory",
    "selective_plan": "function Get-SoulInstallPlan",
    "venv_python_reuse": '@{ Exe = (Join-Path $Venv "Scripts\\python.exe"); Args = @() }',
    "ps51_python_probe": "struct.calcsize(chr(80))*8",
    "atomic_rerun": "function Move-SoulAtomicFile",
    "claude_new_missing_shape": "function Test-SoulMcpMissingText",
    "additive_client_binding": "function Enroll-SoulParentBinding",
    "tray_real_check": 'Invoke-Checked $trayCli @("--headless-check")',
    "ps51_exact_bundle_probe": "direct.get('url')",
}

BANNED = {
    "elevation": re.compile(r"Start-Process\s+-Verb\s+RunAs", re.I),
    "unverified_download": re.compile(r"Invoke-WebRequest|\bcurl(?:\.exe)?\b", re.I),
    "hash_bypass": re.compile(r"--ignore-security-hash", re.I),
    "mass_delete": re.compile(r"Remove-Item\s+[^\r\n]*-Recurse|\brm\s+-rf\b", re.I),
    "private_key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "api_secret": re.compile(r"(?:sk-ant-|sk-proj-|gsk_)[A-Za-z0-9_-]{16,}"),
}


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def validate_installer(text: str) -> list[str]:
    failures = [name for name, token in REQUIRED.items() if token not in text]
    failures.extend(name for name, pattern in BANNED.items() if pattern.search(text))
    return sorted(failures)


def verify(bundle: Path) -> dict[str, object]:
    payload = bundle.read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        platform = [name for name in names if re.fullmatch(r"soul_platform-0\.6\.0-py3-none-any\.whl", name)]
        core = [name for name in names if re.fullmatch(r"soul_framework-0\.4\.3-py3-none-any\.whl", name)]
        if len(platform) != 1 or len(core) != 1:
            raise ValueError("bundle must contain exact Platform 0.6.0 and Core 0.4.3 wheels")
        for name in (*platform, *core):
            expected = archive.read(name + ".sha256").decode("ascii").split()[0].lower()
            if sha256(archive.read(name)) != expected:
                raise ValueError(f"checksum mismatch: {name}")
        installer = archive.read("Install-Soul.ps1").decode("utf-8")
        failures = validate_installer(installer)
        if failures:
            raise ValueError("adaptive installer gate failed: " + ", ".join(failures))

        # Non-vacuous control: every required arm must independently make the
        # gate red when removed from the exact release bytes.
        killed: list[str] = []
        for name, token in REQUIRED.items():
            mutant = installer.replace(token, f"__REMOVED_{name}__", 1)
            if name in validate_installer(mutant):
                killed.append(name)
        if sorted(killed) != sorted(REQUIRED):
            raise ValueError("non-vacuous mutation control did not kill every required arm")
    return {
        "schema": "soul.windows-adaptive-bundle.receipt.v1",
        "status": "verified",
        "bundle": str(bundle.resolve()),
        "bundle_sha256": sha256(payload),
        "required_arms": len(REQUIRED),
        "mutation_killed": len(killed),
        "banned_patterns": len(BANNED),
        "entries": names,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    result = verify(args.bundle)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
