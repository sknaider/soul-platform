from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_windows_adaptive_bundle",
    ROOT / "tools" / "verify_windows_adaptive_bundle.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_production_installer_satisfies_adaptive_contract():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text(encoding="utf-8")
    assert MODULE.validate_installer(text) == []


def test_adaptive_gate_is_non_vacuous_for_every_required_arm():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text(encoding="utf-8")
    for name, token in MODULE.REQUIRED.items():
        mutant = text.replace(token, f"__REMOVED_{name}__", 1)
        assert name in MODULE.validate_installer(mutant)


def test_adaptive_gate_rejects_unsafe_bootstrap_mutants():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text(encoding="utf-8")
    for name, payload in {
        "elevation": "\nStart-Process -Verb RunAs installer.exe\n",
        "unverified_download": "\nInvoke-WebRequest https://example.invalid/x.exe\n",
        "hash_bypass": "\nwinget install --ignore-security-hash\n",
        "mass_delete": "\nRemove-Item C:\\SOUL -Recurse -Force\n",
        "private_key": "\n-----BEGIN " + "PRIVATE KEY-----\n",
        "api_secret": "\n" + "gsk_" + "abcdefghijklmnopqrstuvwxyz123456\n",
    }.items():
        assert name in MODULE.validate_installer(text + payload)
