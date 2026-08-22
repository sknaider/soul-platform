from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from soul_platform.tray import _windows_tray_register_script


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL_IMAGE = (
    "mcr.microsoft.com/powershell@"
    "sha256:e69d1ba31146ce79f1b84893f2f89adae1e4a4308a96e821aa6cc886de991710"
)


def test_windows_post_activate_recovery_by_effect():
    """Execute the production recovery module with a faulted new runtime."""
    if os.environ.get("SEAL_REQUIRE_POWERSHELL_FAULT_INJECTION") != "1":
        pytest.skip("release-only PowerShell container gate")
    docker = shutil.which("docker")
    assert docker, "Docker is required for the release-only PowerShell gate"
    result = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/work:ro",
            POWERSHELL_IMAGE,
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "/work/tests/windows_recovery_fault_injection.ps1",
            "-ModulePath",
            "/work/installer/Soul-Installer-Recovery.psm1",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WINDOWS_RECOVERY_FAULT_INJECTION_OK rollback_events=3 fresh_events=1" in result.stdout


def test_windows_adaptive_installer_primitives_by_effect():
    """Parse production bytes and exercise the second-run atomic write."""
    if os.environ.get("SEAL_REQUIRE_POWERSHELL_FAULT_INJECTION") != "1":
        pytest.skip("release-only PowerShell container gate")
    docker = shutil.which("docker")
    assert docker, "Docker is required for the release-only PowerShell gate"
    result = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/work:ro",
            POWERSHELL_IMAGE,
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "/work/tests/windows_installer_adaptive_primitives.ps1",
            "-InstallerPath",
            "/work/installer/Install-Soul.ps1",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WINDOWS_ADAPTIVE_PRIMITIVES_OK reruns=2 backups=1 profiles=4" in result.stdout


@pytest.mark.parametrize("previous_xml", ["", "<Task><RegistrationInfo /></Task>"])
def test_windows_tray_register_script_parses_in_real_powershell(
    tmp_path, previous_xml
):
    """The exact generated task transaction must parse in PowerShell itself."""
    if os.environ.get("SEAL_REQUIRE_POWERSHELL_FAULT_INJECTION") != "1":
        pytest.skip("release-only PowerShell container gate")
    docker = shutil.which("docker")
    assert docker, "Docker is required for the release-only PowerShell gate"
    script = _windows_tray_register_script(
        Path("C:/SOUL/venv/Scripts/python.exe"),
        Path("C:/Users/Dadito/AppData/Local/SOUL/proxy.toml"),
        previous_xml,
    )
    target = tmp_path / "tray-register.ps1"
    target.write_text(script, encoding="utf-8")
    result = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "-v",
            f"{tmp_path}:/gate:ro",
            POWERSHELL_IMAGE,
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[void][ScriptBlock]::Create((Get-Content -LiteralPath /gate/tray-register.ps1 -Raw)); 'TRAY_SCRIPT_PARSE_OK'",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "TRAY_SCRIPT_PARSE_OK" in result.stdout
