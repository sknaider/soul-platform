from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_unix_installer_is_parseable_and_initializes_machine_soul():
    installer = ROOT / "installer" / "soul-install.sh"
    subprocess.run(["bash", "-n", str(installer)], check=True)
    text = installer.read_text()
    assert "soul-machine\" init" in text
    assert "rm -rf" not in text
    assert "curl" not in text or "| bash" not in text
    assert 'PLATFORM_VERSION="0.5.9"' in text
    assert 'CORE_VERSION="0.4.3"' in text
    assert "verify_bundled_wheel" in text and "--find-links" not in text
    assert '--no-deps --force-reinstall "$CORE_WHEEL"' in text
    assert 'PLATFORM_INSTALL_FLAGS=(--force-reinstall)' in text
    assert 'PIP_INDEX_FLAGS=(--isolated --index-url https://pypi.org/simple --only-binary=:all:)' in text
    assert 'INSTALL_SPECS=("$CORE_WHEEL" "$SPEC")' in text
    assert (
        '"${PLATFORM_INSTALL_FLAGS[@]}" "${PIP_INDEX_FLAGS[@]}" '
        '"${INSTALL_SPECS[@]}"'
    ) in text
    assert "bundle detectado: conservo el pip" in text
    assert 'direct_url.json' in text and '.resolve().as_uri()' in text
    assert 'archive_info' in text and 'verify_installed_wheel_provenance' in text
    assert 'ollama pull bge-m3' in text
    assert 'len(value["embeddings"][0]) == 1024' in text
    assert 'soul-machine-embedding-cutover" migrate' in text
    assert 'soul-machine-embedding-cutover" verify' in text
    assert 'soul-machine-embedding-cutover" activate' in text
    assert 'MachineSoul.bge.candidate.db' in text
    assert 'MachineSoul.bge.checkpoint.json' in text
    assert 'resume_args=(--resume)' in text
    assert 'recover_legacy_runtime' in text
    assert 'trap recover_legacy_runtime EXIT INT TERM' in text
    assert 'ProxyHandler({})' in text
    assert 'perfil embedding no soportado' in text
    assert 'config MachineSoul verificada: BGE-M3/1024/auto' in text
    activated = text.index('CUTOVER_ACTIVATED=1')
    failed_init = text.index('if ! "$VENV/bin/soul-machine" init', activated)
    rollback = text.index('embedding-cutover" rollback', failed_init)
    legacy_restart = text.index('soul-machine" init --root', rollback)
    assert activated < failed_init < rollback < legacy_restart


def test_windows_installer_is_user_space_and_initializes_machine_soul():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    recovery = (ROOT / "installer" / "Soul-Installer-Recovery.psm1").read_text()
    assert 'Import-Module -Name $recoveryModule -Force' in text
    assert "Invoke-SoulPostActivateRuntime" in text
    assert '@("rollback", $SoulConfig, $Checkpoint)' in recovery
    assert '@("init", "--root", $SoulRoot' in recovery
    assert "soul-machine.exe" in text and '@("init", "--kind"' in recovery
    assert "LOCALAPPDATA" in text
    assert "Remove-Item" not in text
    assert "ExecutionPolicy" not in text
    assert "Start-Process -Verb RunAs" not in text
    assert (
        'Get-ChildItem -LiteralPath $PSScriptRoot -Filter "soul_platform-*.whl"' in text
        or 'Where-Object { $_.Name -like "soul_platform-*.whl" }' in text
    )
    assert 'Join-Path $PSScriptRoot "WHEELHOUSE.sha256"' in text
    assert "if ($actualDigest -ne $manifestEntries[$bundledWheel.Name])" in text
    assert 'return "soul-platform"' in text
    assert '${resolvedPackageSource}[desktop]' in text
    assert '"--force-reinstall", "--no-deps"' in text
    assert "if (-not $RequireBundledWheel)" in text
    assert "if ($RequireBundledWheel)" in text
    assert "$env:SOUL_PACKAGE_SOURCE" in text
    assert "m.distribution(name).read_text('direct_url.json')" in text
    assert "urlsplit(url).scheme=='file'" in text and "archive_info" in text
    assert "soul-tray.exe" in text
    assert 'Invoke-Checked $tray @("--headless-check")' in text
    assert 'Invoke-Checked $tray @("--install-autostart")' in text
    assert '"pystray==0.19.5", "pillow==12.3.0"' in text
    assert "Scripts\\soul-tray.exe" in text
    assert "Scripts\\soul-tray-cli.exe" in text
    assert 'Invoke-Checked $trayCli @("--headless-check")' in text
    assert "Start-Process -Verb RunAs" not in text
    assert '[version]"0.5.9"' in text
    assert "soul-framework 0.4.3 exacto" in text
    assert '$installedCoreVersion = & $venvPython -c' in text
    assert '$installedCoreVersion = & $python -c' not in text
    assert 'soul-machine-embedding-cutover.exe' in text
    assert 'soul-machine-doctor.exe' in text
    assert 'Invoke-Checked $doctor @("--config", $soulConfig)' in text
    assert '@("disable-autostart", "--config", $soulConfig)' in text
    assert '@("migrate", $soulDb, "--candidate", $candidate, "--checkpoint", $checkpoint)' in text
    assert '@("verify", $checkpoint)' in text
    assert '@("activate", $soulConfig, $checkpoint)' in text
    assert 'migracion parcial ambigua' in text
    assert 'Verificando BGE-M3 antes de detener el alma legacy' in text
    assert text.index('Verificando BGE-M3 antes') < text.index('@("disable-autostart"')
    assert 'reactivando el runtime legacy preservado' in text
    assert '@("init", "--root", $SoulRoot' in recovery
    assert '$isLegacyProfile' in text and '$isBgeProfile' in text
    assert 'provider\\s*=\\s*"simple"' in text
    assert 'vector_index\\s*=\\s*"auto"' in text
    assert 'perfil embedding no soportado' in text
    assert 'No existe una MachineSoul configurada' in text
    assert 'if (-not $NoTray -and -not $NoMachine)' in text
    activated = text.index('$cutoverActivated = $true')
    runtime = text.index('Invoke-SoulPostActivateRuntime', activated)
    assert activated < runtime
    guard = text.index("if (-not $NoMachine) {", text.index("$installedCoreVersion"))
    ollama = text.index('$ollamaExe = Ensure-Ollama')
    machine = text.index('$machine = Join-Path $Venv "Scripts\\soul-machine.exe"')
    assert guard < ollama < machine
    assert 'Good "BGE-M3 local verificado (1024 dimensiones + digest aprobado)"' in text


def test_windows_installer_inventory_is_selective_and_ps51_safe():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    assert "function Get-SoulComponentInventory" in text
    assert "function Get-SoulInstallPlan" in text
    assert "Inventario previo: reutilizo lo presente y descargo solo lo ausente" in text
    assert '@{ Exe = (Join-Path $Venv "Scripts\\python.exe"); Args = @() }' in text
    assert "struct.calcsize(chr(80))*8" in text
    assert 'struct.calcsize(`"P`")' not in text
    assert text.index("$initialInventory = Get-SoulComponentInventory") < text.index(
        "$launcher = Ensure-Python"
    )
    assert "$initialPlan = Get-SoulInstallPlan $initialInventory" in text


def test_windows_installer_second_run_is_atomic_and_client_compatible():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    assert "function Move-SoulAtomicFile" in text
    assert "[IO.File]::Replace($Temporary, $Destination, $backup)" in text
    assert "[IO.File]::Replace($temporary, $path, $null)" not in text
    assert "[IO.File]::Replace($temporary, $hooksPath, $null)" not in text
    assert "function Test-SoulMcpMissingText" in text
    assert "No MCP server (?:found|named)" in text
    assert "function Enroll-SoulParentBinding" in text
    assert "function Resolve-ClaudeAppParentBinaries" in text
    assert "function Sync-ClaudeDesktopMcpConfig" in text
    assert '"claude_desktop_config.json"' in text
    assert "Sync-ClaudeDesktopMcpConfig $Mcp $Config" in text
    assert 'Get-AppxPackage -Name "Claude"' in text
    assert '"Claude\\claude-code"' in text
    assert text.count("Enroll-SoulParentBinding $Mcp $Config") == 4
    assert 'Invoke-Checked $trayCli @("--check")' not in text
    assert 'Invoke-Checked $trayCli @("--headless-check")' in text


def test_windows_installer_reuses_exact_bytes_from_a_different_extraction_path():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    probe = text[text.index("function Test-ExactBundledInstall") : text.index("$initialInventory")]
    assert "expected_hash.lower()" in probe
    assert "urlsplit(url).scheme" in probe
    assert "pathlib.Path(wheel).resolve().as_uri()" not in probe
    assert 'direct.get("url")' not in probe
    assert "direct.get('url')" in probe


def test_windows_fresh_or_bge_install_defines_recovery_paths_before_any_branch():
    """StrictMode must not abort a non-legacy install on an unset checkpoint."""
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    candidate = '$candidate = Join-Path $soulRoot "MachineSoul.bge-m3.candidate.db"'
    checkpoint = (
        '$checkpoint = Join-Path $soulRoot '
        '"MachineSoul.bge-m3.checkpoint.json"'
    )
    legacy_branch = "if (-not $NoMachine -and $legacyMigrationRequired) {"
    runtime_call = "Invoke-SoulPostActivateRuntime"
    assert text.count(candidate) == 1
    assert text.count(checkpoint) == 1
    assert text.index(candidate) < text.index(legacy_branch) < text.index(runtime_call)
    assert text.index(checkpoint) < text.index(legacy_branch) < text.index(runtime_call)


def test_windows_installer_requires_three_gib_before_install_or_migration():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    assert "$MinimumFreeBytes = [UInt64]3221225472" in text
    assert "function Assert-MinimumFreeSpace" in text
    assert "if ($availableBytes -lt $RequiredBytes)" in text
    assert "se requieren al menos 3 GiB libres" in text
    assert "Espacio libre verificado" in text
    call = "Assert-MinimumFreeSpace -Paths @($Venv, $soulRoot)"
    assert call in text
    assert text.index(call) < text.index("if (-not $Check)")
    assert text.index(call) < text.index('@("disable-autostart"')


def test_windows_installer_requires_approved_bge_m3_digest_after_probe():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    digest = "7907646426070047a77226ac3e684fbbe8410524f7b4a74d02837e43f2146bab"
    assert f'$ApprovedBgeM3Digest = "{digest}"' in text
    assert "function Assert-BgeM3Digest" in text
    assert "if ($installedDigest -ne $ApprovedBgeM3Digest)" in text
    assert "no coincide con el artefacto aprobado" in text
    assert "coincide con el digest aprobado" in text
    call = "Assert-BgeM3Digest -Tags $verifiedBgeTags"
    assert call in text
    assert text.index("$bgeProbe = Invoke-RestMethod") < text.index(call)
    assert text.index('@("pull", "bge-m3")') < text.index(call)


def test_windows_bundled_install_is_exact_and_never_uses_pypi():
    text = (ROOT / "installer" / "Install-Soul.ps1").read_text()
    assert "WHEELHOUSE.sha256 contiene un wheel duplicado" in text
    assert "conjunto de wheels no coincide exactamente" in text
    assert "wheel fuera del lock" in text
    assert "ReparsePoint" in text
    assert "El bundle offline requiere Python 3.13 x64" in text
    offline_platform = (
        'Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", '
        '"--find-links", $PSScriptRoot, $resolvedInstallSpec)'
    )
    offline_tray = (
        'Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", '
        '"--find-links", $PSScriptRoot, "pystray==0.19.5", "pillow==12.3.0")'
    )
    offline_reinstall = (
        'Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", '
        '"--find-links", $PSScriptRoot, "--force-reinstall", "--no-deps", '
        "$resolvedPackageSource)"
    )
    assert offline_platform in text
    assert offline_tray in text
    assert offline_reinstall in text
    install_section = text[text.index('Step "Instalando SOUL Platform') :]
    bundled_branch = install_section.split("} else {", 1)[0]
    assert '"--upgrade", "pip"' not in bundled_branch


def test_windows_click_installer_is_local_and_non_elevating():
    text = (ROOT / "installer" / "Instalar-SOUL-Windows.bat").read_text()
    assert "Install-Soul.ps1" in text
    assert "-RequireBundledWheel" in text
    assert "-ExecutionPolicy Bypass" in text
    assert "RunAs" not in text
    assert "curl" not in text
def test_windows_novice_guide_matches_tray_release():
    text = (ROOT / "installer" / "LEEME-WINDOWS.txt").read_text()
    assert "SOUL PLATFORM 0.5.9" in text
    assert "icono violeta SOUL" in text
    assert "Copiar token local" in text
    assert "Python 3.13 x64" in text
    assert "sin PyPI" in text
    assert "WHEELHOUSE.sha256" in text
    assert "--no-index" in text
