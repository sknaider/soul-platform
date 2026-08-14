[CmdletBinding()]
param(
    [string]$Model = $env:SOUL_MODEL,
    [string]$Kind = $(if ($env:SOUL_UPSTREAM_KIND) { $env:SOUL_UPSTREAM_KIND } else { "ollama" }),
    [string]$BaseUrl = $(if ($env:SOUL_UPSTREAM_URL) { $env:SOUL_UPSTREAM_URL } else { "http://127.0.0.1:11434/v1" }),
    [string]$Venv = $(if ($env:SOUL_VENV) { $env:SOUL_VENV } else { Join-Path $env:LOCALAPPDATA "SOUL\venv" }),
    [string]$PackageSource,
    [switch]$RequireBundledWheel,
    [switch]$NoMachine,
    [switch]$NoTray,
    [switch]$Check
)

$ErrorActionPreference = "Stop"
$recoveryModule = Join-Path $PSScriptRoot "Soul-Installer-Recovery.psm1"
if (-not (Test-Path -LiteralPath $recoveryModule -PathType Leaf)) {
    throw "Falta el modulo de recuperacion verificado: $recoveryModule"
}
Import-Module -Name $recoveryModule -Force
$MinimumFreeBytes = [UInt64]3221225472
$ApprovedBgeM3Digest = "7907646426070047a77226ac3e684fbbe8410524f7b4a74d02837e43f2146bab"

function Step([string]$Message) { Write-Host "[SOUL] $Message" -ForegroundColor Cyan }
function Good([string]$Message) { Write-Host "  OK $Message" -ForegroundColor Green }
function Assert-MinimumFreeSpace {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [UInt64]$RequiredBytes = 3221225472
    )
    $checkedRoots = @{}
    foreach ($path in $Paths) {
        $fullPath = [System.IO.Path]::GetFullPath($path)
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if (-not $root) { throw "No pude resolver el volumen para $fullPath" }
        $rootKey = $root.ToUpperInvariant()
        if ($checkedRoots.ContainsKey($rootKey)) { continue }
        $drive = [System.IO.DriveInfo]::new($root)
        if (-not $drive.IsReady) { throw "El volumen $root no esta listo." }
        $availableBytes = [UInt64]$drive.AvailableFreeSpace
        if ($availableBytes -lt $RequiredBytes) {
            $availableGiB = [Math]::Round($availableBytes / 1GB, 2)
            throw "HOLD: se requieren al menos 3 GiB libres en $root antes de instalar o migrar; disponibles: $availableGiB GiB."
        }
        $checkedRoots[$rootKey] = $true
        Good "Espacio libre verificado en $root (minimo 3 GiB)"
    }
}

function Assert-BgeM3Digest {
    param([Parameter(Mandatory = $true)]$Tags)
    $modelRecords = @($Tags.models | Where-Object {
        $_.name -eq "bge-m3" -or $_.name -eq "bge-m3:latest" -or
        $_.model -eq "bge-m3" -or $_.model -eq "bge-m3:latest"
    })
    if ($modelRecords.Count -ne 1) {
        throw "HOLD: Ollama debe exponer exactamente un modelo bge-m3 verificable."
    }
    $installedDigest = ([string]$modelRecords[0].digest).Trim().ToLowerInvariant()
    if ($installedDigest -ne $ApprovedBgeM3Digest) {
        throw "HOLD: el digest local de bge-m3 no coincide con el artefacto aprobado."
    }
    Good "BGE-M3 local coincide con el digest aprobado ($installedDigest)"
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "El comando fallo con codigo ${LASTEXITCODE}: $File $($Arguments -join ' ')"
    }
}

function Resolve-PackageSource {
    if (-not $RequireBundledWheel) {
        if ($PackageSource) { return $PackageSource }
        if ($env:SOUL_PACKAGE_SOURCE) { return $env:SOUL_PACKAGE_SOURCE }
    }

    $wheelhouseManifest = Join-Path $PSScriptRoot "WHEELHOUSE.sha256"
    if (-not (Test-Path -LiteralPath $wheelhouseManifest -PathType Leaf)) {
        throw "Falta WHEELHOUSE.sha256; el bundle offline esta incompleto."
    }
    $manifestEntries = @{}
    foreach ($line in @(Get-Content -LiteralPath $wheelhouseManifest)) {
        if ($line -notmatch '^(?<digest>[0-9a-fA-F]{64})  (?<name>[A-Za-z0-9_.+-]+\.whl)$') {
            throw "WHEELHOUSE.sha256 contiene una entrada invalida."
        }
        $lockedName = $Matches['name']
        if ($manifestEntries.ContainsKey($lockedName)) {
            throw "WHEELHOUSE.sha256 contiene un wheel duplicado: $lockedName"
        }
        $manifestEntries[$lockedName] = $Matches['digest'].ToLowerInvariant()
    }
    if ($manifestEntries.Count -eq 0) {
        throw "WHEELHOUSE.sha256 esta vacio."
    }
    $allBundledWheels = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.whl" -File)
    if ($allBundledWheels.Count -ne $manifestEntries.Count) {
        throw "El conjunto de wheels no coincide exactamente con WHEELHOUSE.sha256."
    }
    foreach ($bundledWheel in $allBundledWheels) {
        if (($bundledWheel.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "El wheel incluido no puede ser un enlace/reparse point: $($bundledWheel.Name)"
        }
        if (-not $manifestEntries.ContainsKey($bundledWheel.Name)) {
            throw "El bundle contiene un wheel fuera del lock: $($bundledWheel.Name)"
        }
        $actualDigest = (Get-FileHash -LiteralPath $bundledWheel.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualDigest -ne $manifestEntries[$bundledWheel.Name]) {
            throw "El wheel $($bundledWheel.Name) no coincide con WHEELHOUSE.sha256."
        }
        $sidecar = "$($bundledWheel.FullName).sha256"
        if (-not (Test-Path -LiteralPath $sidecar -PathType Leaf)) {
            throw "Falta el checksum individual de $($bundledWheel.Name)."
        }
        $sidecarText = (Get-Content -LiteralPath $sidecar -Raw).Trim()
        if ($sidecarText -ne "$actualDigest  $($bundledWheel.Name)") {
            throw "El checksum individual no coincide para $($bundledWheel.Name)."
        }
    }
    $bundledWheels = @($allBundledWheels | Where-Object { $_.Name -like "soul_platform-*.whl" })
    if ($bundledWheels.Count -gt 1) {
        throw "Hay varios wheels soul-platform junto al instalador. Deja solo el que quieras instalar o usa -PackageSource."
    }
    if ($bundledWheels.Count -eq 1) {
        $wheel = $bundledWheels[0]
        Good "Paquete incluido verificado: $($wheel.Name) ($($manifestEntries[$wheel.Name]))"
        $coreWheels = @($allBundledWheels | Where-Object { $_.Name -eq "soul_framework-0.4.3-py3-none-any.whl" })
        if ($coreWheels.Count -ne 1) {
            throw "El bundle debe incluir exactamente un wheel soul-framework 0.4.3."
        }
        $coreWheel = $coreWheels[0]
        $script:BundledCoreWheel = $coreWheel.FullName
        $script:BundledPlatformHash = $manifestEntries[$wheel.Name]
        $script:BundledCoreHash = $manifestEntries[$coreWheel.Name]
        Good "Wheelhouse offline verificada: $($manifestEntries.Count) wheels exactos"
        return $wheel.FullName
    }

    if ($RequireBundledWheel) {
        throw "El instalador de doble clic exige exactamente un wheel soul-platform incluido y su checksum. Extrae todo el ZIP y reintenta."
    }

    return "soul-platform"
}

function Find-Python {
    $candidates = @(
        @{ Exe = "py"; Args = @("-3.13") },
        @{ Exe = "py"; Args = @("-3.12") },
        @{ Exe = "py"; Args = @("-3.11") },
        @{ Exe = "python"; Args = @() }
    )
    foreach ($candidate in $candidates) {
        try {
            $version = & $candidate.Exe @($candidate.Args) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            $parts = $version.Trim().Split('.')
            if ($RequireBundledWheel -and -not ([int]$parts[0] -eq 3 -and [int]$parts[1] -eq 13)) {
                continue
            }
            if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11)) {
                return $candidate
            }
        } catch { }
    }
    if ($RequireBundledWheel) {
        throw "El bundle offline requiere Python 3.13 x64. Instalalo desde python.org y vuelve a ejecutar este archivo."
    }
    throw "Python 3.11+ no esta instalado. Instala Python desde python.org y vuelve a ejecutar este archivo."
}

$launcher = Find-Python
Good "Python detectado"
$resolvedPackageSource = Resolve-PackageSource
$resolvedPackageIsBundled = Test-Path -LiteralPath $resolvedPackageSource -PathType Leaf
$resolvedInstallSpec = "${resolvedPackageSource}[desktop]"
$venvPython = Join-Path $Venv "Scripts\python.exe"
$soulRoot = Join-Path $env:LOCALAPPDATA "SOUL"
$soulConfig = Join-Path $soulRoot "proxy.toml"
$soulDb = Join-Path $soulRoot "MachineSoul.db"
Assert-MinimumFreeSpace -Paths @($Venv, $soulRoot) -RequiredBytes $MinimumFreeBytes
$legacyMigrationRequired = $false
$legacyModel = ""
$cutoverActivated = $false
if (-not $NoMachine -and (Test-Path -LiteralPath $soulConfig -PathType Leaf)) {
    $soulConfigText = Get-Content -LiteralPath $soulConfig -Raw
    $embeddingMatch = [regex]::Match(
        $soulConfigText,
        '(?ms)^\s*\[embedding\]\s*\r?\n(?<body>.*?)(?=^\s*\[[^\]]+\]\s*$|\z)'
    )
    if (-not $embeddingMatch.Success) {
        $legacyMigrationRequired = $true
    } else {
        $embeddingBody = $embeddingMatch.Groups['body'].Value
        $isBgeProfile = (
            $embeddingBody -match '(?m)^\s*provider\s*=\s*"bge-m3"\s*$' -and
            $embeddingBody -match '(?m)^\s*dimensions\s*=\s*1024\s*$' -and
            $embeddingBody -match '(?m)^\s*model\s*=\s*"bge-m3"\s*$' -and
            $embeddingBody -match '(?m)^\s*vector_index\s*=\s*"auto"\s*$'
        )
        $isLegacyProfile = (
            $embeddingBody -match '(?m)^\s*provider\s*=\s*"simple"\s*$' -and
            $embeddingBody -match '(?m)^\s*dimensions\s*=\s*128\s*$' -and
            $embeddingBody -match '(?m)^\s*model\s*=\s*"simple"\s*$' -and
            $embeddingBody -match '(?m)^\s*vector_index\s*=\s*"exact"\s*$'
        )
        if ($isLegacyProfile) {
            $legacyMigrationRequired = $true
        } elseif (-not $isBgeProfile) {
            throw "HOLD: perfil embedding no soportado; se requiere simple/128/exact o bge-m3/1024/auto"
        }
    }
    $upstreamMatch = [regex]::Match(
        $soulConfigText,
        '(?ms)^\s*\[upstream\]\s*\r?\n(?<body>.*?)(?=^\s*\[[^\]]+\]\s*$|\z)'
    )
    if ($upstreamMatch.Success) {
        $modelMatch = [regex]::Match($upstreamMatch.Groups['body'].Value, '(?m)^\s*model\s*=\s*"(?<model>[^"]+)"\s*$')
        if ($modelMatch.Success) { $legacyModel = $modelMatch.Groups['model'].Value }
    }
}

if ($legacyMigrationRequired -and $Check) {
    throw "HOLD: MachineSoul usa embeddings legacy 128d. Ejecuta el instalador sin -Check para migrar de forma reversible."
}
if ($Check -and -not $NoMachine -and -not (Test-Path -LiteralPath $soulConfig -PathType Leaf)) {
    throw "No existe una MachineSoul configurada. Ejecuta el instalador sin -Check."
}

if (-not $Check) {
    if (Test-Path $Venv) {
        if (-not (Test-Path (Join-Path $Venv "pyvenv.cfg"))) {
            throw "$Venv existe pero no es un entorno virtual. No lo modifico; elige otra ruta con -Venv."
        }
        if (-not (Test-Path $venvPython)) {
            $backup = "$Venv.broken.$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))"
            Move-Item -LiteralPath $Venv -Destination $backup
            Step "Entorno incompleto preservado en $backup"
        }
    }
    if (-not (Test-Path $venvPython)) {
        Step "Creando entorno aislado en $Venv"
        Invoke-Checked $launcher.Exe (@($launcher.Args) + @("-m", "venv", $Venv))
    }
    Step "Instalando SOUL Platform dentro del entorno aislado"
    if ($resolvedPackageIsBundled) {
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, $resolvedInstallSpec)
    } else {
        Invoke-Checked $venvPython @("-m", "pip", "install", "--upgrade", $resolvedInstallSpec)
    }
    Step "Instalando la interfaz de bandeja con versiones verificadas"
    if ($resolvedPackageIsBundled) {
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, "pystray==0.19.5", "pillow==12.3.0")
        # `pip --upgrade` skips a local wheel when the same version is already
        # present. Reinstall only this package so updates with an unchanged
        # semantic version still load the exact verified bundle bytes.
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, "--force-reinstall", "--no-deps", $resolvedPackageSource)
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, "--force-reinstall", "--no-deps", $BundledCoreWheel)
    } else {
        Invoke-Checked $venvPython @("-m", "pip", "install", "--upgrade", "pystray==0.19.5", "pillow==12.3.0")
    }
}

if (-not (Test-Path $venvPython)) { throw "No existe un entorno SOUL verificable en $Venv" }
Invoke-Checked $venvPython @("-c", "import soul_platform, soul_framework")
Invoke-Checked $venvPython @("-m", "pip", "check")
$installedVersion = & $venvPython -c "from importlib.metadata import version; print(version('soul-platform'))"
if ($LASTEXITCODE -ne 0) { throw "No pude leer la version instalada de soul-platform" }
if ([version]$installedVersion.Trim() -lt [version]"0.4.1") {
    throw "Se requiere soul-platform 0.4.1 o superior; quedo instalada $installedVersion"
}

$installedCoreVersion = & $venvPython -c "import importlib.metadata as m; print(m.version('soul-framework'))"
if ($LASTEXITCODE -ne 0 -or $installedCoreVersion.Trim() -ne "0.4.3") {
    throw "Se requiere soul-framework 0.4.3 exacto; quedo instalada $installedCoreVersion"
}
if ($resolvedPackageIsBundled) {
    $provenanceCheck = "import importlib.metadata as m,json,pathlib,sys,urllib.parse; name,wheel,expected=sys.argv[1:]; d=json.loads(m.distribution(name).read_text('direct_url.json')); url=str(d.get('url') or ''); assert urllib.parse.urlsplit(url).scheme=='file'; assert url==pathlib.Path(wheel).resolve().as_uri(); hashes=(d.get('archive_info') or {}).get('hashes') or {}; observed=str(hashes.get('sha256') or '').removeprefix('sha256=').lower(); assert observed==expected.lower()"
    Invoke-Checked $venvPython @("-c", $provenanceCheck, "soul-platform", $resolvedPackageSource, $BundledPlatformHash)
    Invoke-Checked $venvPython @("-c", $provenanceCheck, "soul-framework", $BundledCoreWheel, $BundledCoreHash)
    Good "Procedencia PEP 610 y hashes del bundle verificados"
}

if (-not $NoMachine) {
$ollamaCommand = Get-Command "ollama" -ErrorAction SilentlyContinue
if (-not $ollamaCommand) {
    throw "SOUL 0.4 requiere Ollama local para BGE-M3. Instala Ollama y vuelve a ejecutar el instalador."
}
$ollamaList = @(& $ollamaCommand.Source list 2>$null)
$bgeInstalled = @($ollamaList | Where-Object { $_ -match '^bge-m3(:latest)?\s' }).Count -gt 0
if (-not $bgeInstalled) {
    if ($Check) { throw "Falta el modelo local bge-m3. Ejecuta el instalador sin -Check para instalarlo." }
    Step "Instalando BGE-M3 local para memoria multilingue"
    Invoke-Checked $ollamaCommand.Source @("pull", "bge-m3")
}
Invoke-Checked $venvPython @("-c", "import asyncio; from soul_platform.local_embedding import LocalBgeM3Embedding as E; assert len(asyncio.run(E().embed('SOUL readiness')))==1024")
$bgeProbe = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:11434/api/embed" `
    -ContentType "application/json" -Body '{"model":"bge-m3","input":"SOUL readiness"}' -TimeoutSec 120
if (@($bgeProbe.embeddings).Count -ne 1 -or @($bgeProbe.embeddings[0]).Count -ne 1024) {
    throw "BGE-M3 local no devolvio un embedding de 1024 dimensiones."
}
try {
    $verifiedBgeTags = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
} catch {
    throw "No pude verificar el digest local de BGE-M3 despues del pull/probe: $($_.Exception.Message)"
}
Assert-BgeM3Digest -Tags $verifiedBgeTags
Good "BGE-M3 local verificado (1024 dimensiones + digest aprobado)"
}

$machine = Join-Path $Venv "Scripts\soul-machine.exe"
if (-not (Test-Path $machine)) { throw "Falta soul-machine.exe en el paquete instalado" }
$cutover = Join-Path $Venv "Scripts\soul-machine-embedding-cutover.exe"
if (-not (Test-Path $cutover)) { throw "Falta soul-machine-embedding-cutover.exe en el paquete instalado" }
$doctor = Join-Path $Venv "Scripts\soul-machine-doctor.exe"
if (-not (Test-Path $doctor)) { throw "Falta soul-machine-doctor.exe en el paquete instalado" }
$trayCli = Join-Path $Venv "Scripts\soul-tray-cli.exe"
if (-not $NoTray -and -not (Test-Path $trayCli)) { throw "Falta soul-tray-cli.exe en el paquete instalado" }

$candidate = Join-Path $soulRoot "MachineSoul.bge-m3.candidate.db"
$checkpoint = Join-Path $soulRoot "MachineSoul.bge-m3.checkpoint.json"
if (-not $NoMachine -and $legacyMigrationRequired) {
    if (-not (Test-Path -LiteralPath $soulDb -PathType Leaf)) {
        throw "HOLD: existe config legacy pero falta la base MachineSoul.db"
    }
    Step "Verificando BGE-M3 antes de detener el alma legacy"
    try {
        Invoke-Checked $venvPython @("-c", "import asyncio; from soul_platform.local_embedding import LocalBgeM3Embedding as E; assert len(asyncio.run(E().embed('SOUL readiness')))==1024")
    } catch {
        throw "HOLD: BGE-M3 local no esta listo; el alma legacy sigue activa. Ejecuta: ollama pull bge-m3"
    }
    Step "Deteniendo el runtime legacy solo despues del probe BGE-M3 verde"
    Invoke-Checked $machine @("disable-autostart", "--config", $soulConfig)

    $candidateExists = Test-Path -LiteralPath $candidate -PathType Leaf
    $checkpointExists = Test-Path -LiteralPath $checkpoint -PathType Leaf
    if ($candidateExists -xor $checkpointExists) {
        throw "HOLD: migracion parcial ambigua; candidate y checkpoint deben existir juntos"
    }
    try {
        if ($candidateExists -and $checkpointExists) {
            & $cutover verify $checkpoint *> $null
            if ($LASTEXITCODE -ne 0) {
                Step "Reanudando migracion BGE-M3 desde checkpoint"
                Invoke-Checked $cutover @("migrate", $soulDb, "--candidate", $candidate, "--checkpoint", $checkpoint, "--resume")
            }
        } else {
            Step "Migrando MachineSoul 128d a candidato BGE-M3 1024d (la original no se modifica)"
            Invoke-Checked $cutover @("migrate", $soulDb, "--candidate", $candidate, "--checkpoint", $checkpoint)
        }
        Invoke-Checked $cutover @("verify", $checkpoint)
        Invoke-Checked $cutover @("activate", $soulConfig, $checkpoint)
        $cutoverActivated = $true
        Good "MachineSoul activada en BGE-M3/índice auto; backup reversible preservado"
    } catch {
        Step "Fallo el upgrade; reactivando el runtime legacy preservado"
        $recoveryModel = $(if ($Model) { $Model } else { "legacy-recovery" })
        try {
            Invoke-Checked $machine @("init", "--root", $soulRoot, "--kind", $Kind, "--base-url", $BaseUrl, "--model", $recoveryModel)
        } catch {
            throw "HOLD CRITICO: fallo el upgrade y no pude reactivar el autostart legacy. Datos preservados en $soulRoot"
        }
        throw
    }
}
$tray = Join-Path $Venv "Scripts\soul-tray.exe"
if (-not $NoTray -and -not (Test-Path $tray)) { throw "Falta soul-tray.exe en el paquete instalado" }
Good "Paquete, dependencias y comandos verificados"

if (-not $Check -and -not $NoMachine) {
    if (-not $Model -and $legacyModel) { $Model = $legacyModel }
    if (-not $Model -and $Kind -eq "ollama") {
        $modelLine = @(& $ollamaCommand.Source list 2>$null | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^bge-m3(:latest)?\s' } | Select-Object -First 1)
        if ($modelLine.Count -gt 0) { $Model = (($modelLine[0] -split '\s+')[0]) }
    }
    if ($Model) {
        Step "Inicializando alma persistente con cerebro ${Kind}:$Model"
        if ($cutoverActivated) { Step "Rollback sin perdida armado si falla el runtime BGE" }
        Invoke-SoulPostActivateRuntime `
            -Machine $machine `
            -Cutover $cutover `
            -SoulConfig $soulConfig `
            -Checkpoint $checkpoint `
            -SoulRoot $soulRoot `
            -Kind $Kind `
            -BaseUrl $BaseUrl `
            -Model $Model `
            -CutoverActivated $cutoverActivated `
            -Runner { param($File, $Arguments) Invoke-Checked $File $Arguments }
        if (-not $NoTray) { Invoke-Checked $trayCli @("--check") }
        Invoke-Checked $doctor @("--config", $soulConfig)
        Good "Alma persistente y arranque automatico verificados"
    } else {
        Write-Warning "SOUL quedo instalado, pero no detecte un modelo Ollama. Cuando tengas uno ejecuta: $machine init --model NOMBRE"
    }
}

if (-not $NoTray -and -not $NoMachine) {
    Step "Verificando e instalando SOUL Tray al iniciar sesion"
    Invoke-Checked $tray @("--headless-check")
    if (-not $Check) {
        Invoke-Checked $tray @("--install-autostart")
    }
    Good "SOUL Tray verificado con tarea de usuario sin elevacion"
}

Write-Host "SOUL listo. Datos persistentes: $env:LOCALAPPDATA\SOUL" -ForegroundColor Green
