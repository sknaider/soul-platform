[CmdletBinding()]
param(
    [string]$Model = $env:SOUL_MODEL,
    [string]$Kind = $(if ($env:SOUL_UPSTREAM_KIND) { $env:SOUL_UPSTREAM_KIND } else { "ollama" }),
    [string]$BaseUrl = $(if ($env:SOUL_UPSTREAM_URL) { $env:SOUL_UPSTREAM_URL } else { "http://127.0.0.1:11434/v1" }),
    [string]$Venv = $(if ($env:SOUL_VENV) { $env:SOUL_VENV } else { Join-Path $env:LOCALAPPDATA "SOUL\venv" }),
    [string]$PackageSource,
    [string]$BootstrapModel = $(if ($env:SOUL_BOOTSTRAP_MODEL) { $env:SOUL_BOOTSTRAP_MODEL } else { "gemma3:1b" }),
    [switch]$RequireBundledWheel,
    [switch]$TrustCurrentOllama,
    [switch]$NoBootstrap,
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
function Skip([string]$Message) { Write-Host "  SKIP $Message" -ForegroundColor DarkGreen }
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
$script:InstalledComponents = New-Object System.Collections.Generic.List[string]
$script:SkippedComponents = New-Object System.Collections.Generic.List[string]
function Mark-Installed([string]$Component) { $script:InstalledComponents.Add($Component) | Out-Null }
function Mark-Skipped([string]$Component) { $script:SkippedComponents.Add($Component) | Out-Null }
function Move-SoulAtomicFile([string]$Temporary, [string]$Destination, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Temporary -PathType Leaf)) {
        throw "Falta el archivo temporal para $Label"
    }
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        # Windows PowerShell 5.1/.NET Framework rejects File.Replace(..., $null)
        # on some systems. A real, unique backup path makes the replacement
        # atomic and preserves the previous bytes instead of deleting them.
        $backupRoot = Join-Path $env:LOCALAPPDATA "SOUL\atomic-backups"
        [IO.Directory]::CreateDirectory($backupRoot) | Out-Null
        $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '-')
        $backup = Join-Path $backupRoot ("{0}-{1}-{2}.bak" -f $safeLabel, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), $PID)
        [IO.File]::Replace($Temporary, $Destination, $backup)
    } else {
        [IO.File]::Move($Temporary, $Destination)
    }
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        throw "El reemplazo atomico no produjo $Label"
    }
}
function Write-InstallReceipt([string]$Root, [string]$Status) {
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $path = Join-Path $Root "install-receipt.json"
    $temporary = "$path.soul-$PID.tmp"
    $payload = [ordered]@{
        schema_version = 1
        status = $Status
        platform_version = "0.5.9"
        core_version = "0.4.3"
        utc = [DateTime]::UtcNow.ToString("o")
        machine = $env:COMPUTERNAME
        user = $env:USERNAME
        installed = @($script:InstalledComponents)
        skipped = @($script:SkippedComponents)
    } | ConvertTo-Json -Depth 8
    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temporary, $payload, $utf8NoBom)
    Move-SoulAtomicFile $temporary $path "install-receipt"
    return $path
}
function Invoke-NativeCapture([string]$File, [string[]]$Arguments) {
    # Windows PowerShell can promote a native program's stderr to a terminating
    # NativeCommandError while `$ErrorActionPreference = "Stop"`, even when the
    # program is merely reporting a normal negative probe. Capture the stream
    # and decide exclusively from the native exit code.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $File @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = @($output) }
}

function Resolve-NativeCli([System.Management.Automation.CommandInfo]$Command) {
    # npm installs both .ps1 and .cmd shims on Windows. A PowerShell shim can
    # consume the `--` separator before Claude Code sees it, causing MCP server
    # arguments such as `--config` to be misparsed as Claude options. Prefer the
    # byte-adjacent .cmd shim when available.
    $source = [string]$Command.Source
    if ([IO.Path]::GetExtension($source).Equals(".ps1", [StringComparison]::OrdinalIgnoreCase)) {
        $cmdShim = [IO.Path]::ChangeExtension($source, ".cmd")
        if (Test-Path -LiteralPath $cmdShim -PathType Leaf) { return $cmdShim }
    }
    return $source
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    $result = Invoke-NativeCapture $File $Arguments
    foreach ($line in $result.Output) { Write-Host ([string]$line) }
    if ($result.ExitCode -ne 0) {
        throw "El comando fallo con codigo $($result.ExitCode): $File $($Arguments -join ' ')"
    }
}

function Backup-ClientConfig([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $backupRoot = Join-Path $env:LOCALAPPDATA "SOUL\client-config-backups"
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    $digest = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0, 16)
    $target = Join-Path $backupRoot ("{0}-{1}-{2}.bak" -f $Label, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), $digest)
    Copy-Item -LiteralPath $Path -Destination $target
    return $target
}

function Get-OptionalFileHash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "__MISSING__" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Restore-ClientConfigCas(
    [string]$Path, [string]$Backup, [string]$BeforeHash,
    [string]$PostAddHash, [string]$Label
) {
    $current = Get-OptionalFileHash $Path
    if ($current -eq $BeforeHash) { return }
    if ($current -ne $PostAddHash) {
        throw "HOLD: $Label cambio concurrentemente; preservo esos bytes y no ejecuto rollback destructivo"
    }
    if ($BeforeHash -eq "__MISSING__") {
        [IO.File]::Delete($Path)
    } elseif ($Backup) {
        Copy-Item -LiteralPath $Backup -Destination $Path -Force
    } else {
        throw "HOLD: falta backup verificable de $Label"
    }
    if ((Get-OptionalFileHash $Path) -ne $BeforeHash) {
        throw "Rollback CAS de $Label no reprodujo los bytes previos"
    }
}

function Resolve-ClientParentBinary([string]$ClientId, [string]$CommandPath) {
    $command = Get-Item -LiteralPath $CommandPath -ErrorAction Stop
    if ($command.Extension -ieq ".exe") { return $command.FullName }
    $base = $command.Directory.FullName
    if ($ClientId -eq "claude") {
        $candidate = Join-Path $base "node_modules\@anthropic-ai\claude-code\bin\claude.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    if ($ClientId -eq "codex") {
        $nativeRoot = Join-Path $base "node_modules\@openai\codex\node_modules"
        $candidates = @(
            Get-ChildItem -LiteralPath $nativeRoot -Filter "codex.exe" -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\vendor\\[^\\]+\\bin\\codex\.exe$' }
        )
        if ($candidates.Count -eq 1) { return $candidates[0].FullName }
        if ($candidates.Count -gt 1) {
            throw "HOLD: encontre varios binarios nativos de Codex; no puedo ligar el grant sin ambiguedad"
        }
    }
    throw "HOLD: no pude ligar $ClientId a un binario padre unico y verificable"
}

function Resolve-CodexAppParentBinaries {
    $package = Get-AppxPackage -Name "OpenAI.Codex" -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $package) { return @() }
    $canonical = Join-Path $package.InstallLocation "app\resources\codex.exe"
    if (-not (Test-Path -LiteralPath $canonical -PathType Leaf)) {
        throw "HOLD: Codex App esta registrado pero su runtime integrado no existe"
    }
    $canonicalHash = (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash
    $parents = @($canonical)
    $cache = Join-Path $env:LOCALAPPDATA "OpenAI\Codex\bin"
    if (Test-Path -LiteralPath $cache -PathType Container) {
        $parents += @(
            Get-ChildItem -LiteralPath $cache -Filter "codex.exe" -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -eq $canonicalHash } |
                ForEach-Object { $_.FullName }
        )
    }
    return @($parents | Sort-Object -Unique)
}

function Resolve-ClaudeAppParentBinaries {
    # Claude Desktop launches MCP through a per-user Claude Code runtime and,
    # depending on the Desktop build, may launch it directly from Claude.exe.
    # Bind only the OS-registered app plus the exact current runtime bytes.
    $package = Get-AppxPackage -Name "Claude" -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $package) { return @() }
    $desktop = Join-Path $package.InstallLocation "app\Claude.exe"
    if (-not (Test-Path -LiteralPath $desktop -PathType Leaf)) {
        throw "HOLD: Claude Desktop esta registrado pero su ejecutable no existe"
    }
    $parents = @($desktop)
    $runtimeRoot = Join-Path $env:APPDATA "Claude\claude-code"
    if (Test-Path -LiteralPath $runtimeRoot -PathType Container) {
        $live = @(
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.ExecutablePath -and
                    $_.ExecutablePath.StartsWith($runtimeRoot, [StringComparison]::OrdinalIgnoreCase) -and
                    [IO.Path]::GetFileName($_.ExecutablePath) -ieq "claude.exe"
                } |
                ForEach-Object { $_.ExecutablePath } |
                Sort-Object -Unique
        )
        if ($live.Count -gt 0) {
            $parents += $live
        } else {
            $latest = Get-ChildItem -LiteralPath $runtimeRoot -Filter "claude.exe" -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\claude-code\\[^\\]+\\claude\.exe$' } |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 1
            if ($latest) { $parents += $latest.FullName }
        }
    }
    $unique = @($parents | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Sort-Object -Unique)
    if ($unique.Count -gt 8) {
        throw "HOLD: encontre demasiadas superficies de Claude Desktop"
    }
    return $unique
}

function Set-SoulPrivateAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $isDirectory = Test-Path -LiteralPath $Path -PathType Container
    if ($isDirectory) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $inherit = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,"FullControl",$inherit,$propagation,"Allow")))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,"FullControl",$inherit,$propagation,"Allow")))
    } else {
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,"FullControl","Allow")))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,"FullControl","Allow")))
    }
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl -LiteralPath $Path -AclObject $acl
    $live = Get-Acl -LiteralPath $Path
    $allowed = @($identity.Value, $system.Value)
    $unexpected = @($live.Access | Where-Object {
        $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $_.AccessControlType -eq "Allow" -and $sid -notin $allowed
    })
    if (-not $live.AreAccessRulesProtected -or $unexpected.Count -ne 0) {
        throw "ACL privada no se verifico para $Path"
    }
}

function Assert-CodexSoulMcp([string]$Codex, [string]$Mcp, [string]$Config) {
    $probe = Invoke-NativeCapture $Codex @("mcp", "get", "soul-local", "--json")
    if ($probe.ExitCode -ne 0) { return $false }
    try { $entry = (($probe.Output -join "`n") | ConvertFrom-Json) } catch { return $false }
    return (
        $entry.enabled -eq $true -and
        $entry.transport.type -eq "stdio" -and
        [IO.Path]::GetFullPath([string]$entry.transport.command) -eq [IO.Path]::GetFullPath($Mcp) -and
        (@($entry.transport.args) -join "`0") -eq (@("--config", $Config, "--client-id", "codex") -join "`0")
    )
}

function Test-SoulMcpMissingText([string]$Text) {
    return [bool]($Text -match 'No MCP server (?:found|named)')
}

function Enroll-SoulParentBinding([string]$Mcp, [string]$Config, [string]$ClientId, [string]$Parent) {
    Invoke-Checked $Mcp @(
        "--config", $Config, "--client-id", $ClientId, "--enroll-parent", $Parent,
        "--rotate-existing", "--add-parent-binding"
    )
}

function Assert-ClaudeSoulMcp([string]$Claude, [string]$Mcp, [string]$Config) {
    $probe = Invoke-NativeCapture $Claude @("mcp", "get", "soul-local")
    if ($probe.ExitCode -ne 0) { return $false }
    $text = $probe.Output -join "`n"
    return (
        $text -notmatch 'Failed to connect' -and
        -not (Test-SoulMcpMissingText $text) -and
        $text -match [regex]::Escape("Command: $Mcp") -and
        $text -match [regex]::Escape("Args: --config $Config --client-id claude")
    )
}

function Install-CodexSessionStartHook([string]$HookExe, [string]$Mcp, [string]$Config) {
    if (-not (Test-Path -LiteralPath $HookExe -PathType Leaf)) {
        throw "Falta soul-codex-session-start.exe en el paquete instalado"
    }
    $codexRoot = Join-Path $env:USERPROFILE ".codex"
    $hooksPath = Join-Path $codexRoot "hooks.json"
    [IO.Directory]::CreateDirectory($codexRoot) | Out-Null
    $backup = Backup-ClientConfig $hooksPath "codex-hooks"
    $beforeHash = Get-OptionalFileHash $hooksPath
    try {
        if (Test-Path -LiteralPath $hooksPath -PathType Leaf) {
            $document = Get-Content -LiteralPath $hooksPath -Raw | ConvertFrom-Json
        } else {
            $document = [pscustomobject]@{ description = "SOUL local lifecycle hooks"; hooks = [pscustomobject]@{} }
        }
        if (-not $document.hooks) {
            $document | Add-Member -NotePropertyName hooks -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $command = ('"{0}" --config "{1}" --server-executable "{2}" --client-id codex' -f $HookExe, $Config, $Mcp)
        $handler = [ordered]@{
            type = "command"
            command = $command
            commandWindows = $command
            timeout = 25
            statusMessage = "Encendiendo SOUL local"
            additionalContextLimit = 6000
        }
        $groups = @($document.hooks.SessionStart)
        $preserved = @($groups | Where-Object {
            $owned = @($_.hooks | Where-Object {
                ([string]$_.commandWindows) -match 'soul-codex-session-start\.exe'
            })
            $owned.Count -eq 0
        })
        $sessionStart = @($preserved) + @([ordered]@{
            matcher = "^(startup|resume|clear|compact)$"
            hooks = @($handler)
        })
        $document.hooks | Add-Member -NotePropertyName SessionStart -NotePropertyValue $sessionStart -Force
        $temporary = "$hooksPath.soul-$PID.tmp"
        $json = $document | ConvertTo-Json -Depth 20
        $utf8NoBom = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($temporary, $json, $utf8NoBom)
        Move-SoulAtomicFile $temporary $hooksPath "codex-hooks"
        $live = Get-Content -LiteralPath $hooksPath -Raw | ConvertFrom-Json
        $ownedLive = @($live.hooks.SessionStart | ForEach-Object { $_.hooks } | Where-Object {
            ([string]$_.commandWindows) -eq $command -and
            [int]$_.additionalContextLimit -eq 6000
        })
        if ($ownedLive.Count -ne 1) {
            throw "Codex SessionStart hook no quedo cableado exactamente una vez"
        }
    } catch {
        $currentHash = Get-OptionalFileHash $hooksPath
        if ($currentHash -ne $beforeHash) {
            if ($beforeHash -eq "__MISSING__") {
                [IO.File]::Delete($hooksPath)
            } elseif ($backup) {
                Copy-Item -LiteralPath $backup -Destination $hooksPath -Force
            }
        }
        throw
    }
    return $hooksPath
}

function Test-ClaudeSoulMcpShape([string]$Claude, [string]$Mcp, [string]$Config) {
    $probe = Invoke-NativeCapture $Claude @("mcp", "get", "soul-local")
    $text = $probe.Output -join "`n"
    return (
        -not (Test-SoulMcpMissingText $text) -and
        $text -match [regex]::Escape("Command: $Mcp") -and
        $text -match [regex]::Escape("Args: --config $Config --client-id claude")
    )
}

function Sync-ClaudeDesktopMcpConfig([string]$Mcp, [string]$Config) {
    $desktopDir = Join-Path $env:APPDATA "Claude"
    $desktopConfig = Join-Path $desktopDir "claude_desktop_config.json"
    New-Item -ItemType Directory -Path $desktopDir -Force | Out-Null
    $beforeHash = Get-OptionalFileHash $desktopConfig
    $backup = Backup-ClientConfig $desktopConfig "claude-desktop"
    if ($beforeHash -eq "__MISSING__") {
        $document = [pscustomobject]@{}
    } else {
        try {
            $document = Get-Content -LiteralPath $desktopConfig -Raw | ConvertFrom-Json
        } catch {
            throw "HOLD: claude_desktop_config.json no es JSON valido; preservo sus bytes"
        }
    }
    if (-not $document -or $document -isnot [Management.Automation.PSCustomObject]) {
        throw "HOLD: claude_desktop_config.json no contiene un objeto JSON"
    }
    if (-not $document.PSObject.Properties['mcpServers']) {
        $document | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{})
    } elseif ($document.mcpServers -isnot [Management.Automation.PSCustomObject]) {
        throw "HOLD: mcpServers de Claude Desktop no es un objeto"
    }
    $desired = [ordered]@{
        command = $Mcp
        args = @("--config", $Config, "--client-id", "claude")
    }
    $current = $document.mcpServers.'soul-local'
    if (
        $current -and
        [string]$current.command -eq $Mcp -and
        ((@($current.args) -join [char]0) -eq (@($desired.args) -join [char]0))
    ) {
        return $false
    }
    if ($document.mcpServers.PSObject.Properties['soul-local']) {
        $document.mcpServers.'soul-local' = $desired
    } else {
        $document.mcpServers | Add-Member -NotePropertyName 'soul-local' -NotePropertyValue $desired
    }
    $json = $document | ConvertTo-Json -Depth 64
    $temporary = $desktopConfig + ".soul-tmp"
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    $wrote = $false
    try {
        if ((Get-OptionalFileHash $desktopConfig) -ne $beforeHash) {
            throw "HOLD: Claude Desktop cambio su config concurrentemente; preservo esos bytes"
        }
        if ($beforeHash -eq "__MISSING__") {
            [IO.File]::Move($temporary, $desktopConfig)
        } else {
            [IO.File]::Replace($temporary, $desktopConfig, $null, $true)
        }
        $wrote = $true
        $postHash = Get-OptionalFileHash $desktopConfig
        $verified = Get-Content -LiteralPath $desktopConfig -Raw | ConvertFrom-Json
        $entry = $verified.mcpServers.'soul-local'
        if (
            -not $entry -or
            [string]$entry.command -ne $Mcp -or
            ((@($entry.args) -join [char]0) -ne (@($desired.args) -join [char]0))
        ) {
            throw "Claude Desktop no confirmo soul-local en su config"
        }
        return $true
    } catch {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            [IO.File]::Delete($temporary)
        }
        if ($wrote) {
            $postHash = Get-OptionalFileHash $desktopConfig
            Restore-ClientConfigCas $desktopConfig $backup $beforeHash $postHash "Claude Desktop config"
        }
        throw
    }
}

function Install-SoulClientMcp([string]$Mcp, [string]$Config) {
    if (-not (Test-Path -LiteralPath $Mcp -PathType Leaf)) {
        throw "Falta soul-mcp-stdio.exe en el paquete instalado"
    }
    $wired = @()
    $needCodex = $false
    $needClaude = $false
    $codexAppParents = @(Resolve-CodexAppParentBinaries)
    $claudeAppParents = @(Resolve-ClaudeAppParentBinaries)
    $codexCommand = Get-Command "codex" -ErrorAction SilentlyContinue
    $codexCli = $null
    if ($codexCommand) {
        $codexCli = Resolve-NativeCli $codexCommand
    } elseif ($codexAppParents.Count -gt 0) {
        $codexCli = $codexAppParents[0]
    }
    if ($codexCli) {
        if (-not (Assert-CodexSoulMcp $codexCli $Mcp $Config)) {
            $existing = Invoke-NativeCapture $codexCli @("mcp", "get", "soul-local", "--json")
            if ($existing.ExitCode -eq 0) {
                throw "HOLD: Codex ya tiene soul-local con otro comando; no lo sobrescribo"
            }
            $needCodex = $true
        }
    }
    $claudeCommand = Get-Command "claude" -ErrorAction SilentlyContinue
    $claudeCli = $null
    if ($claudeCommand) {
        $claudeCli = Resolve-NativeCli $claudeCommand
    } else {
        $claudeCli = @($claudeAppParents | Where-Object {
            $_ -match '\\Claude\\claude-code\\[^\\]+\\claude\.exe$'
        } | Select-Object -First 1)
        if ($claudeCli.Count -eq 1) { $claudeCli = $claudeCli[0] } else { $claudeCli = $null }
    }
    if ($claudeCli) {
        if (-not (Test-ClaudeSoulMcpShape $claudeCli $Mcp $Config)) {
            $existing = Invoke-NativeCapture $claudeCli @("mcp", "get", "soul-local")
            if (-not (Test-SoulMcpMissingText ($existing.Output -join "`n"))) {
                throw "HOLD: Claude ya tiene soul-local distinto o no saludable; no lo sobrescribo"
            }
            $needClaude = $true
        }
    }

    # Preflight both clients before the first mutation. If either post-add gate
    # fails, remove only the entries created here and restore exact config bytes.
    $codexConfig = Join-Path $env:USERPROFILE ".codex\config.toml"
    $claudeConfig = Join-Path $env:USERPROFILE ".claude.json"
    $codexExisted = Test-Path -LiteralPath $codexConfig -PathType Leaf
    $claudeExisted = Test-Path -LiteralPath $claudeConfig -PathType Leaf
    $codexBeforeHash = Get-OptionalFileHash $codexConfig
    $claudeBeforeHash = Get-OptionalFileHash $claudeConfig
    $codexBackup = $(if ($needCodex) { Backup-ClientConfig $codexConfig "codex" } else { $null })
    $claudeBackup = $(if ($needClaude) { Backup-ClientConfig $claudeConfig "claude" } else { $null })
    $codexAdded = $false
    $claudeAdded = $false
    $codexPostAddHash = $codexBeforeHash
    $claudePostAddHash = $claudeBeforeHash
    try {
        if ($needCodex) {
            Invoke-Checked $codexCli @("mcp", "add", "soul-local", "--", $Mcp, "--config", $Config, "--client-id", "codex")
            $codexAdded = $true
            $codexPostAddHash = Get-OptionalFileHash $codexConfig
        }
        if ($needClaude) {
            Invoke-Checked $claudeCli @("mcp", "add", "--scope", "user", "soul-local", "--", $Mcp, "--config", $Config, "--client-id", "claude")
            $claudeAdded = $true
            $claudePostAddHash = Get-OptionalFileHash $claudeConfig
        }
        if ($codexCli) {
            $codexParent = Resolve-ClientParentBinary "codex" $codexCli
            Enroll-SoulParentBinding $Mcp $Config "codex" $codexParent
            foreach ($appParent in $codexAppParents) {
                Enroll-SoulParentBinding $Mcp $Config "codex" $appParent
            }
            if (-not (Assert-CodexSoulMcp $codexCli $Mcp $Config)) {
                throw "Codex no confirmo el MCP local de SOUL"
            }
        }
        if ($claudeCli) {
            $claudeParent = Resolve-ClientParentBinary "claude" $claudeCli
            Enroll-SoulParentBinding $Mcp $Config "claude" $claudeParent
            foreach ($appParent in $claudeAppParents) {
                Enroll-SoulParentBinding $Mcp $Config "claude" $appParent
            }
            if (-not (Assert-ClaudeSoulMcp $claudeCli $Mcp $Config)) {
                throw "Claude no confirmo el MCP local de SOUL"
            }
        }
        if ($claudeAppParents.Count -gt 0) {
            $null = Sync-ClaudeDesktopMcpConfig $Mcp $Config
        }
    } catch {
        # Do not call `mcp remove` first: the CLI can reserialize B(post-add)
        # into C(post-remove), which would make the byte-CAS mistake its own
        # change for a concurrent writer. The exact A backup is already the
        # complete inverse of our add. Restore A directly only while bytes are
        # still exactly B; an external D is preserved and raises HOLD.
        if ($claudeAdded) { Restore-ClientConfigCas $claudeConfig $claudeBackup $claudeBeforeHash $claudePostAddHash "Claude config" }
        if ($codexAdded) { Restore-ClientConfigCas $codexConfig $codexBackup $codexBeforeHash $codexPostAddHash "Codex config" }
        throw
    }
    if ($codexCli) { $wired += "codex" }
    if ($claudeCli) { $wired += "claude" }
    return $wired
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
    if ($manifestEntries.Count -eq 0) { throw "WHEELHOUSE.sha256 esta vacio." }
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
        if ((Get-Content -LiteralPath $sidecar -Raw).Trim() -ne "$actualDigest  $($bundledWheel.Name)") {
            throw "El checksum individual no coincide para $($bundledWheel.Name)."
        }
    }
    $bundledWheels = @($allBundledWheels | Where-Object { $_.Name -like "soul_platform-*.whl" })
    if ($bundledWheels.Count -gt 1) {
        throw "Hay varios wheels soul-platform junto al instalador. Deja solo el que quieras instalar o usa -PackageSource."
    }
    if ($bundledWheels.Count -eq 1) {
        $wheel = $bundledWheels[0]
        $actual = $manifestEntries[$wheel.Name]
        Good "Paquete incluido verificado: $($wheel.Name) ($actual)"
        $coreWheels = @($allBundledWheels | Where-Object { $_.Name -eq "soul_framework-0.4.3-py3-none-any.whl" })
        if ($coreWheels.Count -ne 1) {
            throw "El bundle debe incluir exactamente un wheel soul-framework 0.4.3."
        }
        $coreWheel = $coreWheels[0]
        $coreActual = $manifestEntries[$coreWheel.Name]
        $script:BundledCoreWheel = $coreWheel.FullName
        $script:BundledPlatformHash = $actual
        $script:BundledCoreHash = $coreActual
        Good "Wheelhouse offline verificada: $($manifestEntries.Count) wheels exactos"
        return $wheel.FullName
    }

    if ($RequireBundledWheel) {
        throw "El instalador de doble clic exige exactamente un wheel soul-platform incluido y su checksum. Extrae todo el ZIP y reintenta."
    }

    return "soul-platform"
}

function Refresh-ProcessPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Resolve-Winget {
    $command = Get-Command "winget" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $fallback = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\winget.exe"
    if (Test-Path -LiteralPath $fallback -PathType Leaf) { return $fallback }
    return $null
}

function Install-WingetUserPackage([string]$PackageId, [string]$Label) {
    $winget = Resolve-Winget
    if (-not $winget) {
        Step "WinGet no esta registrado; reparando App Installer para el usuario actual"
        try {
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
        } catch {
            throw "Falta WinGet y Windows no pudo registrar App Installer: $($_.Exception.Message)"
        }
        Refresh-ProcessPath
        $winget = Resolve-Winget
        if (-not $winget) {
            throw "App Installer se registro, pero WinGet sigue ausente. Actualizalo desde Microsoft Store y reintenta."
        }
    }
    Step "Instalando $Label (solo usuario, paquete exacto $PackageId)"
    Invoke-Checked $winget @(
        "install", "--id", $PackageId, "--exact", "--source", "winget", "--scope", "user",
        "--silent", "--disable-interactivity", "--accept-package-agreements", "--accept-source-agreements"
    )
    Refresh-ProcessPath
    Mark-Installed $Label
}

function Find-Python {
    $candidates = @(
        @{ Exe = (Join-Path $Venv "Scripts\python.exe"); Args = @() },
        @{ Exe = "py"; Args = @("-3.13") },
        @{ Exe = "py"; Args = @("-3.12") },
        @{ Exe = "py"; Args = @("-3.11") },
        @{ Exe = "python"; Args = @() },
        @{ Exe = (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"); Args = @() },
        @{ Exe = (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"); Args = @() },
        @{ Exe = (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"); Args = @() }
    )
    foreach ($candidate in $candidates) {
        try {
            # chr(80) avoids nested quote escaping that breaks this probe in
            # Windows PowerShell 5.1 even though it works in PowerShell 7.
            $version = & $candidate.Exe @($candidate.Args) -c "import struct,sys; print(f'{sys.version_info.major}.{sys.version_info.minor}:{struct.calcsize(chr(80))*8}')" 2>$null
            $fields = $version.Trim().Split(':')
            $parts = $fields[0].Split('.')
            if ($RequireBundledWheel -and -not (
                [int]$parts[0] -eq 3 -and [int]$parts[1] -eq 13 -and [int]$fields[1] -eq 64
            )) { continue }
            if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11)) {
                return $candidate
            }
        } catch { }
    }
    return $null
}

function Ensure-Python {
    $python = Find-Python
    if ($python) {
        if ($RequireBundledWheel) {
            Skip "Python 3.13 x64 ya existe"
            Mark-Skipped "Python 3.13 x64 (presente)"
        } else {
            Skip "Python 3.11+ ya existe"
            Mark-Skipped "Python 3.11+ (presente)"
        }
        return $python
    }
    $requiredPython = $(if ($RequireBundledWheel) { "Python 3.13 x64" } else { "Python 3.11+" })
    if ($Check) { throw "Falta $requiredPython. Ejecuta el instalador sin -Check para instalarlo." }
    if ($NoBootstrap) { throw "Falta $requiredPython y -NoBootstrap prohibe instalarlo." }
    Install-WingetUserPackage "Python.Python.3.13" "Python 3.13 x64"
    $python = Find-Python
    if (-not $python) { throw "El bundle offline requiere Python 3.13 x64 y WinGet no lo dejo detectable." }
    Good "Python 3.13 x64 instalado y detectado"
    return $python
}

function Find-Ollama {
    $command = Get-Command "ollama" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $fallback = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
    if (Test-Path -LiteralPath $fallback -PathType Leaf) { return $fallback }
    return $null
}

function Ensure-Ollama {
    $ollama = Find-Ollama
    if ($ollama) {
        Skip "Ollama ya existe"
        Mark-Skipped "Ollama (presente)"
    } else {
        if ($Check) { throw "Falta Ollama. Ejecuta el instalador sin -Check para instalarlo." }
        if ($NoBootstrap) { throw "Falta Ollama y -NoBootstrap prohibe instalarlo." }
        Install-WingetUserPackage "Ollama.Ollama" "Ollama"
        $ollama = Find-Ollama
        if (-not $ollama) { throw "WinGet termino, pero Ollama no quedo detectable." }
        Good "Ollama instalado y detectado"
    }
    $probe = Invoke-NativeCapture $ollama @("list")
    if ($probe.ExitCode -ne 0 -and -not $Check) {
        Step "Encendiendo Ollama local"
        Start-Process -FilePath $ollama -ArgumentList @("serve") -WindowStyle Hidden | Out-Null
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            Start-Sleep -Milliseconds 500
            $probe = Invoke-NativeCapture $ollama @("list")
            if ($probe.ExitCode -eq 0) { break }
        }
    }
    if ($probe.ExitCode -ne 0) { throw "Ollama esta instalado pero su API local no responde." }
    return $ollama
}

function Get-SoulComponentInventory {
    $python = Find-Python
    $ollama = Find-Ollama
    $codex = Get-Command "codex" -ErrorAction SilentlyContinue
    $claude = Get-Command "claude" -ErrorAction SilentlyContinue
    $claudeApp = @(Resolve-ClaudeAppParentBinaries)
    return [pscustomobject]@{
        Python = [bool]$python
        PythonSource = $(if ($python) { "{0} {1}" -f $python.Exe, (@($python.Args) -join " ") } else { "missing" })
        SoulVenv = (Test-Path -LiteralPath (Join-Path $Venv "Scripts\python.exe") -PathType Leaf)
        Ollama = [bool]$ollama
        Codex = [bool]$codex
        Claude = ([bool]$claude -or $claudeApp.Count -gt 0)
    }
}

function Get-SoulInstallPlan([pscustomobject]$Inventory) {
    return [pscustomobject][ordered]@{
        Python = $(if ($Inventory.Python) { "skip" } else { "install" })
        SoulVenv = $(if ($Inventory.SoulVenv) { "reuse" } else { "create" })
        Ollama = $(if ($Inventory.Ollama) { "skip" } else { "install" })
        Codex = $(if ($Inventory.Codex) { "verify-or-wire" } else { "hot-ready" })
        Claude = $(if ($Inventory.Claude) { "verify-or-wire" } else { "hot-ready" })
    }
}

function Show-SoulComponentInventory([pscustomobject]$Inventory, [pscustomobject]$Plan) {
    Step "Inventario previo: reutilizo lo presente y descargo solo lo ausente"
    Write-Host ("  Python={0} ({1}) · venv={2} · Ollama={3} · Codex={4} · Claude={5}" -f `
        $Inventory.Python, $Inventory.PythonSource, $Inventory.SoulVenv,
        $Inventory.Ollama, $Inventory.Codex, $Inventory.Claude)
    Write-Host ("  Plan: Python={0} · venv={1} · Ollama={2} · Codex={3} · Claude={4}" -f `
        $Plan.Python, $Plan.SoulVenv, $Plan.Ollama, $Plan.Codex, $Plan.Claude)
}

function Stop-SoulMcpForUpgrade([string]$VenvPath) {
    $target = [IO.Path]::GetFullPath((Join-Path $VenvPath "Scripts\soul-mcp-stdio.exe"))
    $stopped = 0
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='soul-mcp-stdio.exe'" -ErrorAction SilentlyContinue)
    foreach ($process in $processes) {
        $observed = [string]$process.ExecutablePath
        if ($observed -and [IO.Path]::GetFullPath($observed).Equals($target, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
            Wait-Process -Id ([int]$process.ProcessId) -Timeout 10 -ErrorAction SilentlyContinue
            $stopped++
        }
    }
    $stillRunning = @(
        Get-CimInstance Win32_Process -Filter "Name='soul-mcp-stdio.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -and
                [IO.Path]::GetFullPath([string]$_.ExecutablePath).Equals($target, [StringComparison]::OrdinalIgnoreCase)
            }
    )
    if ($stillRunning.Count -gt 0) {
        throw "HOLD: el MCP local sigue usando los bytes que deben actualizarse"
    }
    if ($stopped -gt 0) { Step "MCP local detenido de forma acotada para actualizar sus bytes" }
}

function Test-ExactBundledInstall(
    [string]$Python, [string]$PlatformWheel, [string]$PlatformHash,
    [string]$CoreWheel, [string]$CoreHash
) {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { return $false }
    $probe = @'
import base64, csv, hashlib, importlib.metadata as m
import io, json, pathlib, sys, urllib.parse

for name, expected_version, wheel, expected_hash in (
    ('soul-platform', '0.5.9', sys.argv[1], sys.argv[2]),
    ('soul-framework', '0.4.3', sys.argv[3], sys.argv[4]),
):
    if m.version(name) != expected_version:
        raise SystemExit(2)
    distribution = m.distribution(name)
    direct = json.loads(distribution.read_text('direct_url.json'))
    url = str(direct.get('url') or '')
    if urllib.parse.urlsplit(url).scheme != 'file':
        raise SystemExit(3)
    hashes = (direct.get('archive_info') or {}).get('hashes') or {}
    observed = str(hashes.get('sha256') or '').removeprefix('sha256=').lower()
    if observed != expected_hash.lower():
        raise SystemExit(5)
    record = distribution.read_text('RECORD')
    if not record:
        raise SystemExit(6)
    for relative, encoded_hash, encoded_size in csv.reader(io.StringIO(record)):
        if not encoded_hash:
            continue
        algorithm, expected = encoded_hash.split('=', 1)
        if algorithm != 'sha256':
            continue
        installed = pathlib.Path(distribution.locate_file(relative))
        if not installed.is_file():
            raise SystemExit(7)
        payload = installed.read_bytes()
        actual = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode()
        if actual != expected or (encoded_size and len(payload) != int(encoded_size)):
            raise SystemExit(8)
'@
    $result = Invoke-NativeCapture $Python @(
        "-c", $probe, $PlatformWheel, $PlatformHash, $CoreWheel, $CoreHash
    )
    return $result.ExitCode -eq 0
}

$initialInventory = Get-SoulComponentInventory
$initialPlan = Get-SoulInstallPlan $initialInventory
Show-SoulComponentInventory $initialInventory $initialPlan
$launcher = Ensure-Python
Good "Python detectado"
$resolvedPackageSource = Resolve-PackageSource
$resolvedPackageIsBundled = Test-Path -LiteralPath $resolvedPackageSource -PathType Leaf
$resolvedInstallSpec = "${resolvedPackageSource}[desktop]"
$venvPython = Join-Path $Venv "Scripts\python.exe"
$soulRoot = Join-Path $env:LOCALAPPDATA "SOUL"
$soulConfig = Join-Path $soulRoot "proxy.toml"
$soulDb = Join-Path $soulRoot "MachineSoul.db"
$candidate = Join-Path $soulRoot "MachineSoul.bge-m3.candidate.db"
$checkpoint = Join-Path $soulRoot "MachineSoul.bge-m3.checkpoint.json"
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
        Mark-Installed "venv SOUL"
    } else {
        Skip "entorno aislado ya existe y es utilizable"
        Mark-Skipped "venv SOUL (presente)"
    }
    Stop-SoulMcpForUpgrade $Venv
    $pipProbe = Invoke-NativeCapture $venvPython @("-m", "pip", "--version")
    if ($pipProbe.ExitCode -ne 0) {
        Step "pip falta en el venv; instalando con ensurepip"
        Invoke-Checked $venvPython @("-m", "ensurepip", "--upgrade")
    } else {
        Skip "pip ya existe dentro del entorno aislado"
    }
    $exactBundleInstalled = $false
    if ($resolvedPackageIsBundled) {
        $exactBundleInstalled = Test-ExactBundledInstall `
            $venvPython $resolvedPackageSource $BundledPlatformHash $BundledCoreWheel $BundledCoreHash
    }
    if ($exactBundleInstalled) {
        Skip "SOUL Platform 0.5.9 + Core 0.4.3 ya coinciden byte a byte con el bundle"
        Mark-Skipped "SOUL Platform/Core (bytes exactos presentes)"
        $dependencyProbe = Invoke-NativeCapture $venvPython @("-m", "pip", "check")
        if ($dependencyProbe.ExitCode -ne 0) {
            Step "Reparando solo dependencias ausentes o incompatibles"
            Invoke-Checked $venvPython @(
                "-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, $resolvedInstallSpec
            )
            Mark-Installed "dependencias Python reparadas"
        } else {
            Skip "todas las dependencias Python ya estan satisfechas"
            Mark-Skipped "dependencias Python (satisfechas)"
        }
    } elseif ($resolvedPackageIsBundled) {
        Step "Instalando SOUL Platform dentro del entorno aislado"
        # Install the exact hash-verified Core bytes first.  Merely offering a
        # --find-links directory still allows an index candidate with the same
        # version to win dependency resolution.
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, $resolvedInstallSpec)
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, "pystray==0.19.5", "pillow==12.3.0")
        Good "Dependencias Python instaladas desde wheelhouse, sin PyPI"
        Mark-Installed "SOUL Platform/Core"
    } else {
        Step "Instalando SOUL Platform dentro del entorno aislado"
        Invoke-Checked $venvPython @("-m", "pip", "install", "--upgrade", $resolvedInstallSpec)
        Mark-Installed "SOUL Platform/Core"
    }
    if ($resolvedPackageIsBundled -and -not $exactBundleInstalled) {
        # `pip --upgrade` skips a local wheel when the same version is already
        # present. Reinstall only this package so updates with an unchanged
        # semantic version still load the exact verified bundle bytes.
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, "--force-reinstall", "--no-deps", $resolvedPackageSource)
        Invoke-Checked $venvPython @("-m", "pip", "install", "--no-index", "--find-links", $PSScriptRoot, "--force-reinstall", "--no-deps", $BundledCoreWheel)
    }
}

if (-not (Test-Path $venvPython)) { throw "No existe un entorno SOUL verificable en $Venv" }
Invoke-Checked $venvPython @("-c", "import soul_platform, soul_framework")
Invoke-Checked $venvPython @("-m", "pip", "check")
$installedVersion = & $venvPython -c "from importlib.metadata import version; print(version('soul-platform'))"
if ($LASTEXITCODE -ne 0) { throw "No pude leer la version instalada de soul-platform" }
if ([version]$installedVersion.Trim() -ne [version]"0.5.9") {
    throw "Se requiere soul-platform 0.5.9 exacto; quedo instalada $installedVersion"
}

$installedCoreVersion = & $venvPython -c "import importlib.metadata as m; print(m.version('soul-framework'))"
if ($LASTEXITCODE -ne 0 -or $installedCoreVersion.Trim() -ne "0.4.3") {
    throw "Se requiere soul-framework 0.4.3 exacto; quedo instalada $installedCoreVersion"
}
if ($resolvedPackageIsBundled) {
    $provenanceCheck = "import importlib.metadata as m,json,sys,urllib.parse; name,wheel,expected=sys.argv[1:]; d=json.loads(m.distribution(name).read_text('direct_url.json')); url=str(d.get('url') or ''); assert urllib.parse.urlsplit(url).scheme=='file'; hashes=(d.get('archive_info') or {}).get('hashes') or {}; observed=str(hashes.get('sha256') or '').removeprefix('sha256=').lower(); assert observed==expected.lower()"
    Invoke-Checked $venvPython @("-c", $provenanceCheck, "soul-platform", $resolvedPackageSource, $BundledPlatformHash)
    Invoke-Checked $venvPython @("-c", $provenanceCheck, "soul-framework", $BundledCoreWheel, $BundledCoreHash)
    Good "Procedencia PEP 610 y hashes del bundle verificados"
}

if (-not $NoMachine) {
$ollamaExe = Ensure-Ollama
$ollamaList = @(& $ollamaExe list 2>$null)
$bgeInstalled = @($ollamaList | Where-Object { $_ -match '^bge-m3(:latest)?\s' }).Count -gt 0
if (-not $bgeInstalled) {
    if ($Check) { throw "Falta el modelo local bge-m3. Ejecuta el instalador sin -Check para instalarlo." }
    Step "Instalando BGE-M3 local para memoria multilingue"
    Invoke-Checked $ollamaExe @("pull", "bge-m3")
    Mark-Installed "BGE-M3"
} else {
    Skip "BGE-M3 ya existe"
    Mark-Skipped "BGE-M3 (presente)"
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
$autowire = Join-Path $Venv "Scripts\soul-autowire.exe"
if (-not (Test-Path $autowire)) { throw "Falta soul-autowire.exe en el paquete instalado" }
$soulMcp = Join-Path $Venv "Scripts\soul-mcp-stdio.exe"
if (-not (Test-Path $soulMcp)) { throw "Falta soul-mcp-stdio.exe en el paquete instalado" }
$soulCodexSessionStart = Join-Path $Venv "Scripts\soul-codex-session-start.exe"
if (-not (Test-Path $soulCodexSessionStart)) { throw "Falta soul-codex-session-start.exe en el paquete instalado" }
$doctor = Join-Path $Venv "Scripts\soul-machine-doctor.exe"
if (-not (Test-Path $doctor)) { throw "Falta soul-machine-doctor.exe en el paquete instalado" }
$trayCli = Join-Path $Venv "Scripts\soul-tray-cli.exe"
if (-not $NoTray -and -not (Test-Path $trayCli)) { throw "Falta soul-tray-cli.exe en el paquete instalado" }

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

if (-not $Check -and -not $NoMachine -and (Test-Path -LiteralPath $soulConfig -PathType Leaf)) {
    Step "Actualizando el contrato T5 sin mover identidad, embeddings ni recuerdos"
    Invoke-Checked $machine @("upgrade-config", "--config", $soulConfig)
    Good "Contrato de memoria actualizado con backup reversible"
}

if (-not $Check -and -not $NoMachine) {
    if (-not $Model -and $legacyModel) { $Model = $legacyModel }
    if (-not $Model -and $Kind -eq "ollama") {
        $modelLine = @(& $ollamaExe list 2>$null | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^bge-m3(:latest)?\s' } | Select-Object -First 1)
        if ($modelLine.Count -gt 0) { $Model = (($modelLine[0] -split '\s+')[0]) }
    }
    if (-not $Model -and $Kind -eq "ollama" -and $BootstrapModel) {
        Step "No hay cerebro generativo local; instalando el modelo minimo $BootstrapModel"
        Invoke-Checked $ollamaExe @("pull", $BootstrapModel)
        $Model = $BootstrapModel
        Mark-Installed "cerebro local $BootstrapModel"
    }
    if ($Model) {
        Step "Inicializando alma persistente con cerebro ${Kind}:$Model"
        if ($cutoverActivated) { Step "Rollback byte-exacto armado si falla el runtime BGE" }
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
        if (-not $NoTray) { Invoke-Checked $trayCli @("--headless-check") }
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

if (-not $NoMachine) {
    if ($Check) {
        Invoke-Checked $autowire @("--help")
    } else {
        if ($TrustCurrentOllama) {
            Step "Atestando el proceso Ollama vivo por autorizacion del propietario"
            Invoke-Checked $autowire @("--root", $soulRoot, "trust-current-ollama")
            Good "Runtime Ollama ligado a propietario y hash ejecutable"
        }
        Step "Detectando cerebros locales sin cambiar el cerebro activo"
        Invoke-Checked $autowire @("--root", $soulRoot, "reconcile")
        Invoke-Checked $autowire @("--root", $soulRoot, "install-autostart")
        Invoke-Checked $autowire @("--root", $soulRoot, "status")
        Good "AutoWire en shadow, per-user y con embeddings BGE-M3 bloqueados"
    }
}

if (-not $NoMachine -and -not $Check) {
    Step "Cableando SOUL local por las superficies MCP oficiales"
    $wiredClients = @(Install-SoulClientMcp $soulMcp $soulConfig)
    if ($wiredClients.Count -eq 0) {
        Write-Warning "No detecte Codex CLI ni Claude Code; SOUL queda Hot-Ready para cablearlos cuando aparezcan."
    } else {
        Good ("Clientes SOUL verificados: " + ($wiredClients -join ", "))
        if ($wiredClients -contains "codex") {
            $codexHooks = Install-CodexSessionStartHook $soulCodexSessionStart $soulMcp $soulConfig
            Good "Codex SessionStart cableado: SOUL se carga antes del primer mensaje"
            Write-Warning "Codex pedira confiar una sola vez en el hook local de $codexHooks; revisalo en /hooks. Despues arranca automatico."
        }
    }
}

if (-not $NoMachine -and -not $Check) {
    Step "Cerrando ACL de identidad, memoria, tokens y grants al usuario actual"
    Set-SoulPrivateAcl $soulRoot
    foreach ($sensitive in @(
        $soulConfig,
        $soulDb,
        (Join-Path $soulRoot "proxy.token"),
        (Join-Path $soulRoot "client-grants.json"),
        (Join-Path $soulRoot "autowire.sqlite3")
    )) { Set-SoulPrivateAcl $sensitive }
    Good "ACL Windows privada verificada (usuario actual + SYSTEM)"
}

$installReceipt = Write-InstallReceipt $soulRoot "verified"
Good "Recibo de instalacion: $installReceipt"
Write-Host "SOUL listo. Datos persistentes: $env:LOCALAPPDATA\SOUL" -ForegroundColor Green
