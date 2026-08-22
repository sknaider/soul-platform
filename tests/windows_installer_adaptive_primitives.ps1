param([Parameter(Mandatory = $true)][string]$InstallerPath)

$ErrorActionPreference = "Stop"
$source = Get-Content -LiteralPath $InstallerPath -Raw
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $source,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {
    throw "production installer does not parse: $($errors[0].Message)"
}

foreach ($functionName in @("Move-SoulAtomicFile", "Write-InstallReceipt", "Get-SoulInstallPlan")) {
    $matches = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
    }, $true))
    if ($matches.Count -ne 1) { throw "expected exactly one production function $functionName" }
    . ([ScriptBlock]::Create($matches[0].Extent.Text))
}

$env:LOCALAPPDATA = Join-Path ([IO.Path]::GetTempPath()) ("soul-adaptive-" + [Guid]::NewGuid().ToString("N"))
$env:COMPUTERNAME = "SOUL-CANARY"
$env:USERNAME = "william"
$script:InstalledComponents = [System.Collections.Generic.List[string]]::new()
$script:SkippedComponents = [System.Collections.Generic.List[string]]::new()
$root = Join-Path $env:LOCALAPPDATA "SOUL"

$script:InstalledComponents.Add("first")
$first = Write-InstallReceipt $root "verified"
$firstPayload = Get-Content -LiteralPath $first -Raw | ConvertFrom-Json
if ($firstPayload.platform_version -ne "0.5.9") { throw "first receipt version mismatch" }

$script:InstalledComponents.Clear()
$script:InstalledComponents.Add("second")
$second = Write-InstallReceipt $root "verified"
$secondPayload = Get-Content -LiteralPath $second -Raw | ConvertFrom-Json
if (@($secondPayload.installed) -notcontains "second") { throw "second receipt did not replace first" }

$backups = @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA "SOUL\atomic-backups") -Filter "install-receipt-*.bak" -File)
if ($backups.Count -ne 1) { throw "idempotent replacement did not preserve exactly one previous receipt" }
$backupPayload = Get-Content -LiteralPath $backups[0].FullName -Raw | ConvertFrom-Json
if (@($backupPayload.installed) -notcontains "first") { throw "atomic backup did not preserve previous bytes" }

if ($source -notmatch 'struct\.calcsize\(chr\(80\)\)\*8') { throw "PowerShell 5.1-safe Python probe missing" }
if ($source -match 'File\]::Replace\([^\r\n]+\$null') { throw "null File.Replace backup regressed" }
if ($source -notmatch 'No MCP server \(\?:found\|named\)') { throw "Claude missing-server compatibility missing" }

$profiles = @(
    @{ Name = "clean"; Inventory = [pscustomobject]@{ Python=$false; SoulVenv=$false; Ollama=$false; Codex=$false; Claude=$false }; Expected="install|create|install|hot-ready|hot-ready" },
    @{ Name = "partial"; Inventory = [pscustomobject]@{ Python=$true; SoulVenv=$false; Ollama=$false; Codex=$true; Claude=$false }; Expected="skip|create|install|verify-or-wire|hot-ready" },
    @{ Name = "complete"; Inventory = [pscustomobject]@{ Python=$true; SoulVenv=$true; Ollama=$true; Codex=$true; Claude=$true }; Expected="skip|reuse|skip|verify-or-wire|verify-or-wire" },
    @{ Name = "rerun"; Inventory = [pscustomobject]@{ Python=$true; SoulVenv=$true; Ollama=$true; Codex=$true; Claude=$true }; Expected="skip|reuse|skip|verify-or-wire|verify-or-wire" }
)
foreach ($profile in $profiles) {
    $plan = Get-SoulInstallPlan $profile.Inventory
    $observed = @($plan.Python, $plan.SoulVenv, $plan.Ollama, $plan.Codex, $plan.Claude) -join "|"
    if ($observed -ne $profile.Expected) { throw "$($profile.Name) plan mismatch: $observed" }
}

Write-Output "WINDOWS_ADAPTIVE_PRIMITIVES_OK reruns=2 backups=$($backups.Count) profiles=$($profiles.Count)"
