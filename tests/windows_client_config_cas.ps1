param([Parameter(Mandatory=$true)][string]$InstallerPath)

$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $InstallerPath, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw "installer parse failed" }
$wanted = @("Get-OptionalFileHash", "Restore-ClientConfigCas")
$functions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $wanted -contains $node.Name
}, $true))
if ($functions.Count -ne 2) { throw "CAS functions not found" }
foreach ($function in $functions) { Invoke-Expression $function.Extent.Text }

$root = Join-Path ([IO.Path]::GetTempPath()) ("soul-cas-" + [guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $path = Join-Path $root "config.toml"
    $backup = Join-Path $root "config.bak"

    # A -> B -> A: our own add is rolled back byte-exactly without a CLI
    # reserialization step C.
    [IO.File]::WriteAllText($path, "A-before`n")
    [IO.File]::Copy($path, $backup)
    $before = Get-OptionalFileHash $path
    [IO.File]::WriteAllText($path, "B-post-add`n")
    $postAdd = Get-OptionalFileHash $path
    Restore-ClientConfigCas $path $backup $before $postAdd "test config"
    if ([IO.File]::ReadAllText($path) -ne "A-before`n") { throw "A was not restored" }

    # A -> B -> D: a concurrent writer is preserved and produces HOLD.
    [IO.File]::WriteAllText($path, "A-before`n")
    [IO.File]::Copy($path, $backup, $true)
    $before = Get-OptionalFileHash $path
    [IO.File]::WriteAllText($path, "B-post-add`n")
    $postAdd = Get-OptionalFileHash $path
    [IO.File]::WriteAllText($path, "D-concurrent`n")
    $held = $false
    try { Restore-ClientConfigCas $path $backup $before $postAdd "test config" }
    catch { $held = $_.Exception.Message -match "cambio concurrentemente" }
    if (-not $held) { throw "concurrent D was not rejected" }
    if ([IO.File]::ReadAllText($path) -ne "D-concurrent`n") { throw "concurrent D was overwritten" }

    # Missing A -> B -> missing A: an installer-created config is removed only
    # while its bytes are still the exact post-add bytes.
    [IO.File]::Delete($path)
    $before = Get-OptionalFileHash $path
    [IO.File]::WriteAllText($path, "B-created`n")
    $postAdd = Get-OptionalFileHash $path
    Restore-ClientConfigCas $path $null $before $postAdd "test config"
    if ([IO.File]::Exists($path)) { throw "installer-created config survived rollback" }

    Write-Output "WINDOWS_CLIENT_CONFIG_CAS_OK exact=1 concurrent_preserved=1 missing_restored=1"
} finally {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}
