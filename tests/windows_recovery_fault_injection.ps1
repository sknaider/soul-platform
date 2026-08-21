param([Parameter(Mandatory = $true)][string]$ModulePath)

$ErrorActionPreference = "Stop"
Import-Module -Name $ModulePath -Force
$events = [System.Collections.Generic.List[string]]::new()
$runner = {
    param([string]$File, [string[]]$Arguments)
    $events.Add("$File|$($Arguments -join ' ')")
    if ($File -eq "machine.exe" -and $Arguments.Count -gt 0 -and $Arguments[0] -eq "init" -and -not ($Arguments -contains "--root")) {
        throw "fault-injected new runtime failure"
    }
}

$failedClosed = $false
try {
    Invoke-SoulPostActivateRuntime `
        -Machine "machine.exe" `
        -Cutover "cutover.exe" `
        -SoulConfig "C:\SOUL\proxy.toml" `
        -Checkpoint "C:\SOUL\checkpoint.json" `
        -SoulRoot "C:\SOUL" `
        -Kind "ollama" `
        -BaseUrl "http://127.0.0.1:11434/v1" `
        -Model "brain" `
        -CutoverActivated $true `
        -Runner $runner
} catch {
    if ($_.Exception.Message -eq "El runtime BGE no inicio; restaure y reactive el alma legacy") {
        $failedClosed = $true
    } else {
        throw
    }
}

if (-not $failedClosed) { throw "fault injection did not return a failure" }
if ($events.Count -ne 3) { throw "expected 3 lifecycle calls, got $($events.Count)" }
if ($events[0] -notmatch '^machine\.exe\|init --kind ollama') { throw "new runtime was not attempted first" }
if ($events[1] -ne 'cutover.exe|rollback C:\SOUL\proxy.toml C:\SOUL\checkpoint.json') { throw "rollback was not second" }
if ($events[2] -notmatch '^machine\.exe\|init --root C:\\SOUL --kind ollama') { throw "legacy runtime was not restarted third" }

$events.Clear()
$freshRunner = {
    param([string]$File, [string[]]$Arguments)
    $events.Add("$File|$($Arguments -join ' ')")
}
Invoke-SoulPostActivateRuntime `
    -Machine "machine.exe" `
    -Cutover "cutover.exe" `
    -SoulConfig "C:\SOUL\proxy.toml" `
    -Checkpoint "" `
    -SoulRoot "C:\SOUL" `
    -Kind "ollama" `
    -BaseUrl "http://127.0.0.1:11434/v1" `
    -Model "brain" `
    -CutoverActivated $false `
    -Runner $freshRunner
if ($events.Count -ne 1) { throw "fresh install expected one init call, got $($events.Count)" }
if ($events[0] -notmatch '^machine\.exe\|init --kind ollama') { throw "fresh runtime was not initialized" }

Write-Output "WINDOWS_RECOVERY_FAULT_INJECTION_OK rollback_events=3 fresh_events=$($events.Count)"
