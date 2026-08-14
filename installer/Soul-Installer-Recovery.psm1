Set-StrictMode -Version Latest

function Invoke-SoulPostActivateRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Machine,
        [Parameter(Mandatory = $true)][string]$Cutover,
        [Parameter(Mandatory = $true)][string]$SoulConfig,
        [Parameter(Mandatory = $true)][string]$Checkpoint,
        [Parameter(Mandatory = $true)][string]$SoulRoot,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$Model,
        [Parameter(Mandatory = $true)][bool]$CutoverActivated,
        [Parameter(Mandatory = $true)][scriptblock]$Runner
    )

    try {
        & $Runner $Machine @("init", "--kind", $Kind, "--base-url", $BaseUrl, "--model", $Model)
    } catch {
        if ($CutoverActivated) {
            try {
                & $Runner $Cutover @("rollback", $SoulConfig, $Checkpoint)
                & $Runner $Machine @("init", "--root", $SoulRoot, "--kind", $Kind, "--base-url", $BaseUrl, "--model", $Model)
            } catch {
                throw "HOLD CRITICO: runtime nuevo fallo y no pude completar rollback + restart legacy. Datos preservados en $SoulRoot"
            }
            throw "El runtime BGE no inicio; restaure y reactive el alma legacy"
        }
        throw
    }
}

Export-ModuleMember -Function Invoke-SoulPostActivateRuntime
