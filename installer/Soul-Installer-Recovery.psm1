Set-StrictMode -Version Latest

function Invoke-SoulPostActivateRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Machine,
        [Parameter(Mandatory = $true)][string]$Cutover,
        [Parameter(Mandatory = $true)][string]$SoulConfig,
        # Fresh installs have no embedding-cutover checkpoint.  The value is
        # only consumed by the rollback branch when CutoverActivated is true,
        # so rejecting an empty string prevents a clean machine from reaching
        # `soul-machine init` at all.
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Checkpoint,
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
