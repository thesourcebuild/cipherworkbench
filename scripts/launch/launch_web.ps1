<#
.SYNOPSIS
Starts the web app's dev server and opens it in the default browser.

.PARAMETER Port
Port for the dev server. Default 3000.

.EXAMPLE
.\scripts\launch\launch_web.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 3000
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"

$root = Get-RepoRoot
Clear-InheritedElectronEnv
Assert-Dependencies -RepoRoot $root

Push-Location $root
try {
    if (Test-PortOpen -Port $Port) {
        Write-Warn "Something is already listening on port $Port."
        Write-Note 'That is probably a dev server from an earlier run. Opening it anyway.'
        Start-Process "http://localhost:$Port"
        return
    }

    Write-Step "Starting the dev server on http://localhost:$Port"
    Write-Note 'Press Ctrl+C to stop.'

    # Opened before the server is up on purpose: Next takes a few seconds, and the
    # browser's own retry is friendlier than waiting on a port poll here.
    Start-Process "http://localhost:$Port"

    Invoke-Pnpm web
}
finally {
    Pop-Location
}
