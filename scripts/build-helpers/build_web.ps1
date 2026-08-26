<#
.SYNOPSIS
Builds the web app.

.DESCRIPTION
Produces the Next.js static export in apps/web/out. That directory is the entire web
deliverable - drop it on any static host. It is also exactly what the desktop shell
serves over its app:// protocol, so this is the shared half of both builds.

.PARAMETER Clean
Delete build output first and bypass the Turborepo cache.

.PARAMETER Serve
Serve the finished export so you can check it before deploying.

.PARAMETER Port
Port for -Serve. Default 3000.

.EXAMPLE
.\scripts\build-helpers\build_web.ps1
.EXAMPLE
.\scripts\build-helpers\build_web.ps1 -Clean
.EXAMPLE
.\scripts\build-helpers\build_web.ps1 -Serve
#>
[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Serve,
    [int]$Port = 3000
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"

$root = Get-RepoRoot
Clear-InheritedElectronEnv
Assert-Dependencies -RepoRoot $root

Push-Location $root
try {
    if ($Clean) {
        Write-Step 'Cleaning previous output'
        Remove-BuildOutput -RepoRoot $root
    }

    Write-Step 'Building the static export'
    # --filter=@ocs/web... also builds everything web depends on, which here is the
    # whole packages/ tree.
    $turboArgs = @('run', 'build', '--filter=@ocs/web...')
    if ($Clean) { $turboArgs += '--force' }
    Invoke-Pnpm exec turbo @turboArgs

    Show-Artifacts -RepoRoot $root -Paths @('apps\web\out')
    Write-Host 'Deploy apps/web/out to any static host.' -ForegroundColor Green

    if ($Serve) {
        if (Test-PortOpen -Port $Port) {
            Write-Warn "Port $Port is already in use; not serving."
            return
        }
        Write-Step "Serving apps/web/out on http://localhost:$Port"
        Write-Note 'Press Ctrl+C to stop.'
        # Serving it rather than opening the file is not a nicety here. Under file://
        # the export resolves its asset paths against the filesystem root and loads
        # dead, and some browsers withhold crypto.subtle outside a secure context -
        # which would take RSA and every random byte with it.
        #
        # npx rather than a tracked dependency: this is for eyeballing a build, not
        # part of the product.
        & npx --yes serve@14 'apps/web/out' --listen $Port --single
    }
}
finally {
    Pop-Location
}
