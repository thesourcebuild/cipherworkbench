<#
.SYNOPSIS
Builds everything: the web export and the desktop bundle.

.DESCRIPTION
The release path. With -Verify it runs the full quality gate first - the script check,
typecheck, lint and the test suite - and stops before building if any of them fail, so
a broken tree never produces artifacts that look shippable.

.PARAMETER Clean
Delete build output first and bypass the Turborepo cache.

.PARAMETER Verify
Run the script check, typecheck, lint and tests before building. Use this for a
release build.

.PARAMETER Smoke
After building, check the packaged desktop bundle actually loads.

.PARAMETER Package
Also build the Windows installer (the setup .exe) into dist/<version>/.

.PARAMETER Arch
Architectures to package. Default x64. Ignored without -Package.

.PARAMETER OutDir
Base output directory for -Package. Default: dist/ at the repo root.

.PARAMETER StagingDir
Where electron-builder works. Default: a folder under TEMP.

.EXAMPLE
.\scripts\build-helpers\build_all.ps1
.EXAMPLE
.\scripts\build-helpers\build_all.ps1 -Clean -Verify -Smoke
.EXAMPLE
.\scripts\build-helpers\build_all.ps1 -Verify -Package -Arch x64,arm64
#>
[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Verify,
    [switch]$Smoke,
    [switch]$Package,
    [ValidateSet('x64', 'arm64')]
    [string[]]$Arch = @('x64'),
    [string]$OutDir,
    [string]$StagingDir
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"

$root = Get-RepoRoot
Clear-InheritedElectronEnv
Assert-Dependencies -RepoRoot $root

Push-Location $root
try {
    if ($Verify) {
        # First because it is instant, and because a script that does not parse under
        # 5.1 makes every other step here unreachable on a machine without pwsh.
        Write-Step 'Checking the scripts are ASCII and parse under both PowerShell versions'
        & "$PSScriptRoot\..\check_scripts.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'Script check failed.' }

        Write-Step 'Typechecking every package and tests/'
        Invoke-Pnpm typecheck

        Write-Step 'Linting'
        Invoke-Pnpm lint

        Write-Step 'Running tests'
        Invoke-Pnpm test

        Write-Host 'Gate passed.' -ForegroundColor Green
    }

    if ($Clean) {
        Write-Step 'Cleaning previous output'
        Remove-BuildOutput -RepoRoot $root
    }

    Write-Step 'Building web and desktop'
    Write-Note 'Turborepo orders the web export before the desktop renderer copy.'
    $turboArgs = @('run', 'build')
    if ($Clean) { $turboArgs += '--force' }
    Invoke-Pnpm exec turbo @turboArgs

    Show-Artifacts -RepoRoot $root -Paths @(
        'apps\web\out'
        'apps\desktop\renderer'
        'apps\desktop\dist'
    )

    if ($Smoke) {
        Write-Step 'Verifying the built desktop app loads'
        Invoke-Pnpm --filter '@ocs/desktop' smoke
        Write-Host 'Smoke check passed.' -ForegroundColor Green
    }

    if ($Package) {
        # One packaging path for the whole project. -NoBuild because the build above
        # already produced everything create-package needs.
        Write-Step 'Creating the installer'
        $forward = @{ Binary = $true; NoBuild = $true; Arch = $Arch }
        if ($OutDir) { $forward.OutDir = $OutDir }
        if ($StagingDir) { $forward.StagingDir = $StagingDir }
        & "$PSScriptRoot\..\package\create-package.ps1" @forward
    }
    else {
        Write-Host 'Run with -Package to produce the installer.' -ForegroundColor DarkGray
    }
}
finally {
    Pop-Location
}
