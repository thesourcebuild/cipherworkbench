<#
.SYNOPSIS
Creates a shareable release package.

.DESCRIPTION
Produces dist/<version>/ containing everything a recipient needs and nothing they do
not: the web app as a static zip, the Windows installer, a SHA256SUMS.txt so the
download can be verified, and a RELEASE.md explaining each file. Copy or upload that
folder, or pass -Zip for a single archive.

electron-builder's own output also contains win-unpacked and build intermediates -
several hundred megabytes of unpacked Electron runtime - so it works in a staging
directory outside the repo and only the installers are collected. That also sidesteps
antivirus locking the extracted Electron binaries, which otherwise fails the build with
"EPERM: rename ... win-unpacked.tmp".

.PARAMETER Source
Package the source: a buildable archive of the project.

.PARAMETER Binary
Package the built artifacts: the web static zip and the Windows installer.

.PARAMETER Release
Both of the above - the complete set you would attach to a release. This is the default
when none of the three is given.

.PARAMETER Verify
Run the script check, typecheck, lint and tests first, plus the packaged-app smoke
test, and stop if any fail. Use this for anything you actually intend to share.

.PARAMETER NoBuild
Package existing build output instead of rebuilding. Fails if it is missing.

.PARAMETER Arch
Architectures to build installers for. Default x64.

.PARAMETER OutDir
Base output directory. Default: dist/ at the repo root. The release lands in
<OutDir>/<version>/.

.PARAMETER StagingDir
Where electron-builder works. Default: a versioned folder in TEMP.

.PARAMETER Zip
Also produce cipherworkbench-<version>.zip containing the whole release folder.

.PARAMETER Version
Overrides the version. Default: the root `version` file, which is the single source of truth --
see Get-ProjectVersion in lib/common.ps1. An override is written into the workspace manifests too,
so an installer never disagrees with the folder it sits in.

.EXAMPLE
.\scripts\package\create-package.ps1 -Release -Verify

.EXAMPLE
.\scripts\package\create-package.ps1 -Source

.EXAMPLE
.\scripts\package\create-package.ps1 -Binary -Arch x64,arm64
#>
[CmdletBinding()]
param(
    [switch]$Source,
    [switch]$Binary,
    [switch]$Release,
    [switch]$Verify,
    [switch]$NoBuild,
    [ValidateSet('x64', 'arm64')]
    [string[]]$Arch = @('x64'),
    [string]$OutDir,
    [string]$StagingDir,
    [switch]$Zip,
    [string]$Version
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"

$root = Get-RepoRoot
Clear-InheritedElectronEnv
Assert-Dependencies -RepoRoot $root

# The root `version` file is the single source of truth, and the manifests are brought in line
# before anything is archived: the source zip carries them, and `npm_package_version` reaches the
# builds through whichever one the runner was launched in. An explicit -Version wins over the file
# for everything, including that sync, so a one-off build cannot name its installer after one
# version and its folder after another.
$Version = Sync-PackageJsonVersions -RepoRoot $root -VersionOverride $Version
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }
if (-not $StagingDir) {
    $StagingDir = Join-Path ([System.IO.Path]::GetTempPath()) "cipherworkbench-package-$Version"
}

# -Release is source + binary. With nothing specified, produce the full release - the
# useful default for a bare invocation. -Source and -Binary also compose, so
# `-Source -Binary` is equivalent to `-Release`.
$doSource = $Source -or $Release
$doBinary = $Binary -or $Release
if (-not ($doSource -or $doBinary)) { $doSource = $true; $doBinary = $true }

# Named $releaseDir, not $release: PowerShell variable names are case-insensitive, so a
# local $release IS the -Release switch parameter, and assigning a path to it fails with
# "Cannot convert String to SwitchParameter" from a line that looks blameless.
$releaseDir = Join-Path $OutDir $Version
$sourceZipName = "cipherworkbench-$Version-source.zip"
$webZipName = "cipherworkbench-web-$Version.zip"

Push-Location $root
try {
    # ---------------------------------------------------------------- gate
    if ($Verify) {
        # The script check first: it is instant, and these scripts ship inside the
        # source archive, where a PS7-only or non-ASCII slip only fails on someone
        # else's machine.
        Write-Step 'Checking the scripts parse under both PowerShell versions'
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
    else {
        Write-Warn 'Quality gate skipped. Use -Verify for anything you will share.'
    }

    # Start from empty so an artifact from an earlier version cannot ship by accident.
    if (Test-Path $releaseDir) {
        Write-Step "Clearing $releaseDir"
        Remove-Item -LiteralPath $releaseDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

    # ---------------------------------------------------------------- source
    # Archived before anything is built, so build output cannot leak into it even if the
    # exclusion list is ever wrong.
    if ($doSource) {
        Write-Step "Packaging the source -> $sourceZipName"
        $method = New-SourceArchive -RepoRoot $root -ZipPath (Join-Path $releaseDir $sourceZipName)
        Write-Note $method
    }

    if (-not $doBinary) {
        Write-Note 'Source only - skipping the build and the binaries.'
    }

    # ---------------------------------------------------------------- build
    if ($doBinary -and -not $NoBuild) {
        # The desktop build produces the web export as a prerequisite, so one turbo
        # invocation covers both halves of the binary package.
        Write-Step 'Building'
        Invoke-Pnpm exec turbo run build --filter=@ocs/desktop...
    }

    # The smoke test needs a build, so it cannot run in the gate above. It is the only
    # check that exercises the packaged renderer, and shipping an installer that has
    # never been opened is exactly what it exists to prevent.
    if ($doBinary -and $Verify) {
        Write-Step 'Verifying the packaged renderer loads'
        Invoke-Pnpm --filter '@ocs/desktop' smoke
        Write-Host 'Smoke check passed.' -ForegroundColor Green
    }

    # ---------------------------------------------------------------- web
    if ($doBinary) {
        $export = Join-Path $root 'apps\web\out'
        if (-not (Test-Path (Join-Path $export 'index.html'))) {
            throw 'No web build at apps/web/out. Drop -NoBuild so it gets built.'
        }
        Write-Step "Packaging the web app -> $webZipName"
        Compress-DirectoryContents -SourceDir $export -ZipPath (Join-Path $releaseDir $webZipName)
    }

    # ---------------------------------------------------------------- desktop
    if ($doBinary) {
        if (-not (Test-Path (Join-Path $root 'apps\desktop\dist\main\index.cjs'))) {
            throw 'No desktop bundle at apps/desktop/dist. Drop -NoBuild so it gets built.'
        }

        Write-Step "Packaging installers for: $($Arch -join ', ')"
        Write-Note "staging: $StagingDir"
        Write-Note 'First run downloads Electron binaries; expect several minutes.'

        # Read by electron-builder.config.cjs, which is JS rather than YAML for exactly
        # this reason.
        $env:OCS_RELEASE_DIR = $StagingDir
        $builderArgs = @(
            'exec', 'electron-builder',
            '--config', 'electron-builder.config.cjs',
            '--win', 'nsis'
        )
        foreach ($a in $Arch) { $builderArgs += "--$a" }

        Push-Location (Join-Path $root 'apps\desktop')
        try {
            Invoke-Pnpm @builderArgs
        }
        catch {
            Write-Warn 'electron-builder failed.'
            Write-Note 'If the error was "EPERM: rename ... win-unpacked.tmp", antivirus is'
            Write-Note 'holding the extracted Electron binaries. Add the project and the'
            Write-Note 'staging directory to your scanner exclusions, or pass -StagingDir.'
            throw
        }
        finally {
            Pop-Location
        }

        # Collect only what a recipient should receive. The .blockmap travels with its
        # installer so a future auto-updater can compute a differential download.
        $wanted = Get-ChildItem -LiteralPath $StagingDir -File |
            Where-Object { $_.Extension -in '.exe', '.blockmap' } |
            Where-Object { $_.Name -notlike '*__uninstaller*' }

        if (-not $wanted) { throw "electron-builder produced no installers in $StagingDir." }
        foreach ($f in $wanted) {
            Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $releaseDir $f.Name) -Force
        }
    }

    # ---------------------------------------------------------------- assert
    # A release that is missing an artifact must fail loudly, not ship quietly. The
    # build reporting success is not the same claim as the file still being there:
    # antivirus has removed build output on this machine before, after the step that
    # wrote it had already passed.
    $missing = @()
    if ($doSource -and -not (Test-Path (Join-Path $releaseDir $sourceZipName))) {
        $missing += $sourceZipName
    }
    if ($doBinary) {
        if (-not (Test-Path (Join-Path $releaseDir $webZipName))) { $missing += $webZipName }
        $installers = Get-ChildItem -LiteralPath $releaseDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq '.exe' }
        if (-not $installers) { $missing += 'an installer (.exe)' }
    }
    if ($missing.Count -gt 0) {
        throw @"
Release is incomplete - missing: $($missing -join ', ')

The build reported success, so something removed the artifact after it was written.
Check antivirus quarantine and exclude the project and $OutDir, then re-run.
"@
    }

    # ---------------------------------------------------------------- metadata
    # RELEASE.md is written first so SHA256SUMS.txt covers it too.
    Write-Step 'Writing RELEASE.md'
    Write-ReleaseNotes -ReleaseDir $releaseDir -Version $Version -RepoRoot $root -WithChecksums | Out-Null

    Write-Step 'Writing SHA256SUMS.txt'
    New-ChecksumFile -Directory $releaseDir | Out-Null
    Write-Note 'verify with: sha256sum -c SHA256SUMS.txt'

    if ($Zip) {
        Write-Step 'Zipping the release folder'
        Compress-DirectoryContents -SourceDir $releaseDir -ZipPath (Join-Path $OutDir "cipherworkbench-$Version.zip")
    }

    # ---------------------------------------------------------------- summary
    $kind = if ($doSource -and $doBinary) { 'release' } elseif ($doSource) { 'source' } else { 'binary' }
    Write-Host ''
    Write-Host "$Version ($kind)" -ForegroundColor Green
    foreach ($f in Get-ChildItem -LiteralPath $releaseDir -File | Sort-Object Name) {
        $kb = $f.Length / 1KB
        $size = if ($kb -ge 1024) { '{0,7} MB' -f [math]::Round($kb / 1024, 1) }
                else { '{0,7} KB' -f [math]::Round($kb, 1) }
        Write-Host ('  {0,-42} {1}' -f $f.Name, $size)
    }
    Write-Host "  in $releaseDir" -ForegroundColor DarkGray
    if ($Zip) { Write-Host "  archive: $(Join-Path $OutDir "cipherworkbench-$Version.zip")" -ForegroundColor DarkGray }
    Write-Host ''
    Write-Note 'Share or upload that folder. RELEASE.md explains each file.'
    if ($doBinary) {
        Write-Warn 'The installer is NOT code-signed; SmartScreen will warn on download.'
        Write-Note 'Share the checksum so recipients can verify what they received -'
        Write-Note 'this app can check it for them: SHA-256, source File, drop the installer in.'
    }
}
finally {
    Pop-Location
}
