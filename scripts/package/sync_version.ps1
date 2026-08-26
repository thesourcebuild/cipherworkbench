<#
.SYNOPSIS
Reads the root `version` file and brings every workspace package.json in line with it.

.DESCRIPTION
The root `version` file is the single source of truth for the project version. Three things read it
directly and need nothing from this script: `Get-ProjectVersion` in lib/common.ps1 (release folder,
zip and checksum names), apps/web/next.config.ts (NEXT_PUBLIC_APP_VERSION, and therefore the footer
and the About box on the web) and apps/desktop/electron-builder.config.cjs (extraMetadata, and
therefore app.getVersion(), the installer name and the packaged app's version).

What still reads a package.json is pnpm's own metadata and `npm_package_version`, so the twenty-one
manifests are kept in agreement -- and `tests/version.test.ts` fails if they are not, which is what
makes this script the fix rather than a nicety. Nothing resolves those fields (every internal
dependency is `workspace:*`), so a mismatch breaks no build; it just puts a number on screen with
nothing behind it, which is worse.

create-package.ps1 already syncs before it archives anything. This exists for the other half of the
job: bumping. `-Set` writes the `version` file and the manifests in one action, so there is no state
where the file and the tree disagree because someone edited one and forgot the rest.

.PARAMETER Set
The new version. Writes it to the root `version` file first, then syncs. Must be semver.

.PARAMETER Check
Report disagreements and exit non-zero without writing anything. What CI wants.

.EXAMPLE
pnpm win:version
Sync the manifests to whatever the `version` file already says.

.EXAMPLE
pnpm win:version -Set 0.2.0
Bump to 0.2.0 everywhere. No `--` separator: pnpm forwards it literally and PowerShell rejects it as
an ambiguous parameter name.

.EXAMPLE
pnpm win:version -Check
Fail if anything disagrees. Changes nothing.
#>
[CmdletBinding()]
param(
    [string]$Set,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\..\lib\common.ps1"

$root = Get-RepoRoot

if ($Set -and $Check) {
    throw '-Set and -Check are mutually exclusive: one writes, the other refuses to.'
}

if ($Set) {
    if ($Set -notmatch '^[0-9]+\.[0-9]+\.[0-9]+') {
        throw "'$Set' is not a semver version."
    }
    $versionFile = Join-Path $root 'version'
    # A trailing newline, because every other text file here has one and a diff should not say
    # "no newline at end of file" on the one file a release is named after.
    [System.IO.File]::WriteAllText($versionFile, "$Set`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Step "version file set to $Set"
}

$version = Get-ProjectVersion -RepoRoot $root

if ($Check) {
    Write-Step "checking every manifest against the version file ($version)"
    $bad = 0
    $targets = @(Join-Path $root 'package.json')
    foreach ($dir in @('apps', 'packages', 'packages\tools')) {
        $base = Join-Path $root $dir
        if (-not (Test-Path -LiteralPath $base)) { continue }
        foreach ($child in Get-ChildItem -LiteralPath $base -Directory) {
            $candidate = Join-Path $child.FullName 'package.json'
            if (Test-Path -LiteralPath $candidate) { $targets += $candidate }
        }
    }
    foreach ($target in $targets) {
        $raw = [System.IO.File]::ReadAllText($target)
        $match = [regex]::Match($raw, '(?m)^  "version"\s*:\s*"([^"]*)"')
        $label = $target.Substring($root.Length + 1)
        if (-not $match.Success) {
            Write-Warn "$label has no top-level version field"
            continue
        }
        if ($match.Groups[1].Value -eq $version) {
            Write-Note "ok    $label"
        }
        else {
            $bad++
            Write-Host ("  FAIL  {0} reads {1}" -f $label, $match.Groups[1].Value) -ForegroundColor Red
        }
    }
    Write-Host ''
    if ($bad -gt 0) {
        Write-Host "$bad manifest(s) disagree with the version file. Run pnpm win:version." -ForegroundColor Red
        exit 1
    }
    Write-Host "All manifests agree with the version file ($version)." -ForegroundColor Green
    exit 0
}

Write-Step "syncing every manifest to $version"
$null = Sync-PackageJsonVersions -RepoRoot $root
Write-Host ''
Write-Host "Project version is $version." -ForegroundColor Green
