# Shared helpers for the launch_*, build_* and create-package scripts.
# Dot-source it:  . "$PSScriptRoot\..\lib\common.ps1"
#
# The function names and signatures here deliberately match
# cmd-generator/scripts/common.ps1, the repo this project is modelled on. That is not
# tidiness: the two codebases are read side by side, and a helper that does the same
# job under a different name is a small tax on every future edit to either one. Where
# this file adds something that repo does not have, the comment says why.
#
# Everything here must parse under PowerShell 5.1: the .bat wrappers prefer pwsh but
# fall back to the built-in powershell.exe, so PS7-only syntax (?? and ternaries) is
# out.
#
# ASCII ONLY. These files have no BOM, so PowerShell 5.1 decodes them as cp1252. A
# UTF-8 em-dash becomes three characters ending in 0x94, which maps to U+201D - and
# PowerShell accepts that as a double-quote delimiter. One em-dash inside a comment
# therefore terminates a string early and the whole file fails to parse, only on 5.1.
# That shipped here once, and because every script dot-sources this one, every script
# was dead on any machine without pwsh. Run scripts\check_scripts.ps1 after editing.

#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-RepoRoot {
    # This file lives at scripts\lib\common.ps1, two levels below the repo root.
    Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Note {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor DarkGray
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "!!  $Message" -ForegroundColor Yellow
}

<#
.SYNOPSIS
Strips environment variables that VS Code leaks into its integrated terminal.

.DESCRIPTION
The extension host exports ELECTRON_RUN_AS_NODE=1. Any Electron process that inherits
it runs as plain Node instead: require("electron") returns a stub, so `protocol` and
`BrowserWindow` are undefined and the app dies with "Cannot read properties of
undefined (reading 'registerSchemesAsPrivileged')".

apps/desktop/scripts/run-electron.mjs scrubs this too. Doing it here as well means the
whole process tree is clean, including anything a package script spawns.
#>
function Clear-InheritedElectronEnv {
    $leaked = @(
        'ELECTRON_RUN_AS_NODE'
        'VSCODE_ESM_ENTRYPOINT'
        'VSCODE_IPC_HOOK'
        'VSCODE_CODE_CACHE_PATH'
        'VSCODE_HANDLES_UNCAUGHT_ERRORS'
        'VSCODE_CRASH_REPORTER_PROCESS_TYPE'
    )
    $removed = @()
    foreach ($name in $leaked) {
        if (Test-Path "Env:$name") {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            $removed += $name
        }
    }
    if ($removed.Count -gt 0) {
        Write-Note "Cleared inherited: $($removed -join ', ')"
    }
}

<#
.SYNOPSIS
Locates pnpm, falling back to corepack, and fails with instructions if absent.
#>
function Resolve-PackageManager {
    if (Get-Command pnpm -ErrorAction SilentlyContinue) {
        return [pscustomobject]@{ Name = 'pnpm'; Prefix = @() }
    }
    if (Get-Command corepack -ErrorAction SilentlyContinue) {
        Write-Note 'pnpm not on PATH; using "corepack pnpm".'
        return [pscustomobject]@{ Name = 'corepack'; Prefix = @('pnpm') }
    }
    throw @'
pnpm was not found.

Install it with:
    npm install -g pnpm@10

The repo pins 10.x through the "packageManager" field in package.json.
'@
}

<#
.SYNOPSIS
Runs pnpm in the foreground and throws if it exits non-zero.

.DESCRIPTION
Note the splat: `& $exe @all` passes each element as its own argument, while
`& $exe @($all)` builds one array argument and reaches pnpm as a single long string.
That distinction has cost time in this repo before.
#>
function Invoke-Pnpm {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Arguments)

    $pm = Resolve-PackageManager
    $all = @($pm.Prefix) + $Arguments
    Write-Note "$($pm.Name) $($all -join ' ')"

    & $pm.Name @all
    if ($LASTEXITCODE -ne 0) {
        throw "$($pm.Name) $($all -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Test-PortOpen {
    param(
        [Parameter(Mandatory)][int]$Port,
        [string]$Address = '127.0.0.1',
        [int]$TimeoutMs = 400
    )

    # A raw TcpClient rather than Test-NetConnection: that cmdlet lives in the
    # NetTCPIP module, which is Windows-only and absent from some minimal images.
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($Address, $Port)
        if ($connect.Wait($TimeoutMs)) { return $client.Connected }
        return $false
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

<#
.SYNOPSIS
Blocks until a TCP port accepts connections.

.DESCRIPTION
Electron must not load its dev URL before Next is listening, or it renders a
connection error and never retries. This is the guard for that race.

Worth knowing what it cannot tell you: a listening port is not proof that *this* run's
server answered it. An orphaned dev server from a previous launch satisfies this just
as well, which is why every caller stops its server with Stop-ProcessTree.
#>
function Wait-ForPort {
    param(
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutSeconds = 120,
        [string]$Address = '127.0.0.1'
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortOpen -Port $Port -Address $Address) { return $true }
        Start-Sleep -Milliseconds 400
    }
    throw "Nothing was listening on ${Address}:${Port} after $TimeoutSeconds seconds."
}

<#
.SYNOPSIS
Kills a process and everything it spawned.

.DESCRIPTION
Stop-Process only kills the named process. The dev server is cmd -> pnpm -> node, so
the node process would survive and keep holding the port - after which the *next*
run's port poll succeeds immediately against the stale server, and Electron loads a
dev server from the previous session. taskkill /T handles the whole tree.
#>
function Stop-ProcessTree {
    param([Parameter(Mandatory)][int]$ProcessId)

    if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { return }
    # Output discarded because a race with normal exit is expected and not a finding.
    & taskkill.exe /PID $ProcessId /T /F 2>&1 | Out-Null
}

<#
.SYNOPSIS
Fails early if the workspace has not been installed.
#>
function Assert-Dependencies {
    param([Parameter(Mandatory)][string]$RepoRoot)

    if (Test-Path (Join-Path $RepoRoot 'node_modules')) { return }
    throw 'node_modules is missing. Run "pnpm install" first.'
}

<#
.SYNOPSIS
Deletes build output so the next build cannot reuse anything stale.

.DESCRIPTION
Turborepo will restore removed outputs straight back out of its cache, so callers that
clean must also bypass the cache - every build script here pairs -Clean with turbo's
--force for that reason.
#>
function Remove-BuildOutput {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [switch]$IncludeRelease
    )

    $targets = @(
        'apps\web\out'
        'apps\web\.next'
        'apps\desktop\dist'
        'apps\desktop\renderer'
        '.turbo'
        'apps\web\.turbo'
        'apps\desktop\.turbo'
    )
    if ($IncludeRelease) { $targets += 'apps\desktop\release' }

    foreach ($relative in $targets) {
        $path = Join-Path $RepoRoot $relative
        if (-not (Test-Path $path)) { continue }
        Write-Note "removing $relative"
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $path) {
            # Real-time antivirus can hold a lock on freshly extracted Electron
            # binaries; that is a warning, not a reason to abandon the build.
            Write-Warn "could not fully remove $relative (something is holding a file open)"
        }
    }
}

function Get-PathSize {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer) {
        return [pscustomobject]@{ Files = 1; Bytes = $item.Length }
    }
    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    # Measure-Object returns a null Sum for an empty set. Written longhand rather than
    # with ?? so this still parses under PowerShell 5.1.
    $sum = ($files | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { $sum = 0 }
    return [pscustomobject]@{
        Files = ($files | Measure-Object).Count
        Bytes = $sum
    }
}

<#
.SYNOPSIS
Reports what a build actually produced, and where.

.DESCRIPTION
A build that prints only "success" leaves you guessing which directory to deploy or
which installer to hand over. This names the artifacts and their sizes.
#>
function Show-Artifacts {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string[]]$Paths
    )

    Write-Host ''
    Write-Host 'Artifacts' -ForegroundColor Green

    foreach ($path in $Paths) {
        # Callers pass repo-relative paths, but -OutDir is an absolute path the user
        # chose. Join-Path would splice that onto the repo root and produce nonsense,
        # so rooted paths are taken as given.
        $full = if ([System.IO.Path]::IsPathRooted($path)) { $path } else { Join-Path $RepoRoot $path }

        $size = Get-PathSize -Path $full
        if (-not $size) {
            Write-Host ("  {0,-34} (not produced)" -f $path) -ForegroundColor DarkGray
            continue
        }
        $mb = [math]::Round($size.Bytes / 1MB, 1)
        $label = if ($size.Files -eq 1) { '1 file' } else { "$($size.Files) files" }
        Write-Host ("  {0,-34} {1,8} MB  {2}" -f $path, $mb, $label)
    }
    Write-Host ''
}

<#
.SYNOPSIS
Lists the distributable installers a packaging run produced.

.DESCRIPTION
The release directory also holds win-unpacked and build intermediates, so its total
size says nothing useful - it is mostly the unpacked Electron runtime. This names the
files you would actually hand to someone.
#>
function Show-Installers {
    param([Parameter(Mandatory)][string]$ReleaseDir)

    if (-not (Test-Path $ReleaseDir)) {
        Write-Warn "Release directory not found: $ReleaseDir"
        return
    }

    $wanted = @('.exe', '.dmg', '.zip', '.appimage', '.deb', '.msi')
    $installers = Get-ChildItem -LiteralPath $ReleaseDir -File -ErrorAction SilentlyContinue |
        Where-Object { $wanted -contains $_.Extension.ToLower() } |
        Where-Object { $_.Name -notlike '*__uninstaller*' } |
        Sort-Object Name

    Write-Host 'Installers' -ForegroundColor Green
    if (-not $installers) {
        Write-Host '  (none found)' -ForegroundColor DarkGray
        Write-Host ''
        return
    }
    foreach ($file in $installers) {
        Write-Host ("  {0,-46} {1,8} MB" -f $file.Name, [math]::Round($file.Length / 1MB, 1))
    }
    Write-Host "  in $ReleaseDir" -ForegroundColor DarkGray
    Write-Host ''
}

<#
.SYNOPSIS
Builds a source archive of the project.

.DESCRIPTION
Prefers `git archive`, because "the files git tracks" is the cleanest possible
definition of source and needs no exclusion list to maintain. Falls back to a filtered
copy when this is not a git repository yet, pruning build output and dependencies - an
archive carrying node_modules would be hundreds of megabytes and would defeat the
point.

Returns a short description of which method was used.
#>
function New-SourceArchive {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$ZipPath
    )

    New-Item -ItemType Directory -Force -Path (Split-Path $ZipPath -Parent) | Out-Null
    if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }

    if (Get-Command git -ErrorAction SilentlyContinue) {
        & git -C $RepoRoot rev-parse --verify HEAD *> $null
        $tracked = ($LASTEXITCODE -eq 0)
        # git leaves 128 behind for "not a git repository", and a stale non-zero
        # $LASTEXITCODE is read by the next caller as *its own* failure - build_all.ps1
        # gates on exactly that after running check_scripts.ps1, and a successful
        # packaging run reported 128 to its shell before this line existed. Cleared at
        # the source rather than worked around at every reader.
        $global:LASTEXITCODE = 0

        if ($tracked) {
            & git -C $RepoRoot archive --format=zip --output $ZipPath HEAD
            $ok = ($LASTEXITCODE -eq 0)
            $global:LASTEXITCODE = 0
            if ($ok -and (Test-Path $ZipPath)) {
                Add-DocsToArchive -RepoRoot $RepoRoot -ZipPath $ZipPath
                return 'git archive - tracked files at HEAD'
            }
            Write-Warn 'git archive failed; falling back to a filtered copy.'
        }
        else {
            Write-Note 'not a git repository with a commit; using a filtered copy'
        }
    }

    # Directory names pruned wholesale. Pruning as we walk matters: recursing into
    # node_modules first and filtering afterwards would enumerate tens of thousands of
    # files for nothing.
    $prune = @('node_modules', 'dist', 'out', '.next', 'renderer', 'release', '.turbo', '.git')
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) "cipherworkbench-source-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Force -Path $staging | Out-Null

    try {
        $rootPrefix = $RepoRoot.TrimEnd('\') + '\'
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($RepoRoot)
        $count = 0

        while ($queue.Count -gt 0) {
            $dir = $queue.Dequeue()
            foreach ($item in Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue) {
                if ($item.PSIsContainer) {
                    if ($prune -contains $item.Name) { continue }
                    $queue.Enqueue($item.FullName)
                    continue
                }
                if ($item.Extension -eq '.tsbuildinfo') { continue }

                $relative = $item.FullName.Substring($rootPrefix.Length)
                $destination = Join-Path $staging $relative
                New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
                Copy-Item -LiteralPath $item.FullName -Destination $destination -Force
                $count++
            }
        }

        Compress-DirectoryContents -SourceDir $staging -ZipPath $ZipPath
        Add-DocsToArchive -RepoRoot $RepoRoot -ZipPath $ZipPath
        return "filtered copy - $count files, no build output or dependencies"
    }
    finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
Folds docs/ into an already-built source zip, rather than shipping it as a loose folder beside one.

.DESCRIPTION
git archive only ever emits tracked files, so docs/ is missing from that path unless it happens to
be committed -- and the filtered copy the other branch falls back to already walks docs/ in with
everything else, making this a harmless no-op there rather than a second, diverging way of getting
it in. One function, called from both branches of New-SourceArchive, rather than a separate copy
step in create-package.ps1: that used to live there, wrote the folder out to $releaseDir/docs next
to the zips instead of inside either of them, and read $releaseDir where the packaging script itself
already used that exact name -- which is why the mistake was never caught by a typo, only by the
folder landing in the wrong place.
#>
function Add-DocsToArchive {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$ZipPath
    )
    $docsPath = Join-Path $RepoRoot 'docs'
    if (-not (Test-Path -LiteralPath $docsPath)) { return }
    # -Update adds to the existing archive rather than replacing it, which is the whole point: the
    # zip git archive or Compress-DirectoryContents just produced must survive this call intact.
    Compress-Archive -Path $docsPath -DestinationPath $ZipPath -Update
}

<#
.SYNOPSIS
Reads the project version from the root `version` file.

.DESCRIPTION
That file is the single source of truth, and everything that needs a version reads it: these
packaging scripts, electron-builder (through extraMetadata, which is what makes app.getVersion()
and the installer name agree), and the web build (through NEXT_PUBLIC_APP_VERSION in
next.config.ts). It used to read the root package.json, which meant a bump had to be made in
twenty-one manifests and any one of them could be missed.

Throws rather than defaulting. A packaging run that quietly produced 0.0.0 because a file was
missing would name a release folder, an installer, a zip and a checksum file after a version that
does not exist.
#>
function Get-ProjectVersion {
    param([Parameter(Mandatory)][string]$RepoRoot)

    $versionFile = Join-Path $RepoRoot 'version'
    if (-not (Test-Path -LiteralPath $versionFile)) {
        throw "No version file at $versionFile. That file is the project version."
    }
    $version = (Get-Content -Raw -LiteralPath $versionFile).Trim()
    if (-not $version) { throw "The version file at $versionFile is empty." }
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+') {
        throw "The version file at $versionFile reads '$version', which is not a semver version."
    }
    return $version
}

<#
.SYNOPSIS
Rewrites the `version` field of every workspace package.json to match the root `version` file.

.DESCRIPTION
Nothing resolves these fields -- every internal dependency is `workspace:*` -- but pnpm and
electron-builder still read them in some paths, `npm_package_version` comes from whichever manifest
the runner was launched in, and a manifest disagreeing with the version file is a number on screen
with nothing behind it. So they are brought in line before anything is archived.

Rewritten by regex on the raw text rather than through ConvertFrom-Json/ConvertTo-Json, which would
reorder the keys and reformat the whole file. Anchored to a two-space-indented top-level field,
which is what prettier produces here, so it cannot reach a nested `version` inside a dependency
block. Only files that differ are written, so a clean tree stays clean.

Returns the version it synced to, so a caller can use it as its own lookup.
#>
function Sync-PackageJsonVersions {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [string]$VersionOverride
    )

    $version = $VersionOverride
    if (-not $version) { $version = Get-ProjectVersion -RepoRoot $RepoRoot }

    $targets = @(Join-Path $RepoRoot 'package.json')
    foreach ($dir in @('apps', 'packages', 'packages\tools')) {
        $base = Join-Path $RepoRoot $dir
        if (-not (Test-Path -LiteralPath $base)) { continue }
        foreach ($child in Get-ChildItem -LiteralPath $base -Directory) {
            $candidate = Join-Path $child.FullName 'package.json'
            if (Test-Path -LiteralPath $candidate) { $targets += $candidate }
        }
    }

    $pattern = '(?m)^(  "version"\s*:\s*")[^"]*(")'
    $changed = 0
    foreach ($target in $targets) {
        $raw = [System.IO.File]::ReadAllText($target)
        if ($raw -notmatch $pattern) {
            Write-Warn "No top-level version field in $target, left alone."
            continue
        }
        $updated = [regex]::Replace($raw, $pattern, "`${1}$version`${2}", 1)
        if ($updated -ne $raw) {
            # No BOM, LF preserved: these files are prettier-formatted and diffed.
            [System.IO.File]::WriteAllText($target, $updated, (New-Object System.Text.UTF8Encoding($false)))
            $changed++
            Write-Note ("synced {0} -> {1}" -f $target.Substring($RepoRoot.Length + 1), $version)
        }
    }
    if ($changed -eq 0) { Write-Note "all $($targets.Count) manifests already at $version" }
    return $version
}

<#
.SYNOPSIS
Zips the CONTENTS of a directory, not the directory itself.

.DESCRIPTION
For a static site this matters: extracting must yield index.html at the top level, not
a nested folder that breaks every relative path.
#>
function Compress-DirectoryContents {
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [Parameter(Mandatory)][string]$ZipPath
    )

    if (-not (Test-Path $SourceDir)) { throw "Nothing to compress: $SourceDir does not exist." }
    if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }

    New-Item -ItemType Directory -Force -Path (Split-Path $ZipPath -Parent) | Out-Null
    Compress-Archive -Path (Join-Path $SourceDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal
}

<#
.SYNOPSIS
Writes SHA256SUMS.txt for every file in a directory.

.DESCRIPTION
Written in `sha256sum` format - lowercase hash, two spaces, bare filename - so a
recipient can verify with `sha256sum -c SHA256SUMS.txt` on Linux, macOS or WSL.

Not decoration, and less so here than anywhere: this app's entire pitch is that you
can check what you were given. The Windows installer is not code-signed, so a checksum
is the only way someone can confirm they received what was built - and an app for
verifying digests that shipped without one would be hard to take seriously.
#>
function New-ChecksumFile {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$FileName = 'SHA256SUMS.txt'
    )

    $target = Join-Path $Directory $FileName
    if (Test-Path $target) { Remove-Item -LiteralPath $target -Force }

    $files = Get-ChildItem -LiteralPath $Directory -File | Sort-Object Name
    if (-not $files) { Write-Warn "No files to checksum in $Directory"; return $null }

    $lines = foreach ($f in $files) {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $($f.Name)"
    }
    Set-Content -LiteralPath $target -Value $lines -Encoding ascii
    return $target
}

<#
.SYNOPSIS
Writes a RELEASE.md describing what is in a release folder.

.DESCRIPTION
Generated from what is actually present rather than a fixed template, so it cannot
claim to include an installer that was not built. It also states plainly that the
installers are unsigned - a recipient hitting a SmartScreen warning with no
explanation will reasonably assume the download is malicious.
#>
function Write-ReleaseNotes {
    param(
        [Parameter(Mandatory)][string]$ReleaseDir,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$RepoRoot,
        # Passed rather than probed: RELEASE.md is written before SHA256SUMS.txt so
        # that the checksum file covers it, which means it cannot detect the file.
        [switch]$WithChecksums
    )

    $files = Get-ChildItem -LiteralPath $ReleaseDir -File | Sort-Object Name
    $webZip = $files | Where-Object { $_.Name -like 'cipherworkbench-web-*.zip' }
    $sourceZip = $files | Where-Object { $_.Name -like '*-source.zip' }
    $installers = $files | Where-Object { $_.Extension -eq '.exe' }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Cipher Workbench $Version")
    $lines.Add('')
    $lines.Add('Computes and verifies hashes, CRCs, checksums, MACs, key derivations and ciphers.')
    $lines.Add('')
    $lines.Add('**Nothing you type leaves the machine.** Every algorithm runs locally, in the')
    $lines.Add('browser or in the desktop app. The desktop build blocks outbound requests from the')
    $lines.Add('renderer outright, with a content security policy and a session-level backstop, and')
    $lines.Add('its own smoke test fetches a real external URL and requires the attempt to fail.')
    $lines.Add('Keys, passwords and private keys are never written to a share link or to disk.')
    $lines.Add('')
    $lines.Add('## Contents')
    $lines.Add('')

    if ($webZip) {
        $lines.Add("### $($webZip.Name)")
        $lines.Add('')
        $lines.Add('The web app as a static site. Extract it into any web root, or upload it to any')
        $lines.Add('static host. `index.html` is at the top level of the archive. There is no server')
        $lines.Add('component and no build step for the recipient.')
        $lines.Add('')
        $lines.Add('Do not double-click `index.html` - under `file://` the browser resolves its asset')
        $lines.Add('paths against the local filesystem root, so the page loads unstyled and dead, and')
        $lines.Add('`crypto.subtle` is unavailable outside a secure context in some browsers, which')
        $lines.Add('takes RSA and every random byte with it. Run the included launcher instead, which')
        $lines.Add('starts a local server and opens the app: `start.bat` on Windows, `start.sh` on')
        $lines.Add('Linux or macOS (needs Python on PATH).')
        $lines.Add('')
    }

    if ($sourceZip) {
        $lines.Add("### $($sourceZip.Name)")
        $lines.Add('')
        $lines.Add('Full source. Build it yourself with:')
        $lines.Add('')
        $lines.Add('```sh')
        $lines.Add('npm install -g pnpm@10')
        $lines.Add('pnpm install')
        $lines.Add('pnpm typecheck; pnpm lint; pnpm test')
        $lines.Add('pnpm build && pnpm --filter @ocs/desktop smoke')
        $lines.Add('```')
        $lines.Add('')
        $lines.Add('Requires Node 20.11 or newer. `scripts/` holds the Windows launchers, build and')
        $lines.Add('packaging scripts; `tests/` holds the suite, including differential tests against')
        $lines.Add("OpenSSL through Node's crypto module and against the reference WASM builds of")
        $lines.Add('xxHash.')
        $lines.Add('')
    }

    if ($installers) {
        foreach ($exe in $installers) {
            $arch = if ($exe.Name -match '-(x64|arm64)\.exe$') { $Matches[1] } else { 'unknown arch' }
            $lines.Add("### $($exe.Name)")
            $lines.Add('')
            $lines.Add("Windows installer ($arch). Run it and follow the prompts; it installs per-user,")
            $lines.Add('so it needs no administrator rights.')
            $lines.Add('')
        }
        $lines.Add('> **These installers are not code-signed.** Windows SmartScreen will show a')
        $lines.Add('> warning, and Edge or Chrome may flag the download. That is expected, not a sign')
        $lines.Add('> of tampering. Verify the checksum below before trusting the file.')
        $lines.Add('')
    }

    if ($WithChecksums) {
        $lines.Add('## Verifying')
        $lines.Add('')
        $lines.Add('`SHA256SUMS.txt` lists a SHA-256 hash for every file here.')
        $lines.Add('')
        $lines.Add('Linux, macOS or WSL:')
        $lines.Add('')
        $lines.Add('```sh')
        $lines.Add('sha256sum -c SHA256SUMS.txt')
        $lines.Add('```')
        $lines.Add('')
        $lines.Add('Windows PowerShell:')
        $lines.Add('')
        $lines.Add('```powershell')
        $lines.Add('Get-FileHash .\<filename> -Algorithm SHA256 | Format-List')
        $lines.Add('```')
        $lines.Add('')
        $lines.Add('Compare the result against the matching line. If it differs, do not use the file.')
        $lines.Add('Once the app is installed you can also check a file with it directly: pick')
        $lines.Add('SHA-256, set the source to File, drop the download in, and paste the expected')
        $lines.Add('hash into the Verify panel.')
        $lines.Add('')
    }

    $lines.Add('## Notes')
    $lines.Add('')
    $lines.Add('- The desktop app and the web app are the same interface and the same algorithms.')
    $lines.Add('  The desktop build adds native file dialogs and saves your settings to disk; the')
    $lines.Add('  web build keeps them in browser storage.')
    $lines.Add('- A checksum is not an integrity check. Every CRC and checksum tool says so in its')
    $lines.Add('  own Checks panel, because treating one as tamper-evidence is the most common')
    $lines.Add('  cryptographic mistake there is.')
    $lines.Add('- Text input recomputes shortly after you stop typing. A file is read as soon')
    $lines.Add('  as it is dropped, in chunks, so its size is not bounded by memory.')
    $lines.Add('')

    $target = Join-Path $ReleaseDir 'RELEASE.md'
    Set-Content -LiteralPath $target -Value $lines -Encoding utf8
    return $target
}

<#
.SYNOPSIS
Starts a pnpm command in its own console window and returns the process.

.DESCRIPTION
cmd.exe is the launcher, and that is load-bearing. `Start-Process -FilePath "pnpm"`
fails on Windows with "%1 is not a valid Win32 application": pnpm is a .cmd or .ps1
shim depending on how it was installed, and Start-Process with -NoNewWindow uses
CreateProcess, which can only run a real executable. Going through cmd lets it resolve
the shim via PATHEXT, which works for every installation shape rather than for the one
on the machine this was written on.

Stop whatever this returns with Stop-ProcessTree, never Stop-Process: the process here
is the cmd.exe wrapper and the node process underneath is its child.
#>
function Start-PnpmWindow {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [string]$Title = 'cipherworkbench',
        [hashtable]$EnvVars = @{},
        # Not in cmd-generator's copy: its dev server gets its own window, which is
        # right when you want to read Next's output. The desktop launcher here wants
        # the server's output interleaved with Electron's in one console, so this is
        # a switch rather than a second near-identical function.
        [switch]$NoNewWindow
    )

    $pm = Resolve-PackageManager
    $all = @($pm.Prefix) + $Arguments

    $parts = @("title $Title")
    foreach ($key in $EnvVars.Keys) { $parts += "set $key=$($EnvVars[$key])" }
    $parts += "$($pm.Name) $($all -join ' ')"

    $splat = @{
        FilePath         = 'cmd.exe'
        ArgumentList     = @('/c', ($parts -join ' && '))
        WorkingDirectory = $WorkingDirectory
        PassThru         = $true
    }
    if ($NoNewWindow) { $splat.NoNewWindow = $true }
    return Start-Process @splat
}

<#
No script in this folder prompts, pauses, or waits for a keypress. Ever.

There was a Wait-IfInteractive here, so that a window opened by double-clicking a .bat
would stay up long enough to read an error. It was wrong twice over. From a terminal -
which is how these actually get run, through `pnpm win:*` - a successful packaging run
stopped dead on "Press Enter to close" with nothing to close. And under
`powershell -NonInteractive` the Read-Host threw, so a run that had already printed its
summary exited 1.

The right detection is "was this launched from Explorer", which means walking the parent
process chain looking for explorer.exe. That is real machinery for a case nobody here
hits, and cmd-generator - the repo these scripts are modelled on - simply does not do it.
A failure prints its error and exits non-zero; a shell shows it, and Explorer closes the
window. If you want a pause back for double-clicking, add `pause` to the end of the one
.bat you use that way rather than to every script.
#>
