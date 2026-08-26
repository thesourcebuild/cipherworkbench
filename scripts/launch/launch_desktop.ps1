<#
.SYNOPSIS
Starts the desktop app against the Next dev server.

.DESCRIPTION
Two processes are needed: `pnpm desktop` builds and runs the Electron shell, which
loads http://localhost:3000, so the web dev server has to be running too. The server
goes in the background and is stopped when this script exits.

Note what dev mode deliberately does *not* have: the renderer's outbound-request block
in apps/desktop/src/main/window.ts is installed only when there is no dev URL. It once
ran in dev too and cancelled Next's HMR websocket, which killed hot reload and filled
the terminal with retry warnings. The guarantee is about the shipped app; a dev session
is a localhost server with DevTools open and nothing to protect.

.PARAMETER Port
Port the dev server listens on. Default 3000.

.PARAMETER TimeoutSeconds
How long to wait for the server before giving up. Default 90.

.EXAMPLE
.\scripts\launch\launch_desktop.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 3000,
    [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"

$root = Get-RepoRoot
Clear-InheritedElectronEnv
Assert-Dependencies -RepoRoot $root

$web = $null

Push-Location $root
try {
    if (Test-PortOpen -Port $Port) {
        # Refused rather than reused. A listening port is not proof that this run's
        # server answered it, and loading Electron against an orphaned dev server from a
        # previous session is a genuinely confusing way to spend twenty minutes.
        throw @"
Port $Port is already in use.

Something is already listening there - most likely a dev server left behind by an
earlier run. Close it (or stop whatever owns the port) and try again, so Electron
cannot end up loading a stale server.
"@
    }

    Write-Step 'Starting the web dev server in the background'
    # Same console rather than a new window, so Next's output and Electron's are
    # interleaved in the order things actually happened.
    $web = Start-PnpmWindow -Arguments @('web') -WorkingDirectory $root -Title 'cipherworkbench dev server' -NoNewWindow

    Write-Note "waiting for http://localhost:$Port"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $listening = $false
    while ((Get-Date) -lt $deadline) {
        if ($web.HasExited) { throw 'The web dev server exited before it started listening.' }
        if (Test-PortOpen -Port $Port) { $listening = $true; break }
        Start-Sleep -Milliseconds 400
    }
    if (-not $listening) {
        throw "The web dev server did not start listening within $TimeoutSeconds seconds."
    }

    Write-Step 'Launching Electron'
    Invoke-Pnpm desktop
}
finally {
    if ($web -and -not $web.HasExited) {
        Write-Note 'Stopping the web dev server'
        # The whole tree: $web is a cmd.exe wrapper and the Next process is its child,
        # so Stop-Process would leave the dev server holding the port after this script
        # returns - and the next run's port check would then find it.
        Stop-ProcessTree -ProcessId $web.Id
    }
    Pop-Location
}
