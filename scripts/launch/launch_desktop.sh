#!/usr/bin/env bash
# Starts the desktop app against the Next dev server.
#
# The Linux and macOS counterpart of launch_desktop.ps1. Two processes are needed: `pnpm desktop`
# builds and runs the Electron shell, which loads http://localhost:3000, so the web dev server has
# to be running too. The server goes in the background and is stopped when this script exits.
#
# Note what dev mode deliberately does *not* have: the renderer's outbound-request block in
# apps/desktop/src/main/window.ts is installed only when there is no dev URL. It once ran in dev
# too and cancelled Next's HMR websocket, which killed hot reload and filled the terminal with
# retry warnings. The guarantee is about the shipped app; a dev session is a localhost server with
# DevTools open and nothing to protect.
#
# Usage: scripts/launch/launch_desktop.sh [--port 3000] [--timeout 90]

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

port=3000
timeout=90
while (($#)); do
  case "$1" in
    --) shift ;;
    --port) port="${2:?--port needs a number}"; shift 2 ;;
    --port=*) port="${1#*=}"; shift ;;
    --timeout) timeout="${2:?--timeout needs a number}"; shift 2 ;;
    --timeout=*) timeout="${1#*=}"; shift ;;
    -h | --help) printf 'usage: %s [--port N] [--timeout SECONDS]\n' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

root="$(repo_root)"
clear_inherited_electron_env
assert_dependencies "$root"

web_pid=""
# Stopped however this script ends, including Ctrl+C -- which is the whole reason for a trap
# rather than a line at the bottom. Without it, interrupting the launcher leaves the dev server
# holding the port and the next run refuses to start.
cleanup() {
  if [[ -n "$web_pid" ]]; then
    write_note 'Stopping the web dev server'
    stop_process_tree "$web_pid"
    web_pid=""
  fi
}
trap cleanup EXIT INT TERM

if test_port_open "$port"; then
  # Refused rather than reused. A listening port is not proof that this run's server answered it,
  # and loading Electron against an orphaned dev server from a previous session is a genuinely
  # confusing way to spend twenty minutes.
  die "Port $port is already in use.

Something is already listening there -- most likely a dev server left behind by an earlier run.
Close it (or stop whatever owns the port) and try again, so Electron cannot end up loading a
stale server."
fi

write_step 'Starting the web dev server in the background'
# Same terminal rather than a new one, so Next's output and Electron's are interleaved in the
# order things actually happened.
web_pid="$(start_pnpm_background web)"

write_note "waiting for http://localhost:$port"
if wait_for_port "$port" "$timeout" "$web_pid"; then
  :
else
  case "$?" in
    2) die 'The web dev server exited before it started listening.' ;;
    *) die "The web dev server did not start listening within $timeout seconds." ;;
  esac
fi

write_step 'Launching Electron'
invoke_pnpm desktop
