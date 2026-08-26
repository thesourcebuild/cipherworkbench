#!/usr/bin/env bash
# Starts the web app's dev server and opens it in the default browser.
#
# The Linux and macOS counterpart of launch_web.ps1. Usage:
#   scripts/launch/launch_web.sh [--port 3000]

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

port=3000
while (($#)); do
  case "$1" in
    --) shift ;;
    --port) port="${2:?--port needs a number}"; shift 2 ;;
    --port=*) port="${1#*=}"; shift ;;
    -h | --help) printf 'usage: %s [--port N]\n' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

root="$(repo_root)"
clear_inherited_electron_env
assert_dependencies "$root"

# xdg-open on Linux, open on macOS, and neither in a container -- where saying so and carrying on
# is better than failing a dev server over a browser.
open_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 &
  else
    write_note "no xdg-open or open here; visit $url yourself"
  fi
}

if test_port_open "$port"; then
  write_warn "Something is already listening on port $port."
  write_note 'That is probably a dev server from an earlier run. Opening it anyway.'
  open_browser "http://localhost:$port"
  exit 0
fi

write_step "Starting the dev server on http://localhost:$port"
write_note 'Press Ctrl+C to stop.'

# Opened before the server is up on purpose: Next takes a few seconds, and the browser's own retry
# is friendlier than waiting on a port poll here.
open_browser "http://localhost:$port"

invoke_pnpm web
