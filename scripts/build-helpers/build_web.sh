#!/usr/bin/env bash
# Builds the web app.
#
# The Linux and macOS counterpart of build_web.ps1. Produces the Next.js static export in
# apps/web/out. That directory is the entire web deliverable -- drop it on any static host. It is
# also exactly what the desktop shell serves over its app:// protocol, so this is the shared half
# of both builds.
#
# Usage: scripts/build-helpers/build_web.sh [--clean] [--serve] [--port 3000]

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

clean=0
serve=0
port=3000
while (($#)); do
  case "$1" in
    --) shift ;;
    --clean) clean=1; shift ;;
    --serve) serve=1; shift ;;
    --port) port="${2:?--port needs a number}"; shift 2 ;;
    --port=*) port="${1#*=}"; shift ;;
    -h | --help) printf 'usage: %s [--clean] [--serve] [--port N]\n' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

root="$(repo_root)"
clear_inherited_electron_env
assert_dependencies "$root"

if ((clean)); then
  write_step 'Cleaning previous output'
  remove_build_output "$root"
fi

write_step 'Building the static export'
# --filter=@ocs/web... also builds everything web depends on, which here is the whole packages/ tree.
turbo_args=(run build --filter=@ocs/web...)
((clean)) && turbo_args+=(--force)
invoke_pnpm exec turbo "${turbo_args[@]}"

show_artifacts "$root" "apps/web/out"
write_ok 'Deploy apps/web/out to any static host.'

if ((serve)); then
  if test_port_open "$port"; then
    write_warn "Port $port is already in use; not serving."
    exit 0
  fi
  write_step "Serving apps/web/out on http://localhost:$port"
  write_note 'Press Ctrl+C to stop.'
  # Serving it rather than opening the file is not a nicety. Under file:// the export resolves its
  # asset paths against the filesystem root and loads dead, and some browsers withhold
  # crypto.subtle outside a secure context -- which would take RSA and every random byte with it.
  #
  # npx rather than a tracked dependency: this is for eyeballing a build, not part of the product.
  npx --yes serve@14 "$root/apps/web/out" --listen "$port" --single
fi
