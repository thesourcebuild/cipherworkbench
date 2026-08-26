#!/usr/bin/env bash
# Builds everything, and optionally gates, smoke-tests and packages it.
#
# The Linux and macOS counterpart of build_all.ps1. --package produces the Linux targets; see the
# note at the top of build_desktop.sh for why it cannot produce the Windows installer.
#
# Usage: scripts/build-helpers/build_all.sh [--clean] [--verify] [--smoke] [--package] [--out DIR]

set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/../lib/common.sh"

clean=0
verify=0
smoke=0
package=0
out_dir=""
while (($#)); do
  case "$1" in
    --) shift ;;
    --clean) clean=1; shift ;;
    --verify) verify=1; shift ;;
    --smoke) smoke=1; shift ;;
    --package) package=1; shift ;;
    --out) out_dir="${2:?--out needs a directory}"; shift 2 ;;
    --out=*) out_dir="${1#*=}"; shift ;;
    -h | --help)
      printf 'usage: %s [--clean] [--verify] [--smoke] [--package] [--out DIR]\n' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

root="$(repo_root)"
clear_inherited_electron_env
assert_dependencies "$root"

if ((verify)); then
  # First because it is instant, and because a script that does not parse makes every other step
  # here unreachable.
  write_step 'Checking the scripts are ASCII, parse and are executable'
  "$here/../check_scripts.sh"

  write_step 'Typechecking every package and tests/'
  invoke_pnpm typecheck

  write_step 'Linting'
  invoke_pnpm lint

  write_step 'Running tests'
  invoke_pnpm test

  write_ok 'Gate passed.'
fi

if ((clean)); then
  write_step 'Cleaning previous output'
  remove_build_output "$root"
fi

write_step 'Building web and desktop'
write_note 'Turborepo orders the web export before the desktop renderer copy.'
turbo_args=(run build)
((clean)) && turbo_args+=(--force)
invoke_pnpm exec turbo "${turbo_args[@]}"

show_artifacts "$root" "apps/web/out" "apps/desktop/renderer" "apps/desktop/dist"

if ((smoke)); then
  write_step 'Verifying the built desktop app loads'
  if [[ -n "${DISPLAY:-}" || "$(uname -s)" == "Darwin" ]]; then
    invoke_pnpm --filter @ocs/desktop smoke
  elif command -v xvfb-run >/dev/null 2>&1; then
    write_note 'no DISPLAY, so running under xvfb-run'
    xvfb-run -a pnpm --dir "$root" --filter @ocs/desktop smoke
  else
    die "The smoke test drives a real Electron window and there is no DISPLAY. Install xvfb (apt install xvfb) or run it on a desktop session."
  fi
  write_ok 'Smoke check passed.'
fi

if ((package)); then
  # --no-build because the build above already produced everything create-package needs.
  write_step 'Creating the Linux packages'
  forward=(--binary --no-build)
  [[ -n "$out_dir" ]] && forward+=(--out "$out_dir")
  "$here/../package/create-package.sh" "${forward[@]}"
else
  write_note 'Run with --package to produce the installers.'
fi
