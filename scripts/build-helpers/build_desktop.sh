#!/usr/bin/env bash
# Builds the desktop app, and optionally packages it.
#
# The Linux and macOS counterpart of build_desktop.ps1, with one platform difference stated up
# front: --package here produces the *Linux* targets from electron-builder.config.cjs -- an
# AppImage and a .deb -- not the Windows NSIS installer. Cross-building that needs wine, and
# producing something named like an installer which had never been through NSIS would be worse
# than refusing. Run the PowerShell script on Windows for the Windows artefact.
#
# Usage: scripts/build-helpers/build_desktop.sh [--clean] [--smoke] [--package] [--out DIR]

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

clean=0
smoke=0
package=0
out_dir=""
while (($#)); do
  case "$1" in
    --) shift ;;
    --clean) clean=1; shift ;;
    --smoke) smoke=1; shift ;;
    --package) package=1; shift ;;
    --out) out_dir="${2:?--out needs a directory}"; shift 2 ;;
    --out=*) out_dir="${1#*=}"; shift ;;
    -h | --help)
      printf 'usage: %s [--clean] [--smoke] [--package] [--out DIR]\n' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(repo_root)"
clear_inherited_electron_env
assert_dependencies "$root"

if ((clean)); then
  write_step 'Cleaning previous output'
  remove_build_output "$root"
fi

write_step 'Building the web export, renderer copy and main bundle'
write_note 'Order matters: the renderer copy reads apps/web/out.'
# The trailing "..." includes @ocs/desktop's dependencies, so the web export is built first rather
# than by luck.
turbo_args=(run build --filter=@ocs/desktop...)
((clean)) && turbo_args+=(--force)
invoke_pnpm exec turbo "${turbo_args[@]}"

show_artifacts "$root" "apps/web/out" "apps/desktop/renderer" "apps/desktop/dist"

# The smoke test drives a real Electron window, so on a headless box it needs a display. xvfb-run
# where there is no DISPLAY, and a message naming the fix rather than a hang if that is missing too.
run_smoke() {
  write_step 'Verifying the built app loads'
  if [[ -n "${DISPLAY:-}" || "$(uname -s)" == "Darwin" ]]; then
    invoke_pnpm --filter @ocs/desktop smoke
  elif command -v xvfb-run >/dev/null 2>&1; then
    write_note 'no DISPLAY, so running under xvfb-run'
    xvfb-run -a pnpm --dir "$root" --filter @ocs/desktop smoke
  else
    die "The smoke test drives a real Electron window and there is no DISPLAY. Install xvfb (apt install xvfb) or run it on a desktop session."
  fi
  write_ok 'Smoke check passed.'
}

# Not redundant with the unit suite, and the only check that can see a CSP which blocks hydration,
# a lazy chunk that will not resolve over app://, or a compute worker that failed to start and fell
# back to the main thread -- which is silent, because the fallback is correct.
((smoke)) && run_smoke

if ((package == 0)); then
  write_note 'Run with --package to produce installers.'
  exit 0
fi

# Delegated to create-package.sh rather than duplicated: one packaging path for the whole project,
# and it stages outside the repo.
write_step 'Creating the Linux packages'
write_note 'via create-package.sh -- one packaging path for the whole project.'
forward=(--binary --no-build)
[[ -n "$out_dir" ]] && forward+=(--out "$out_dir")
"$here/../package/create-package.sh" "${forward[@]}"
