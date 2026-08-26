#!/usr/bin/env bash
# Checks the desktop icon artefacts, and explains why it will not regenerate them here.
#
# This is the one script in the set that is deliberately *not* a port. make_icon.ps1 draws the
# padlock with System.Drawing -- primitives, gradients and a real multi-size .ico -- and its own
# header says it redraws rather than rasterising apps/desktop/resources/icon.svg on purpose,
# because a 32-pixel rasterisation of that SVG looks like mud.
#
# So a Linux version had three options, and two of them are worse than nothing:
#
#   * Rasterise the SVG with ImageMagick or rsvg-convert. That produces a *different* icon from the
#     one Windows produces, and two scripts generating two different icons is worse than one script
#     generating one. Whichever ran last would win, silently, in a committed binary file.
#   * Reimplement the drawing. Several hundred lines of ImageMagick to reproduce a padlock pixel for
#     pixel, with no way to prove it matched beyond looking at it.
#   * Verify the committed artefacts and say where they come from. That is this.
#
# The icons are committed -- icon.png, icon.ico and icon.svg all live in
# apps/desktop/resources/ -- so nothing here needs generating to build or package the app. If the
# design changes, run `pnpm win:icon` on Windows and commit the result.
#
# Usage: scripts/package/make_icon.sh

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

while (($#)); do
  case "$1" in
    --) shift ;;
    -h | --help) printf 'usage: %s\n' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

root="$(repo_root)"
resources="$root/apps/desktop/resources"

write_step 'Checking the committed icon artefacts'

missing=0
check_one() {
  local name="$1" min_bytes="$2" what="$3"
  local file="$resources/$name"
  if [[ ! -f "$file" ]]; then
    missing=$((missing + 1))
    printf '%s  FAIL  %s is missing -- %s%s\n' "$C_RED" "$name" "$what" "$C_RESET"
    return
  fi
  local size
  size="$(wc -c <"$file" | tr -d '[:space:]')"
  if ((size < min_bytes)); then
    missing=$((missing + 1))
    printf '%s  FAIL  %s is only %s bytes, which is too small to be real%s\n' \
      "$C_RED" "$name" "$size" "$C_RESET"
    return
  fi
  write_note "ok    $name  ${size} bytes  -- $what"
}

# The floors are deliberately low: this is checking a file is present and not a stub, not
# fingerprinting its contents. A wrong-looking icon is something only an eye can catch.
check_one 'icon.png' 2000 'Linux, and the window when running unpackaged'
check_one 'icon.ico' 2000 'Windows title bar, taskbar and installer'
check_one 'icon.svg' 200 'the source drawing, for reference'

printf '\n'
if ((missing > 0)); then
  printf '%s%s icon file(s) are missing or truncated.%s\n' "$C_RED" "$missing" "$C_RESET"
  write_note 'Regenerate them on Windows with: pnpm win:icon'
  exit 1
fi

write_ok 'The icon artefacts are present.'
write_note 'They are committed, so no build or packaging step needs this script.'
write_note 'To change the design, run pnpm win:icon on Windows and commit the result --'
write_note 'rasterising the SVG here would produce a different icon from the packaged one.'
