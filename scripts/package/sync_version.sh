#!/usr/bin/env bash
# Keeps every workspace manifest in step with the root `version` file.
#
# The Linux and macOS counterpart of sync_version.ps1. The root `version` file is the single source
# of truth; nothing resolves the manifest versions, because every internal dependency is
# `workspace:*`, which is exactly why they need a gate rather than trust -- a stale one breaks no
# build, it just puts a number on screen with nothing behind it.
#
# Usage:
#   scripts/package/sync_version.sh              sync the manifests to the version file
#   scripts/package/sync_version.sh --set 0.2.0  write the version file, then sync
#   scripts/package/sync_version.sh --check      fail if anything disagrees; change nothing

set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
. "$here/../lib/common.sh"

set_to=""
check=0
while (($#)); do
  case "$1" in
    --) shift ;;
    --set) set_to="${2:?--set needs a version}"; shift 2 ;;
    --set=*) set_to="${1#*=}"; shift ;;
    --check) check=1; shift ;;
    -h | --help) printf 'usage: %s [--set X.Y.Z | --check]\n' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

root="$(repo_root)"

if [[ -n "$set_to" ]] && ((check)); then
  die '--set and --check are mutually exclusive: one writes, the other refuses to.'
fi

if [[ -n "$set_to" ]]; then
  [[ "$set_to" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || die "'$set_to' is not a semver version."
  # A trailing newline, because every other text file here has one and a diff should not say
  # "no newline at end of file" on the one file a release is named after.
  printf '%s\n' "$set_to" >"$root/version"
  write_step "version file set to $set_to"
fi

version="$(project_version "$root")"

if ((check)); then
  write_step "checking every manifest against the version file ($version)"
  bad=0
  while IFS= read -r file; do
    label="${file#"$root"/}"
    current="$(sed -n 's/^  "version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n 1)"
    if [[ -z "$current" ]]; then
      write_warn "$label has no top-level version field"
      continue
    fi
    if [[ "$current" == "$version" ]]; then
      write_note "ok    $label"
    else
      bad=$((bad + 1))
      printf '%s  FAIL  %s reads %s%s\n' "$C_RED" "$label" "$current" "$C_RESET"
    fi
  done < <(manifest_paths "$root")
  printf '\n'
  if ((bad > 0)); then
    printf '%s%s manifest(s) disagree with the version file. Run pnpm sh:version.%s\n' \
      "$C_RED" "$bad" "$C_RESET"
    exit 1
  fi
  write_ok "All manifests agree with the version file ($version)."
  exit 0
fi

write_step "syncing every manifest to $version"
changed="$(sync_package_json_versions "$root" "$version")"
printf '\n'
if [[ "$changed" == "0" ]]; then
  write_ok "Project version is $version. Every manifest already agreed."
else
  write_ok "Project version is $version. Updated $changed manifest(s)."
fi
