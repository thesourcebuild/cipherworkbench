#!/usr/bin/env bash
# The one packaging path for Linux and macOS.
#
# The counterpart of create-package.ps1, and it keeps that script's two structural decisions
# because both are about not shipping something broken rather than about Windows:
#
#   * **electron-builder runs in a staging directory outside the repo**, and only the finished
#     artefacts are collected. Its own output holds an unpacked Electron runtime of several hundred
#     megabytes, which nothing downstream wants -- and on Windows real-time antivirus locks those
#     freshly extracted binaries and fails the build outright.
#   * **the release is asserted afterwards**. A run that reports success while the web zip or the
#     package is missing throws rather than shipping quietly, because that has happened.
#
# One platform difference, stated rather than hidden: this produces the **Linux** targets from
# electron-builder.config.cjs -- an AppImage and a .deb -- not the Windows NSIS installer.
# Cross-building that needs wine, and emitting something named like an installer which had never
# been through NSIS would be worse than refusing.
#
# Usage:
#   scripts/package/create-package.sh                     source and web zips
#   scripts/package/create-package.sh --binary            also the Linux app packages
#   scripts/package/create-package.sh --release --verify   the full gate, then everything

set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/../lib/common.sh"

do_source=0
do_binary=0
do_verify=0
no_build=0
out_dir=""
staging_dir=""
version_override=""
while (($#)); do
  case "$1" in
    --) shift ;;
    --source) do_source=1; shift ;;
    --binary) do_binary=1; shift ;;
    --release) do_source=1; do_binary=1; shift ;;
    --verify) do_verify=1; shift ;;
    --no-build) no_build=1; shift ;;
    --out) out_dir="${2:?--out needs a directory}"; shift 2 ;;
    --out=*) out_dir="${1#*=}"; shift ;;
    --staging) staging_dir="${2:?--staging needs a directory}"; shift 2 ;;
    --staging=*) staging_dir="${1#*=}"; shift ;;
    --version) version_override="${2:?--version needs a value}"; shift 2 ;;
    --version=*) version_override="${1#*=}"; shift ;;
    -h | --help)
      printf 'usage: %s [--source] [--binary] [--release] [--verify] [--no-build] [--out DIR] [--staging DIR]\n' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Nothing selected means the source and web zips, which is the cheap useful default.
if ((do_source == 0 && do_binary == 0)); then do_source=1; fi

root="$(repo_root)"
clear_inherited_electron_env
assert_dependencies "$root"

# Synced before anything is archived, because the source zip carries the manifests and a release
# whose manifests disagree with its own name is the thing the version file exists to prevent.
write_step 'Syncing the manifest versions to the version file'
version="${version_override:-$(project_version "$root")}"
if [[ -z "$version_override" ]]; then
  changed="$(sync_package_json_versions "$root" "$version")"
  [[ "$changed" == "0" ]] && write_note 'every manifest already agreed'
fi

release_dir="${out_dir:-$root/dist}/$version"
staging="${staging_dir:-${TMPDIR:-/tmp}/cipherworkbench-pkg-$$}"

if ((do_verify)); then
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

write_step "Clearing $release_dir"
rm -rf -- "$release_dir"
mkdir -p -- "$release_dir"

source_zip="cipherworkbench-$version-source.zip"
web_zip="cipherworkbench-$version-web.zip"

if ((do_source)); then
  write_step "Packaging the source -> $source_zip"
  new_source_archive "$root" "$release_dir/$source_zip"
fi

if ((no_build == 0)); then
  write_step 'Building'
  # Plain `build`, not the Pages variant: build:pages sets NEXT_PUBLIC_BASE_PATH and both write to
  # the same apps/web/out, so a desktop package built after a Pages build would ship prefixed asset
  # URLs and load nothing. That is why build_desktop.ps1 calls plain build too.
  invoke_pnpm exec turbo run build
fi

write_step "Packaging the web app -> $web_zip"
[[ -d "$root/apps/web/out" ]] || die 'apps/web/out is missing. Drop --no-build, or run the build first.'
compress_directory_contents "$root/apps/web/out" "$release_dir/$web_zip"

if ((do_binary)); then
  write_step 'Packaging the Linux app'
  write_note 'AppImage and .deb, from the linux section of electron-builder.config.cjs.'
  mkdir -p -- "$staging"
  # OCS_RELEASE_DIR is what the config reads, so electron-builder works outside the repo -- see
  # the note at the top of electron-builder.config.cjs.
  ( cd "$root/apps/desktop" &&
      OCS_RELEASE_DIR="$staging" pnpm exec electron-builder --linux --publish never )

  write_step 'Collecting the artefacts'
  found=0
  while IFS= read -r -d '' file; do
    cp -- "$file" "$release_dir/"
    write_note "collected $(basename -- "$file")"
    found=$((found + 1))
  done < <(find "$staging" -maxdepth 2 -type f \
    \( -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' \) -print0)
  ((found > 0)) || die "electron-builder produced no Linux packages under $staging."
  # The staging tree holds the unpacked Electron runtime, which is hundreds of megabytes and which
  # nothing downstream wants.
  rm -rf -- "$staging"
fi

# RELEASE.md before SHA256SUMS.txt, so the checksums cover it.
write_step 'Writing RELEASE.md'
write_release_notes "$release_dir" "$version"
write_step 'Writing SHA256SUMS.txt'
new_checksum_file "$release_dir"

# ------------------------------------------------------------------ assert the release
#
# A run that reported success while missing an artefact has happened, which is why this is a check
# rather than a summary.
write_step 'Release contents'
show_installers "$release_dir"
for name in RELEASE.md SHA256SUMS.txt; do
  [[ -f "$release_dir/$name" ]] || die "$name was not written to $release_dir."
done
((do_source == 0)) || [[ -f "$release_dir/$source_zip" ]] || die "$source_zip is missing."
[[ -f "$release_dir/$web_zip" ]] || die "$web_zip is missing."

printf '\n'
write_ok "Release $version is in $release_dir"
