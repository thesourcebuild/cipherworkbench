#!/usr/bin/env bash
# Shared helpers for the Linux and macOS scripts, mirroring scripts/lib/common.ps1.
#
# The function names are the PowerShell ones in snake_case -- write_step for Write-Step,
# project_version for Get-ProjectVersion -- because the two files get read side by side and a
# helper doing the same job under a different name is a tax on every future edit to either. Where
# behaviour genuinely differs the comment says so; there are four such places and all four are
# platform facts rather than choices.
#
# Two rules for anything added here.
#
# Pure ASCII, like the PowerShell half. The reason is different -- there is no cp1252 decoding
# problem in bash -- but the outcome is the same: these files are read on machines with unknown
# locales, and a UTF-8 em-dash in a message is one more thing that can render as garbage in a
# terminal set to something else. Use -- and ... . check_scripts.sh enforces it.
#
# Quote every path. This repo lives under a directory containing parentheses, and while bash does
# not parse those inside a quoted string, an unquoted $root in a command substitution or a [[ ]]
# test will split or glob and fail somewhere far from the mistake. That is the shell analogue of
# the PowerShell subexpression problem the package.json note describes.

set -euo pipefail

# ------------------------------------------------------------------ presentation

# Colour only when stdout is a terminal. Piping to a file or a CI log should not collect escape
# codes, and `command -v tput` is checked because a minimal container may have no terminfo.
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  C_CYAN="$(tput setaf 6)"
  C_GREY="$(tput setaf 8 2>/dev/null || tput setaf 7)"
  C_YELLOW="$(tput setaf 3)"
  C_RED="$(tput setaf 1)"
  C_GREEN="$(tput setaf 2)"
  C_RESET="$(tput sgr0)"
else
  C_CYAN="" C_GREY="" C_YELLOW="" C_RED="" C_GREEN="" C_RESET=""
fi

write_step() { printf '\n%s==> %s%s\n' "$C_CYAN" "$1" "$C_RESET"; }
write_note() { printf '%s    %s%s\n' "$C_GREY" "$1" "$C_RESET"; }
write_warn() { printf '%s !! %s%s\n' "$C_YELLOW" "$1" "$C_RESET" >&2; }
write_ok() { printf '%s%s%s\n' "$C_GREEN" "$1" "$C_RESET"; }

# Every failure path goes through here, so a message and a non-zero exit cannot come apart.
die() {
  printf '\n%sERROR: %s%s\n' "$C_RED" "$1" "$C_RESET" >&2
  exit 1
}

# ------------------------------------------------------------------ the repo

# Two levels up from scripts/lib, which is what makes this correct from any working directory.
# The PowerShell version has the same two Split-Path calls for the same reason, and both broke
# once when the scripts moved into subfolders with only one.
repo_root() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$here/../.." && pwd
}

# Electron's own variables, inherited from a parent shell, change how the app starts -- and the
# symptom is a dev session behaving unlike everyone else's with nothing on screen to say why.
clear_inherited_electron_env() {
  unset ELECTRON_RUN_AS_NODE ELECTRON_NO_ATTACH_CONSOLE ELECTRON_ENABLE_LOGGING \
    ELECTRON_ENABLE_STACK_DUMPING ELECTRON_DEFAULT_ERROR_MODE 2>/dev/null || true
}

assert_dependencies() {
  local root="$1"
  command -v node >/dev/null 2>&1 || die 'node is not on PATH. Install Node 20.11 or newer.'
  command -v pnpm >/dev/null 2>&1 ||
    die 'pnpm is not on PATH. Install it with: npm install -g pnpm'
  [[ -d "$root/node_modules" ]] ||
    die "Dependencies are not installed. Run: pnpm install --dir '$root'"
}

# pnpm, run from the repo root whatever the caller's directory. `--dir` rather than a `cd`, so a
# failure leaves the caller where it was.
invoke_pnpm() {
  local root
  root="$(repo_root)"
  pnpm --dir "$root" "$@"
}

# ------------------------------------------------------------------ ports and processes

# Three probes, because none of them is everywhere: `ss` on modern Linux, `lsof` on macOS and
# older distributions, and bash's own /dev/tcp as the fallback that needs nothing installed.
test_port_open() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]" && return 0
    return 1
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN -n -P >/dev/null 2>&1 && return 0
    return 1
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1 && return 0
  return 1
}

wait_for_port() {
  local port="$1" timeout="${2:-90}" pid="${3:-}"
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      return 2 # the server died before it listened, which is a different failure from a timeout
    fi
    test_port_open "$port" && return 0
    sleep 0.4
  done
  return 1
}

# The whole tree, not just the pid. `pnpm web` is a wrapper and Next is its child, so killing the
# parent alone leaves the dev server holding the port after this script returns -- and the next
# run's port check then finds it. Same reason the PowerShell half has Stop-ProcessTree.
stop_process_tree() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  # Negative pid signals the whole process group, which is why the launchers start their server
  # with setsid: without a group of its own, this would signal the script too.
  kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null && ((waited < 50)); do
    sleep 0.1
    waited=$((waited + 1))
  done
  kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

# Started in its own process group so stop_process_tree can signal the group without signalling
# this script. `setsid` where available, which is every Linux; macOS falls back to a plain
# background job, where the group kill degrades to a single-pid kill.
start_pnpm_background() {
  local root
  root="$(repo_root)"
  if command -v setsid >/dev/null 2>&1; then
    setsid pnpm --dir "$root" "$@" &
  else
    pnpm --dir "$root" "$@" &
  fi
  printf '%s' "$!"
}

# ------------------------------------------------------------------ build output

remove_build_output() {
  local root="$1"
  local targets=(
    "apps/web/out" "apps/web/.next"
    "apps/desktop/renderer" "apps/desktop/dist"
    ".turbo" "apps/web/.turbo" "apps/desktop/.turbo"
  )
  local target
  for target in "${targets[@]}"; do
    if [[ -e "$root/$target" ]]; then
      write_note "removing $target"
      rm -rf -- "$root/$target"
    fi
  done
}

path_size() {
  local target="$1"
  [[ -e "$target" ]] || { printf 'missing'; return; }
  du -sh -- "$target" 2>/dev/null | cut -f1 | tr -d '[:space:]'
}

show_artifacts() {
  local root="$1"
  shift
  write_step 'Artifacts'
  local rel full
  for rel in "$@"; do
    full="$root/$rel"
    if [[ -e "$full" ]]; then
      printf '  %-34s %s\n' "$rel" "$(path_size "$full")"
    else
      write_warn "$rel is missing"
    fi
  done
}

show_installers() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  local file
  while IFS= read -r -d '' file; do
    printf '  %-46s %s\n' "$(basename "$file")" "$(path_size "$file")"
  done < <(find "$dir" -maxdepth 1 -type f \
    \( -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' -o -name '*.zip' -o -name '*.exe' \) \
    -print0 2>/dev/null | sort -z)
}

# ------------------------------------------------------------------ version

# The root `version` file is the single source of truth. Read with `head -1` and trimmed, so a
# trailing newline -- which that file deliberately has -- is not part of the value.
project_version() {
  local root="$1"
  local file="$root/version"
  [[ -f "$file" ]] || die "The version file is missing: $file"
  local value
  value="$(head -n 1 -- "$file" | tr -d '[:space:]')"
  [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] ||
    die "The version file does not hold a semver version: '$value'"
  printf '%s' "$value"
}

# Every workspace manifest, which is the set sync_version and create-package both walk.
manifest_paths() {
  local root="$1"
  printf '%s\n' "$root/package.json"
  local base dir
  for base in "apps" "packages" "packages/tools"; do
    [[ -d "$root/$base" ]] || continue
    for dir in "$root/$base"/*/; do
      # The trailing slash comes from the glob, so it is stripped rather than doubled -- a label
      # reading "packages/tools/parity//package.json" is the sort of thing that makes a reader
      # wonder whether the path is right.
      dir="${dir%/}"
      [[ -f "$dir/package.json" ]] && printf '%s
' "$dir/package.json"
    done
  done
}

# Rewritten by regex on the raw text, anchored to a two-space-indented top-level field -- not
# through a JSON parse and re-serialise, which would reorder the keys and reformat every file.
# The PowerShell half does exactly the same for exactly that reason.
sync_package_json_versions() {
  local root="$1" version="$2" changed=0 file current
  while IFS= read -r file; do
    current="$(sed -n 's/^  "version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n 1)"
    if [[ -z "$current" ]]; then
      write_warn "${file#"$root"/} has no top-level version field"
      continue
    fi
    if [[ "$current" == "$version" ]]; then continue; fi
    # A temporary file then a move, so an interrupted run cannot leave a half-written manifest.
    sed "s/^\(  \"version\"[[:space:]]*:[[:space:]]*\"\)[^\"]*\(\"\)/\1$version\2/" \
      "$file" >"$file.tmp"
    mv -- "$file.tmp" "$file"
    write_note "set ${file#"$root"/} to $version"
    changed=$((changed + 1))
  done < <(manifest_paths "$root")
  printf '%s' "$changed"
}

# ------------------------------------------------------------------ archives

# git archive where this is a git checkout, and tar otherwise. The PowerShell half probes the same
# way -- and note it has to clear $LASTEXITCODE afterwards because `git rev-parse` exits 128
# outside a repository; a shell has no such trap, but the probe is still the same one.
new_source_archive() {
  local root="$1" out="$2"
  mkdir -p -- "$(dirname -- "$out")"
  # rev-parse --verify HEAD, not just --git-dir: a repository that exists but has no commit yet --
  # this one, right now -- has a .git directory and no HEAD, and `git archive HEAD` dies with
  # "not a valid object name" under set -e rather than falling through to the copy below. The
  # PowerShell New-SourceArchive already checks the commit, not just the directory; this did not.
  if command -v git >/dev/null 2>&1 && git -C "$root" rev-parse --verify HEAD >/dev/null 2>&1; then
    write_note 'git archive: tracked files only'
    git -C "$root" archive --format=zip --output "$out" HEAD
    add_docs_to_archive "$root" "$out"
    return
  fi
  write_note 'no commit to archive here, so falling back to a filtered copy'
  command -v zip >/dev/null 2>&1 || die 'zip is not installed, and there is no git checkout to archive.'
  ( cd "$root" && zip -q -r -- "$out" . \
      -x 'node_modules/*' '*/node_modules/*' \
         '.git/*' '.turbo/*' '*/.turbo/*' \
         'dist/*' 'apps/web/out/*' 'apps/web/.next/*' \
         'apps/desktop/renderer/*' 'apps/desktop/dist/*' )
  add_docs_to_archive "$root" "$out"
}

# docs/ folded into the source zip itself rather than shipped as a loose folder beside it.
#
# git archive only ever emits tracked files, so docs/ is missing from that path unless it happens
# to be committed -- and the filtered copy the other branch falls back to already includes it,
# making this append a harmless no-op there rather than a second, diverging way of getting it in.
# One place, called from both branches, rather than a separate copy step in create-package.sh:
# that used to live there, wrote the folder out to $release_dir/docs next to the zips instead of
# inside either of them, and used $releaseDir where every other line in this project spells it
# $release_dir -- caught only because the two never matched.
add_docs_to_archive() {
  local root="$1" out="$2"
  [[ -d "$root/docs" ]] || return 0
  command -v zip >/dev/null 2>&1 || die 'zip is not installed, and docs/ needs to be added to the archive.'
  ( cd "$root" && zip -q -r -- "$out" docs )
}

compress_directory_contents() {
  local dir="$1" out="$2"
  command -v zip >/dev/null 2>&1 || die 'zip is not installed.'
  mkdir -p -- "$(dirname -- "$out")"
  # From inside the directory, so the archive has no leading path component -- which is what
  # "contents" means and what a static host expects when the zip is unpacked.
  ( cd "$dir" && zip -q -r -- "$out" . )
}

# sha256sum on Linux, shasum on macOS. The output format is deliberately the one both `sha256sum
# -c` and `shasum -a 256 -c` accept, so the file is checkable on either.
new_checksum_file() {
  local dir="$1" out="${2:-$1/SHA256SUMS.txt}"
  local -a files=()
  local file
  while IFS= read -r -d '' file; do files+=("$(basename "$file")"); done < <(
    find "$dir" -maxdepth 1 -type f ! -name 'SHA256SUMS.txt' -print0 | sort -z
  )
  ((${#files[@]} > 0)) || { write_warn 'nothing to checksum'; return 0; }
  if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$dir" && sha256sum -- "${files[@]}" >"$(basename -- "$out")" )
  elif command -v shasum >/dev/null 2>&1; then
    ( cd "$dir" && shasum -a 256 -- "${files[@]}" >"$(basename -- "$out")" )
  else
    die 'Neither sha256sum nor shasum is installed.'
  fi
  write_note "wrote $(basename -- "$out") for ${#files[@]} file(s)"
}

# Written *before* the checksum file, so the checksums cover it. Same ordering as the PowerShell
# half, and for the same reason.
write_release_notes() {
  local dir="$1" version="$2"
  local out="$dir/RELEASE.md"
  {
    printf '# Cipher Workbench %s\n\n' "$version"
    printf 'Built on %s.\n\n' "$(date -u '+%Y-%m-%d')"
    printf '## What is here\n\n'
    local file name
    while IFS= read -r -d '' file; do
      name="$(basename -- "$file")"
      case "$name" in
        RELEASE.md | SHA256SUMS.txt) continue ;;
        *-source.zip) printf -- '- `%s` -- the source tree.\n' "$name" ;;
        *-web.zip) printf -- '- `%s` -- the static web build. Unpack onto any static host.\n' "$name" ;;
        *.AppImage) printf -- '- `%s` -- Linux, self-contained. `chmod +x` and run.\n' "$name" ;;
        *.deb) printf -- '- `%s` -- Debian and Ubuntu package.\n' "$name" ;;
        *.rpm) printf -- '- `%s` -- Fedora and RHEL package.\n' "$name" ;;
        *.exe) printf -- '- `%s` -- Windows installer.\n' "$name" ;;
        *) printf -- '- `%s`\n' "$name" ;;
      esac
    done < <(find "$dir" -maxdepth 1 -type f -print0 | sort -z)
    printf '\n## Verifying\n\n'
    printf '```sh\nsha256sum -c SHA256SUMS.txt\n```\n\n'
    printf 'Everything runs locally. Nothing you type leaves the machine.\n'
  } >"$out"
  write_note 'wrote RELEASE.md'
}

# ------------------------------------------------------------------ argument parsing

# A bare `--` is dropped rather than treated as a flag.
#
# pnpm forwards the separator to the script verbatim, which is the same fact that makes
# `pnpm win:x -- -Flag` fail on the PowerShell side -- there it is fatal, because PowerShell
# rejects an empty parameter name. Here it can simply be ignored, so `pnpm sh:package --release`
# and `pnpm sh:package -- --release` both work.
is_separator() { [[ "$1" == "--" ]]; }
