#!/usr/bin/env bash
# Checks every script under this folder is ASCII and parses.
#
# The Linux and macOS counterpart of check_scripts.ps1, and the division of labour between them is
# worth stating because it is not symmetric.
#
# ASCII is checked for *every* script here -- .sh, .ps1 and .bat alike -- because the rule applies
# to all of them and a byte scan needs no interpreter. The reasons differ: PowerShell 5.1 decodes
# these BOM-less files in the console codepage, so a UTF-8 em-dash arrives as three bytes ending
# 0x94, cp1252 reads that as a right double quote, and PowerShell treats it as a string delimiter
# -- one em-dash in a comment therefore breaks the whole file. bash has no such trap, but a message
# full of replacement characters in a terminal set to another locale is still worth avoiding.
#
# Parsing is checked for what the host can parse: `bash -n` for the .sh files always, and the
# PowerShell files only if pwsh happens to be installed here, which on Linux it may well be. What
# this script cannot do is stand in for the Windows check -- powershell.exe 5.1 exists only there,
# and it is the version whose decoding causes the problem above. Both gates run in CI.
#
# Exits non-zero on any failure, so build_all.sh can gate on it.

set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/lib/common.sh"

failures=0
label() { printf '%s' "${1#"$here"/}"; }

# ------------------------------------------------------------------ ASCII

printf '\n%s==> ASCII%s\n' "$C_CYAN" "$C_RESET"
while IFS= read -r -d '' file; do
  # A byte test, not a decode: decoding would interpret the very characters being hunted, and
  # LC_ALL=C is what makes the bracket expression byte-oriented rather than locale-aware.
  #
  # Written as `[^[:space:] -~]` -- neither whitespace nor a printable ASCII character -- rather
  # than as a \x00-\x7F range, which was the first version and was silently wrong: GNU grep does
  # not interpret \x escapes in a basic expression, so it became "not x, 0, backslash, 7 or F" and
  # matched almost every line of every file. It reported all 23 scripts as broken and listed
  # apostrophes and hyphens as the offending bytes, which is the kind of failure that gets a check
  # deleted rather than fixed.
  count="$(LC_ALL=C grep -c '[^[:space:] -~]' -- "$file" || true)"
  if [[ -z "$count" || "$count" == "0" ]]; then
    write_note "ok    $(label "$file")"
    continue
  fi
  failures=$((failures + 1))
  bytes="$(LC_ALL=C tr -d '\011\012\015\040-\176' <"$file" | od -An -tx1 -v |
    tr -s ' \n' ' ' | cut -c1-60)"
  printf '%s  FAIL  %s -- %s line(s) with non-ASCII bytes:%s%s\n' \
    "$C_RED" "$(label "$file")" "$count" "$bytes" "$C_RESET"
  write_note '      Use -- for an em-dash and ... for an ellipsis.'
done < <(find "$here" -type f \( -name '*.sh' -o -name '*.ps1' -o -name '*.bat' \) -print0 | sort -z)

# ------------------------------------------------------------------ bash

printf '\n%s==> parse under bash%s\n' "$C_CYAN" "$C_RESET"
while IFS= read -r -d '' file; do
  if output="$(bash -n -- "$file" 2>&1)"; then
    write_note "ok    $(label "$file")"
  else
    failures=$((failures + 1))
    printf '%s  FAIL  %s -- %s%s\n' "$C_RED" "$(label "$file")" "$output" "$C_RESET"
  fi
done < <(find "$here" -type f -name '*.sh' -print0 | sort -z)

# Executable, because these are invoked by path from package.json. A .sh without the bit set fails
# with "Permission denied", which reads like a filesystem problem rather than a missing chmod.
printf '\n%s==> executable bit%s\n' "$C_CYAN" "$C_RESET"
while IFS= read -r -d '' file; do
  if [[ -x "$file" ]]; then
    write_note "ok    $(label "$file")"
  else
    failures=$((failures + 1))
    printf '%s  FAIL  %s is not executable -- chmod +x it%s\n' "$C_RED" "$(label "$file")" "$C_RESET"
  fi
done < <(find "$here" -type f -name '*.sh' -print0 | sort -z)

# ------------------------------------------------------------------ PowerShell, if present

if command -v pwsh >/dev/null 2>&1; then
  printf '\n%s==> parse under pwsh%s\n' "$C_CYAN" "$C_RESET"
  while IFS= read -r -d '' file; do
    # Parsed in a child process of that shell, because the point is how *it* decodes the file.
    # `cygpath` where it exists, which is Git Bash on Windows: `find` yields a POSIX path there and
    # pwsh is a Windows binary that cannot resolve one -- it prepends a drive letter and reports
    # every file missing. On Linux there is no cygpath and the path is already the right shape.
    native="$file"
    if command -v cygpath >/dev/null 2>&1; then native="$(cygpath -w -- "$file")"; fi
    script="\$e = \$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$native', [ref]\$null, [ref]\$e); if (\$e.Count) { 'FAIL ' + \$e[0].Message } else { 'ok' }"
    result="$(pwsh -NoProfile -Command "$script" 2>&1 | tr -d '\r' | tr '\n' ' ')"
    if [[ "$result" == ok* ]]; then
      write_note "ok    $(label "$file")"
    else
      failures=$((failures + 1))
      printf '%s  FAIL  %s -- %s%s\n' "$C_RED" "$(label "$file")" "$result" "$C_RESET"
    fi
  done < <(find "$here" -type f -name '*.ps1' -print0 | sort -z)
else
  printf '\n%s==> pwsh not installed, skipping the PowerShell parse%s\n' "$C_YELLOW" "$C_RESET"
  write_note 'Windows CI runs pnpm win:check, which covers those files under 5.1 as well.'
fi

printf '\n'
if ((failures > 0)); then
  printf '%s%s check(s) failed.%s\n' "$C_RED" "$failures" "$C_RESET"
  exit 1
fi
write_ok 'Scripts are ASCII, parse, and are executable.'
