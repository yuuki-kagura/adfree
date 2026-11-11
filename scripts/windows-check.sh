#!/usr/bin/env bash
# Does the core compile for Windows yet?
#
# Windows support is a port of the socket layer, so the useful question each day
# is not "does the app run on Windows" but "how many places still assume Unix".
# This prints that number and the first few, and exits non-zero while any
# remain, so a CI job can hold the line.
#
# Needs: rustup target add x86_64-pc-windows-gnu, and a mingw C compiler
# (Arch: pacman -S mingw-w64-gcc) because the TLS stack builds C for the target.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

TARGET=x86_64-pc-windows-gnu

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "missing target: rustup target add $TARGET" >&2
    exit 2
fi
if ! command -v x86_64-w64-mingw32-gcc >/dev/null; then
    echo "missing C cross compiler for $TARGET (mingw-w64-gcc)" >&2
    exit 2
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT

if cargo check --manifest-path rust/Cargo.toml --target "$TARGET" --lib >"$log" 2>&1; then
    echo "windows: the core compiles for $TARGET"
    exit 0
fi

errors=$(grep -cE '^error' "$log")
echo "windows: $errors errors still assume Unix"
grep -oE -- '--> src/[a-zA-Z0-9_/]+\.rs' "$log" | sort | uniq -c | sort -rn | head -12
echo
echo "first failures:"
grep -E '^error' -A 2 "$log" | head -40
exit 1
