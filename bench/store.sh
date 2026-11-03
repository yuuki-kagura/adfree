#!/usr/bin/env bash
# Reads the app's SQLite store off the device (debug builds only, run-as).
# The -wal is copied alongside so uncommitted pages are visible; sqlite3 needs
# both files to share the same basename, hence the fixed snapshot path.
set -e
dir=$(mktemp -d)
adb exec-out "run-as git.shin.adfree cat files/adfree.db" > "$dir/snap.db"
adb exec-out "run-as git.shin.adfree cat files/adfree.db-wal" > "$dir/snap.db-wal" 2>/dev/null || true
trap 'rm -rf "$dir"' EXIT
sqlite3 "$dir/snap.db" "$@"
