#!/usr/bin/env bash
# usage: flowmem.sh [step] [stages] [hold_s] [mode] [port]
#
# Holds a staircase of concurrent TCP flows inside the tunnel and samples the
# AdFree process's memory at each tread, so the on-device cost of a live flow
# can be read off the slope instead of inferred from `size_of`.
#
# The flows do not come from the shell on this pass, and the reason is a timing
# trap rather than a platform rule: `files/capture-shell` is read when the tunnel
# is built, so a tunnel established before the marker exists keeps the hole at
# uid 2000 (`dumpsys connectivity` reads `Uids: <{0-1999, 2001-...}>`, and those
# sockets keep their wlan0 source instead of `10.111.42.1`). Rebuilding
# protection with the marker in place does route the shell. Running as a
# *captured* app uid sidesteps the question entirely: any debuggable package the
# tunnel is not excluding, entered with `run-as`, which drops to that uid and
# executes from its own data directory (`/data/local/tmp` is not executable
# there). The helper is expected to be a development install whose data can be
# written to; the only files it gains are `files/flows` and its log, and the
# script deletes both on the way out.
#
# Both halves of every flow are counted from /proc/net/tcp: the client socket on
# the helper uid and the origin socket the engine dials on its own uid. Those two
# numbers are the measured concurrency, and they should track each other one for
# one — the regression is against that, not against what the harness asked for.
#
# Needs the debug build (so the tunnel is running and `dumpsys meminfo` answers),
# `bench/flows.c` built and pushed to the helper's `files/`, and the screen held
# on (`svc power stayon true` plus a WAKEUP): the holds are timed on
# CLOCK_MONOTONIC, which stops in suspend, so a dozing device turns 60 s treads
# into minutes and this script into a timeout.
set -e
STEP="${1:-1024}"
STAGES="${2:-4}"
HOLD="${3:-60}"
MODE="${4:-http}"
PORT="${5:-80}"
PKG=git.shin.adfree
HELPER="${HELPER:-git.shin.komorei}"
BIN=bench/flows
HEXPORT=$(printf '%04X' "$PORT")
LOG=files/flows.log
HOSTS=(www.google.com clients3.google.com connectivitycheck.gstatic.com
       fonts.gstatic.com play.googleapis.com time.google.com www.bing.com
       developers.google.com)

uid_of() { adb shell "dumpsys package $1" | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -1; }
as_helper() { adb shell "run-as $HELPER sh -c '$*'"; }
helper_log() { adb shell "run-as $HELPER cat $LOG" 2>/dev/null || true; }

app_uid=$(uid_of "$PKG")
helper_uid=$(uid_of "$HELPER")

# Memory of the tunnel process. `heap_alloc` is what the engine's own allocations
# move; `native_pss` and the totals catch what the allocator has actually touched.
sample() {
    printf '%s ' "$(date +%T)"
    adb shell "dumpsys meminfo $PKG" | awk '
        /^  Native Heap/ {printf "native_pss=%s private_dirty=%s heap_size=%s heap_alloc=%s", $3, $4, $7, $8}
        /^[ \t]+TOTAL:/  {printf " total_pss=%s total_swap=%s", $2, $6}'
    echo
}

# Established sockets on the target port, split by the two ends of a relay.
count() {
    printf '%s ' "$(date +%T)"
    adb shell cat /proc/net/tcp | awk -v app="$app_uid" -v hlp="$helper_uid" -v rp="$HEXPORT" '
        NR > 1 && $4 == "01" {
            split($3, r, ":");
            if (r[2] != rp) next;
            if ($8 == app) a++;
            else if ($8 == hlp) s++;
        }
        END {printf "client_flows=%d relay_flows=%d\n", s + 0, a + 0}'
}

wait_for() {
    for _ in $(seq 1 180); do
        if helper_log | grep -q -E "^$1"; then return 0; fi
        if ! adb shell pgrep -f files/flows >/dev/null 2>&1; then
            echo "harness died" >&2
            helper_log >&2
            return 1
        fi
        sleep 1
    done
    echo "timed out waiting for $1" >&2
    return 1
}

echo "step=$STEP stages=$STAGES hold=${HOLD}s mode=$MODE port=$PORT app_uid=$app_uid helper=$HELPER/$helper_uid"
as_helper "rm -f $LOG"
as_helper "cat > files/flows" < "$BIN"
as_helper "chmod 700 files/flows"

for i in 1 2 3; do echo "$(date +%T) baseline"; sample; count; sleep 10; done

as_helper "nohup ./files/flows $STEP $STAGES $HOLD $MODE $PORT ${HOSTS[*]} > $LOG 2>&1 &"
for s in $(seq 1 "$STAGES"); do
    wait_for "stage,$s,"
    echo "$(date +%T) $(helper_log | grep -m1 "^stage,$s,") (fill)"
    for _ in 1 2 3 4; do sleep 15; sample; count; done
done
wait_for "released,"
echo "$(date +%T) $(helper_log | grep -m1 '^released,')"
for _ in 1 2 3; do sleep 15; sample; count; done
helper_log
as_helper "rm -f files/flows $LOG"
