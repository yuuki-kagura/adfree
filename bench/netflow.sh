#!/usr/bin/env bash
# usage: netflow.sh [concurrency] [hold_s] [port]
#
# Behaviour of the tunnel while it holds N live relays, as opposed to
# bench/flowmem.sh, which asks what a relay costs. The numbers here say whether
# the relay table tracks the connections at all: how many origin sockets the
# engine keeps, how many descriptors the process holds for them, what it spends
# in CPU and page faults to keep them warm, and how its RSS moves while the flows
# stay up.
#
# The flows come from a captured app uid for the reason given in bench/flowmem.sh:
# whether adb's uid is inside the tunnel depends on when `files/capture-shell` was
# written relative to the last protection start, and this run did not want to
# depend on that. The binary and log are removed from the helper on the way out.
set -e
N="${1:-768}"
HOLD="${2:-90}"
PORT="${3:-80}"
PKG=git.shin.adfree
HELPER="${HELPER:-git.shin.komorei}"
BIN=bench/flows
HEXPORT=$(printf '%04X' "$PORT")
LOG=files/flows.log
# Hosts the engine can reach. Every tenth connection gets a fresh HEAD, so the
# origin sees activity and should keep the relay; if the relay table still falls
# short of the client count, the shortfall is the tunnel's own, and that is the
# number worth looking at.
HOSTS=(www.google.com clients3.google.com connectivitycheck.gstatic.com
       fonts.gstatic.com play.googleapis.com time.google.com www.bing.com
       developers.google.com)

app_uid=$(adb shell "dumpsys package $PKG" | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -1)
helper_uid=$(adb shell "dumpsys package $HELPER" | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -1)
as_helper() { adb shell "run-as $HELPER sh -c '$*'"; }

stat_line() {
    printf '%s ' "$(date +%T)"
    pid=$(adb shell pidof "$PKG" | tr -d '\r\n')
    adb shell "dumpsys meminfo $PKG" | awk -v pid="$pid" '
        /^  Native Heap/ {printf "native_pss=%s private_dirty=%s heap_size=%s heap_alloc=%s", $3, $4, $7, $8}
        /^[ \t]+TOTAL:/  {printf " total_pss=%s", $2}'
    adb shell "cat /proc/$pid/stat" | awk '{printf " utime=%s stime=%s minflt=%s", $14, $15, $10}'
    adb shell "cat /proc/$pid/status" | awk '/^VmRSS:/ {printf " rss=%s", $2} /^Threads:/ {printf " threads=%s", $2}'
    adb shell cat /proc/net/tcp | awk -v app="$app_uid" -v hlp="$helper_uid" -v rp="$HEXPORT" '
        NR > 1 {
            split($3, r, ":");
            if (r[2] != rp) next;
            if ($4 == "01") {
                if ($8 == app) a++;
                else if ($8 == hlp) s++;
            } else if ($8 == hlp && ($4 == "08" || $4 == "07")) h++;
        }
        END {printf " relay_estab=%d client_estab=%d client_halfclosed=%d\n", a + 0, s + 0, h + 0}'
}

echo "n=$N hold=${HOLD}s port=$PORT app_uid=$app_uid helper_uid=$helper_uid"
as_helper "rm -f $LOG"
as_helper "cat > files/flows" < "$BIN"
as_helper "chmod 700 files/flows"
for i in 1 2; do echo "$(date +%T) baseline"; stat_line; sleep 5; done

as_helper "nohup ./files/flows $N 1 $HOLD http $PORT ${HOSTS[*]} > $LOG 2>&1 &"
for _ in $(seq 1 90); do
    if as_helper "grep -q ^stage $LOG"; then break; fi
    sleep 2
done
echo "$(date +%T) filled: $(as_helper "cat $LOG" | head -1)"
for _ in $(seq 1 9); do sleep 10; stat_line; done
echo "$(date +%T) end: $(as_helper "tail -1 $LOG")"
as_helper "rm -f files/flows $LOG"
