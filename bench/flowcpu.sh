#!/usr/bin/env bash
# usage: flowcpu.sh [hold_s] [spec...]      spec = <mode><count>, e.g. nudge1024
# default: hold 40, specs base nudge1024 http1024 nudge2048
#
# How much CPU the tunnel spends to keep a relay alive, and how much it spends on
# a request through one. `flowmem.sh` asks what a relay weighs; this asks what it
# costs, which is a different question because the forwarder rebuilds its poll set
# and sweeps its relay table on every pass.
#
# The shape to look for is superlinear. The forwarder loop is event-paced, not
# clock-paced: a relay that receives something writes the wake eventfd, which ends
# the wait and runs a whole pass, and every pass walks every relay. So the work per
# second is (passes per second) x (relays per pass), and if the passes themselves
# grow with N the total grows with N^2.
#
# Two modes separate the two costs. `nudge` opens the flow and writes one byte —
# enough for the engine to classify it and dial the origin — then leaves it quiet,
# so CPU over a `nudge` window is the price of holding a relay with no traffic in
# the tunnel. `http` re-pokes every socket with a keep-alive HEAD every ten
# seconds, so the same window also pays for about N/10 requests a second. The two
# at one count give the per-request cost; one mode across two counts gives the
# scaling in N.
#
# CPU is read per thread, not per process, and the two data-path threads are told
# apart by what they do rather than by their `std::thread` name: on this device the
# workers appear as `Thread-<n>`, because the name set at spawn does not survive
# into `/proc/<pid>/task/<tid>/comm`. The forwarder is the thread with the system
# bulk (it lives in `poll()`); the packet reader is the one with the user bulk (it
# parses and rewrites what it reads).
#
# Needs the debug build (tunnel up, /proc readable), `bench/flows` built and pushed
# into the helper's `files/`, and the screen held on: `svc power stayon true` plus a
# WAKEUP, because holds are timed on CLOCK_MONOTONIC, which stops in suspend.
set -e
HOLD="${1:-40}"
shift || true
SPECS=("$@")
if [ ${#SPECS[@]} -eq 0 ]; then SPECS=(base nudge1024 http1024 nudge2048); fi
PKG=git.shin.adfree
HELPER="${HELPER:-git.shin.komorei}"
BIN=bench/flows
LOG=files/flows.log
PORT=80
HOSTS=(www.google.com clients3.google.com connectivitycheck.gstatic.com
       fonts.gstatic.com play.googleapis.com time.google.com www.bing.com
       developers.google.com)

# adb hands back CRLF on every line, and a uid compared as "10344\r" matches
# nothing, so a count taken straight from `dumpsys` reads zero relays on a full
# tunnel. Strip it once, in one place.
clean() { tr -d '\r'; }
uid_of() { adb shell "dumpsys package $1" | clean | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -1; }
as_helper() { adb shell "run-as $HELPER sh -c '$*'" | clean; }
pid() { adb shell pidof "$PKG" | clean | tr -d '\n'; }
APP_UID="$(uid_of "$PKG")"

# Live relays, counted where the engine keeps them: a socket the tunnel itself
# opened toward port 80 belongs to a relay, and nothing else in this uid writes one.
live() {
    adb shell cat /proc/net/tcp | clean | awk -v app="$APP_UID" '
        NR > 1 && $4 == "01" { split($3, r, ":"); if (r[2] == "0050" && $8 == app) a++ }
        END {print a + 0}'
}

# Per-thread CPU in clock ticks, as `tid|name|utime|stime`. The name is the text
# between the parentheses, so a thread called "Jit thread pool" does not shift the
# two counters after it, and it travels in a delimited field for the same reason.
# It is decoration only: bionic renumbers the unnamed workers as ART sees them, so
# the same forwarder is `Thread-3196` in one dump and `Thread-7427` in the next, and
# the join is on the tid.
dump_threads() {
    local p; p=$(pid)
    adb shell "for f in /proc/$p/task/*/stat; do awk '{o=index(\$0,\"(\"); i=index(\$0,\")\"); \
        n=substr(\$0,o+1,i-o-1); r=substr(\$0,i+2); split(r,a,\" \"); \
        print \$1 \"|\" n \"|\" a[12] \"|\" a[13]}' \$f; done" | clean > "$1"
}

# The threads that moved between the two dumps, biggest delta first. Three ticks is
# 30 ms; below that a thread is not part of the story.
thread_report() {
    awk -F'|' 'NR==FNR {u[$1]=$3; s[$1]=$4; next}
        {du=$3-u[$1]; ds=$4-s[$1]; if (du+ds >= 3) printf "%8d ms total %7d ms sys  %s %s\n", \
            (du+ds)*10, ds*10, $1, $2}' "$1" "$2" | sort -rn
}

cpu() { adb shell "cat /proc/$(pid)/stat" | clean | awk '{printf "%s %s %s", $14, $15, $10}'; }

# Traffic across the tunnel during the window, so "quiet" is a fact rather than
# an assumption: an origin that answers the one byte the harness writes makes
# every relay in the window a busy one, and then the poll set and the sweeps are
# both being paid for real traffic. Fields of `/proc/net/dev`: rx bytes, rx
# packets, then tx bytes, tx packets.
tun() { adb shell cat /proc/net/dev | clean | awk '/tun0/ {print $2, $3, $10, $11}'; }

# One adb round trip that waits on the device: polling the log from the host costs a
# shell launch per try, and at 2048 sockets the open takes long enough that a
# host-side loop runs out of iterations before the stage line lands.
fill() {
    as_helper "nohup ./files/flows $2 1 $HOLD $1 $PORT ${HOSTS[*]} > $LOG 2>&1 &
               for i in \$(seq 1 90); do grep -q ^stage $LOG && break; sleep 2; done"
}

run_one() {
    local spec="$1" mode n
    if [ "$spec" = base ]; then mode=nudge; n=0; else
        mode=$(sed 's/[0-9]*$//' <<< "$spec"); n=$(sed 's/^[a-z]*//' <<< "$spec")
    fi
    echo "--- $spec"
    if [ "$n" -gt 0 ]; then
        as_helper "rm -f $LOG"
        fill "$mode" "$n"
        echo "    filled: $(as_helper "head -1 $LOG")  live=$(live)"
    fi
    local t0=/tmp/flowcpu.t0 t1=/tmp/flowcpu.t1 before after du ds df n0 n1
    dump_threads "$t0"
    before=$(cpu)
    n0=$(tun)
    sleep "$HOLD"
    after=$(cpu)
    n1=$(tun)
    dump_threads "$t1"
    echo "    tun0: $(awk -v a="$n0" -v b="$n1" 'BEGIN{split(a,x," ");split(b,y," ");
        printf "+%d B +%d pk in, +%d B +%d pk out", y[1]-x[1], y[2]-x[2], y[3]-x[3], y[4]-x[4]}')"
    echo "    live after hold: $(live)"
    if [ "$n" -gt 0 ]; then echo "    harness: $(as_helper "tail -1 $LOG")"; fi
    set -- $before
    local bu=$1 bs=$2 bf=$3
    set -- $after
    du=$(( $1 - bu )); ds=$(( $2 - bs )); df=$(( $3 - bf ))
    # One tick is 10 ms of CPU.
    echo "    process cpu: user=$((du * 10))ms sys=$((ds * 10))ms faults=$df"
    if [ "$n" -gt 0 ]; then
        echo "    per_relay: $(( (du + ds) * 10 / n )) ms of process cpu over the ${HOLD}s window"
    fi
    echo "    threads:"
    thread_report "$t0" "$t1" | sed 's/^/      /'
    # Let the relays retire before the next tread, or the count is a lie.
    as_helper "pkill -f files/flows" 2>/dev/null || true
    sleep 15
}

echo "hold=${HOLD}s pkg=$PKG helper=$HELPER app_uid=$APP_UID"
adb shell svc power stayon true >/dev/null
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
as_helper "rm -f $LOG"
as_helper "cat > files/flows" < "$BIN"
as_helper "chmod 700 files/flows"
for spec in "${SPECS[@]}"; do run_one "$spec"; done
as_helper "rm -f files/flows $LOG"
