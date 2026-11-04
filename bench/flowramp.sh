#!/usr/bin/env bash
# usage: flowramp.sh [counts...]   default: 256 512 1024 2048
#
# How long the tunnel takes to *open* N flows. `flowcpu.sh` measures what a live
# relay costs once it exists; this measures the queue that builds them, because a
# relay is not free at creation either: every flow waits for app attribution (a
# binder round trip to netd), a `protect()` and a dial, all on one FIFO worker.
#
# Read it as a throughput curve, not a latency one. If the wall time to reach the
# stage line grows linearly in N, setup is a fixed cost per flow and a burst of
# new connections drains at a constant rate. If it grows faster, something in the
# setup path is being charged by how many flows are already open — and the visible
# symptom on a phone is a page whose later requests stall behind its earlier ones.
#
# The harness is run in `nudge` mode: one byte down each socket, enough that the
# engine classifies the flow and dials, then quiet. The hold is short because only
# the ramp is timed; the stage line is what the clock stops on.
#
# Needs the same setup as `flowcpu.sh`: debug build, `bench/flows` in the helper's
# `files/`, screen held on.
set -e
COUNTS=("$@")
if [ ${#COUNTS[@]} -eq 0 ]; then COUNTS=(256 512 1024 2048); fi
HELPER="${HELPER:-git.shin.komorei}"
LOG=files/flows.log
MODE=nudge
PORT=80
HOLD=10
HOSTS=(www.google.com clients3.google.com connectivitycheck.gstatic.com
       fonts.gstatic.com play.googleapis.com time.google.com)

as_helper() { adb shell "run-as $HELPER sh -c '$*'" | tr -d '\r'; }

echo "mode=$MODE hold=${HOLD}s helper=$HELPER"
adb shell svc power stayon true >/dev/null
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
as_helper "cat > files/flows" < bench/flows
as_helper "chmod 700 files/flows"
for n in "${COUNTS[@]}"; do
    as_helper "rm -f $LOG"
    # The clock is started in the same shell that launches the harness, and the
    # wait runs on the device: a host-side poll would add an adb round trip to
    # every sample and would time out at the large counts.
    echo -n "n=$n  "
    as_helper "t0=\$(date +%s)
               nohup ./files/flows $n 1 $HOLD $MODE $PORT ${HOSTS[*]} > $LOG 2>&1 &
               for i in \$(seq 1 300); do grep -q ^stage $LOG && break; sleep 1; done
               echo ramp=\$((\$(date +%s) - t0))s \$(head -1 $LOG)"
    as_helper "pkill -f files/flows" 2>/dev/null || true
    sleep 20
done
as_helper "rm -f files/flows $LOG"
