#!/bin/bash
# One forced client-port collision, watched from both sides at once.
#   usage: ./dportrun.sh <bound_port> <noprobe:0|1> <host> [host...]
set -u
BP="$1"; NOPROBE="$2"; shift 2
BPH=$(printf '%04X' "$BP")
echo "=== dport NOPROBE=$NOPROBE bound=$BP hosts=$* ==="
adb shell "run-as git.shin.komorei sh -c 'NOPROBE=$NOPROBE ./files/dport $BP 80 $* > files/dp.log 2>&1'" &
runner=$!
i=0
while [ $i -lt 9 ]; do
  sleep 1
  i=$((i+1))
  snap=$(adb shell "cat /proc/net/tcp" 2>/dev/null | tr -d '\r' | awk -v bp="$BPH" -f dport.awk)
  echo "t=$i $snap"
done
wait $runner
echo "--- harness ---"
adb shell "run-as git.shin.komorei cat files/dp.log" 2>&1 | tr -d '\r'
