#!/bin/bash
# usage: win.sh <package> <seconds> <label>
# CPU delta over one quiet window plus the PSS at the window's end.
# Guards: a package that is not running is reported as na, never sampled as
# /proc//stat (which is /proc/stat, the whole-system line).
pkg="$1"; secs="$2"; label="$3"
pid=$(adb shell pidof -s "$pkg" | tr -d '\r')
if [ -z "$pid" ]; then echo "$label $pkg NOT RUNNING"; exit 1; fi
t0=$(adb shell "cat /proc/$pid/stat | sed 's/.*) //' | awk '{print \$12+\$13}'" 2>/dev/null | tr -d '\r')
sleep "$secs"
pid2=$(adb shell pidof -s "$pkg" | tr -d '\r')
if [ -z "$pid2" ] || [ "$pid2" != "$pid" ]; then echo "$label $pkg pid changed ($pid -> ${pid2:-dead}) mid-window: DISCARD"; exit 1; fi
t1=$(adb shell "cat /proc/$pid/stat | sed 's/.*) //' | awk '{print \$12+\$13}'" 2>/dev/null | tr -d '\r')
adb shell dumpsys meminfo "$pid" > "/tmp/mem_${label}.txt" 2>/dev/null
pss=$(grep -m1 -E "^ *TOTAL +[0-9]" "/tmp/mem_${label}.txt" | awk '{print $2}')
swap=$(grep -m1 -E "^ *TOTAL +[0-9]" "/tmp/mem_${label}.txt" | awk '{print $5}')
d=$((t1 - t0))
up=$(adb shell "cat /proc/uptime" | cut -d' ' -f1 | tr -d '\r')
printf "%-14s %-22s %ss  ticks=%s  cpu_pct_core=%s  pss_kb=%s swap_kb=%s pid=%s uptime=%ss\n" \
  "$label" "$pkg" "$secs" "$d" "$(LC_ALL=C awk -v d=$d -v s=$secs 'BEGIN{printf "%.2f", d/(s*100)*100}')" "$pss" "$swap" "$pid" "$up"
