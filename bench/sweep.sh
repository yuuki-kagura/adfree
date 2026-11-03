#!/bin/bash
# usage: sweep.sh <pass-label>
# Loads the same 12 URLs in Chrome with a cache-busting query, 10 s each.
# Baseline ticks are taken once Chrome is confirmed running, so a
# force-stopped package is never sampled as /proc//stat (= /proc/stat!).
LBL="$1"
URLS=(
  "https://vnexpress.net/?adfreebench=$LBL"
  "https://cafef.vn/?adfreebench=$LBL"
  "https://kenh14.vn/?adfreebench=$LBL"
  "https://24h.com.vn/?adfreebench=$LBL"
  "https://soha.vn/?adfreebench=$LBL"
  "https://genk.vn/?adfreebench=$LBL"
  "https://www.youtube.com/?adfreebench=$LBL"
  "https://github.com/adblockplus/?adfreebench=$LBL"
  "https://en.wikipedia.org/wiki/Domain_Name_System?adfreebench=$LBL"
  "https://www.cloudflare.com/?adfreebench=$LBL"
  "https://www.apple.com/vn/?adfreebench=$LBL"
  "https://www.microsoft.com/en-vn/?adfreebench=$LBL"
)
ticks() {
  [ -z "$1" ] && { echo -1; return; }
  adb shell "cat /proc/$1/stat 2>/dev/null | sed 's/.*) //' | awk '{print \$12+\$13}'" 2>/dev/null | tr -d '\r'
}
delta() { if [ "$1" = "-1" ] || [ "$2" = "-1" ] || [ -z "$1" ]; then echo na; else echo $(( $2 - $1 )); fi; }

adb shell am force-stop com.android.chrome; sleep 3
adb shell input keyevent KEYCODE_HOME; sleep 1
adb shell am start -a android.intent.action.VIEW -d "${URLS[0]}" com.android.chrome >/dev/null 2>&1
sleep 6

AF=$(adb shell pidof -s git.shin.adfree | tr -d '\r')
AG=$(adb shell pidof -s com.adguard.android | tr -d '\r')
CR=$(adb shell pidof -s com.android.chrome | tr -d '\r')
AF0=$(ticks "$AF"); AG0=$(ticks "$AG"); CH0=$(ticks "$CR")
t0=$(date +%s)
for u in "${URLS[@]:1}"; do
  adb shell am start -a android.intent.action.VIEW -d "$u" com.android.chrome >/dev/null 2>&1
  sleep 10
done
t1=$(date +%s)
AF1=$(ticks "$AF"); AG1=$(ticks "$AG")
CH1=$(ticks "$(adb shell pidof -s com.android.chrome | tr -d '\r')")
secs=$((t1 - t0))
up=$(adb shell "cat /proc/uptime" | cut -d' ' -f1 | tr -d '\r')
tun=$(adb shell "ip addr show tun0 2>/dev/null | grep -m1 'inet '" | awk '{print $2}')
printf "%s  adfree_ticks=%s  adguard_ticks=%s  chrome_ticks=%s  wall=%ss  adfree_pct_core=%s  adguard_pct_core=%s  af_pid=%s ag_pid=%s uptime=%ss tun=%s\n" \
  "$LBL" "$(delta $AF0 $AF1)" "$(delta $AG0 $AG1)" "$(delta $CH0 $CH1)" "$secs" \
  "$(LC_ALL=C awk -v d="$(delta $AF0 $AF1)" -v s=$secs 'BEGIN{if(d=="na"||s==0){print "na"}else{printf "%.2f",d/(s*100)*100}}')" \
  "$(LC_ALL=C awk -v d="$(delta $AG0 $AG1)" -v s=$secs 'BEGIN{if(d=="na"||s==0){print "na"}else{printf "%.2f",d/(s*100)*100}}')" \
  "$AF" "$AG" "$up" "$tun"
