#!/usr/bin/env bash
# Installs the app's local CA into a rooted emulator's user trust store.
#
# Android apps (Chrome included) read user certificates from
# /data/misc/user/0/cacerts-added/<subject_hash_old>.0 - the same place the
# Settings "Install a certificate" flow writes them. The system store no
# longer convinces apps on Android 14+: certificates placed in
# /system/etc/security/cacerts are ignored, and the com.android.conscrypt
# APEX that replaced it is read-only, so the tmpfs overlay trick that used to
# work is not worth it. This script simply short-circuits the multi-step
# Settings walk on a rooted emulator.
#
# The file must be owned by system:system, mode 644 and labelled
# misc_user_data_file. Reboot the emulator afterwards so the keystore rescans
# the directory and apps trust the CA from their first request.
#
# The app must have created its CA already (it does so on first launch); the
# certificate is pulled from the app's data directory. For a real device, use
# the in-app "Cài chứng chỉ" flow instead: it exports the certificate to
# Downloads and walks the user through Settings.
#
# Usage: tools/install-emulator-ca.sh [serial]
set -euo pipefail

ADB=${ADB:-adb}
SERIAL=${1:-}
if [ -n "$SERIAL" ]; then
    ADB="$ADB -s $SERIAL"
fi
PKG=git.shin.adfree
CA_DIR=/data/misc/user/0/cacerts-added

$ADB root >/dev/null
$ADB wait-for-device

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
$ADB shell cat "/data/data/$PKG/files/core/ca.pem" > "$tmp/ca.pem"
[ -s "$tmp/ca.pem" ] || { echo "no CA found - launch the app once first" >&2; exit 1; }
hash=$(openssl x509 -in "$tmp/ca.pem" -noout -subject_hash_old)
subject=$(openssl x509 -in "$tmp/ca.pem" -noout -subject)

# Install next to the certificates the user may have added by hand.
$ADB shell "mkdir -p $CA_DIR"
$ADB push "$tmp/ca.pem" "/data/local/tmp/$hash.0" >/dev/null
$ADB shell "cp /data/local/tmp/$hash.0 $CA_DIR/$hash.0 \
  && rm -f /data/local/tmp/$hash.0 \
  && chmod 644 $CA_DIR/$hash.0 \
  && chown system:system $CA_DIR/$hash.0 \
  && chcon u:object_r:misc_user_data_file:s0 $CA_DIR/$hash.0"

count=$($ADB shell "ls $CA_DIR | wc -l")
echo "installed $hash.0 ($subject); $count user certificates in $CA_DIR"
echo "reboot the emulator so the keystore picks it up"
