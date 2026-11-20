#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project
#
# S3 (suspend-to-RAM) round-trip over QEMU.
#
# Boots the full ISO headlessly and drives the serial/VT console *through QEMU*:
#   - guest output is read from COM1 (`-serial file:`),
#   - keystrokes are injected with the monitor `sendkey` command (the shell reads
#     the console, not the serial RX line),
#   - the wake is the monitor `system_wakeup`: on it the platform starts the CPU
#     in real mode at the firmware waking vector (FACS.FirmwareWakingVector ->
#     0xA000), the same path a power button takes on real hardware.
# Then it checks the kernel's S3 trace on the console.
#
#   tools/cact_s3_test.sh [iso]
#
# Env: CACT_ACCEL (kvm|tcg, default kvm), CACT_MEM (default 2G),
#      CACT_BOOT_TIMEOUT (default 180 s), CACT_STEP_TIMEOUT (default 60 s).
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
iso="${1:-$root/build-meson/cact-full.iso}"
accel="${CACT_ACCEL:-kvm}"
mem="${CACT_MEM:-2G}"
boot_timeout="${CACT_BOOT_TIMEOUT:-180}"
step_timeout="${CACT_STEP_TIMEOUT:-60}"

[[ -f "$iso" ]] || { echo "[s3] no ISO: $iso" >&2; exit 2; }
command -v socat >/dev/null || { echo "[s3] socat is required" >&2; exit 2; }

work="$(mktemp -d)"
log="$work/console.log"
mon="$work/mon.sock"
qemu_pid=""

cleanup() {
    [[ -n "$qemu_pid" ]] && kill "$qemu_pid" 2>/dev/null
    wait 2>/dev/null
    [[ -n "${KEEP_LOG:-}" ]] && cp -f "$log" "${KEEP_LOG}" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

cpu_flag=(-cpu host)
[[ "$accel" == tcg ]] && cpu_flag=(-cpu max)

echo "[s3] booting $iso (accel=$accel) ..."
qemu-system-x86_64 \
    -accel "$accel" "${cpu_flag[@]}" -smp 4 -m "$mem" -M q35 \
    -cdrom "$iso" -boot d \
    -display none -no-reboot -no-shutdown -rtc base=localtime \
    -serial "file:$log" \
    -monitor "unix:$mon,server,nowait" \
    -device qemu-xhci -device usb-kbd \
    >/dev/null 2>&1 &
qemu_pid=$!
sleep 1
kill -0 "$qemu_pid" 2>/dev/null || { echo "[s3] QEMU exited at start (accel=$accel)" >&2; exit 1; }

mon() { printf '%s\n' "$1" | socat - "UNIX-CONNECT:$mon" >/dev/null 2>&1; }

# Type a string on the emulated keyboard; `sendkey` takes one key at a time.
type_str() {
    local s="$1" k
    for (( i = 0; i < ${#s}; i++ )); do
        k="${s:i:1}"
        [[ "$k" == "/" ]] && k=slash
        mon "sendkey $k"
        sleep 0.12
    done
}

wait_for() {
    local pat="$1" secs="$2" i=0
    while (( i < secs * 10 )); do
        grep -qaE "$pat" "$log" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
fail() {
    echo "[s3] FAIL: $1" >&2
    echo "[s3] --- console tail ---" >&2
    sed 's/\x1b\[[0-9;]*m//g' "$log" 2>/dev/null | tail -n 30 >&2
    exit 1
}

wait_for 'cact:' "$boot_timeout" || fail "no shell prompt within ${boot_timeout}s"
echo "[s3] shell up; typing '/usr/sbin/suspend' on the console"
type_str '/usr/sbin/suspend'
mon "sendkey ret"

if ! wait_for 'entering S3 \(SLP_EN\)' 15; then
    wait_for 'entering S3 \(SLP_EN\)' "$step_timeout" \
        || fail "the kernel never reached the S3 entry point"
fi
echo "[s3] asleep; waking via monitor: system_wakeup"
mon 'system_wakeup'

if wait_for 'S3 resume complete' "$step_timeout"; then
    echo "[s3] PASS — the machine resumed"
elif wait_for 'resumed from S3' "$step_timeout"; then
    echo "[s3] PARTIAL — the trampoline ran (long mode back), resume did not finish"
    rc=3
else
    fail "no resume after wake"
fi

echo "[s3] --- S3 trace ---"
sed 's/\x1b\[[0-9;]*m//g' "$log" \
  | grep -aE 'power: (suspend to RAM|parking|all worker|wake vector|entering S3|resumed from|machine state|S3 resume)' \
  || true
exit "${rc:-0}"
