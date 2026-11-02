#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

#
# Build and run the host-side SMBIOS discovery test (tools/dmi_parse_test).
#
# Cact/drivers/dmi/dmi.c and Cact/drivers/acpi/efi_config.c are compiled
# unmodified for the host against the stub headers in ./stub, with test.c
# emulating the physical address space the probe walks.  Nothing here is linked
# into the kernel.
#
# Why a host test at all: the two cases that broke DMI on real hardware — a
# 64-bit SMBIOS 3.x table above 4 GiB, and a stale legacy entry point shadowing
# a working one — cannot be produced by QEMU firmware (SeaBIOS and OVMF both
# place a 32-bit entry point in low memory only), so booting cannot regress-test
# them.
#
# Usage: tools/dmi_parse_test/run.sh [output-binary]
#        ninja -C build-meson dmi-parse-test
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${1:-${TMPDIR:-/tmp}/cact_dmi_parse_test}"

cc="${CC:-cc}"
cflags=(-std=gnu17 -Wall -Wextra -O1)

# The real headers of everything the probe talks to (cact_acpi.h, efi_config.h,
# dmi.h) are used as-is, so an API change breaks this build instead of silently
# testing a stale copy; only the kernel's own kernel.h/klib.h/memory.h and
# multiboot2.h are stubbed.
"$cc" "${cflags[@]}" \
    -I "$here/stub" \
    -I "$root/Cact/drivers/dmi" \
    -I "$root/Cact/drivers/acpi" \
    -o "$out" \
    "$here/test.c" \
    "$root/Cact/drivers/dmi/dmi.c" \
    "$root/Cact/drivers/acpi/efi_config.c"

exec "$out"
