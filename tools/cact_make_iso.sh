#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

#
# Assemble a GRUB-bootable ISO for the Cact kernel.
#
# Usage: cact_make_iso.sh <kernel.bin> <grub.cfg> <isodir> <out.iso> [localbinrepo.img]
#                                                     [firmrepo.tar.zst]
#                                                     [netdrvrepo.tar.zst]
#
# With a localbinrepo image the module is copied in and signed, which is what the
# Makefile's iso-full target did.  The staging directory is recreated every
# time so a stale localbinrepo.img can never leak into a kernel-only image.
#
# The firmrepo archive rides along as a second Multiboot2 module: the kernel
# serves it as /dev/firmrepo for cgoct to copy into tmpfs.  The netdrvrepo
# archive is a third module served as /dev/netdrvrepo, from which firmextr
# streams a network .cctk and modload maps it.  Each placeholder line is filled
# in when the archive is passed and dropped otherwise, so a kernel-only image
# still boots (same contract as CactBridge).
set -euo pipefail

kernel=$1
grub_cfg=$2
isodir=$3
output=$4
localbinrepo=${5:-}
firmrepo=${6:-}
netdrvrepo=${7:-}

rm -rf "$isodir"
mkdir -p "$isodir/boot/grub"
cp "$kernel" "$isodir/boot/kernel.bin"

if [ -n "$localbinrepo" ]; then
  if [ ! -f "$localbinrepo" ]; then
    echo "cact_make_iso.sh: localbinrepo image not found: $localbinrepo" >&2
    exit 1
  fi
  cp "$localbinrepo" "$isodir/boot/localbinrepo.img"
  python3 "$(dirname "$(readlink -f "$0")")/cact_sign_localbinrepo.py" "$isodir/boot/localbinrepo.img"
fi

if [ -n "$firmrepo" ] && [ ! -f "$firmrepo" ]; then
  echo "cact_make_iso.sh: firmrepo archive not found: $firmrepo" >&2
  exit 1
fi

if [ -n "$netdrvrepo" ] && [ ! -f "$netdrvrepo" ]; then
  echo "cact_make_iso.sh: netdrvrepo archive not found: $netdrvrepo" >&2
  exit 1
fi

cp "$grub_cfg" "$isodir/boot/grub/grub.cfg"

if [ -n "$firmrepo" ]; then
  cp "$firmrepo" "$isodir/boot/firmrepo.tar.zst"
  sed -i 's|FIRMREPO_ISO_PLACEHOLDER|firmrepo.tar.zst|' \
      "$isodir/boot/grub/grub.cfg"
else
  sed -i '/FIRMREPO_ISO_PLACEHOLDER/d' "$isodir/boot/grub/grub.cfg"
  echo "cact_make_iso.sh: no firmrepo archive — booting without /dev/firmrepo" >&2
fi

if [ -n "$netdrvrepo" ]; then
  cp "$netdrvrepo" "$isodir/boot/netdrvrepo.tar.zst"
  sed -i 's|NETDRVREPO_ISO_PLACEHOLDER|netdrvrepo.tar.zst|' \
      "$isodir/boot/grub/grub.cfg"
else
  sed -i '/NETDRVREPO_ISO_PLACEHOLDER/d' "$isodir/boot/grub/grub.cfg"
  echo "cact_make_iso.sh: no netdrvrepo archive — booting without /dev/netdrvrepo" >&2
fi

grub-mkrescue -o "$output" "$isodir"
