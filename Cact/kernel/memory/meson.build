# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

kernel_objects += custom_target('asm-mm',
  input: 'mm.asm',
  output: 'mm.o',
  command: [nasm, '-f', 'elf64', '@INPUT@', '-o', '@OUTPUT@'])

# The PAT driver used to be pat.c here; it now lives in Rust as
# rust_mm/src/vmm/pat.rs (pat_init / pat_enable_wc_for_framebuffer, C linkage),
# so this directory contributes only the asm stub.
