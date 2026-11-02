# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

kernel_objects += custom_target('asm-mm',
  input: 'mm.asm',
  output: 'mm.o',
  command: [nasm, '-f', 'elf64', '@INPUT@', '-o', '@OUTPUT@'])

kernel_libs += static_library('cact_memory',
  files('pat.c'),
  include_directories: cact_includes,
  implicit_include_directories: false,
  c_args: kernel_c_args)
