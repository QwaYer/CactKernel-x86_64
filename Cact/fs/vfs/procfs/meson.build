# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

kernel_libs += static_library('cact_procfs',
  files(
    'procfs.c',
    'procfs_std.c',
    'procfs_proc.c',
  ),
  include_directories: cact_includes,
  implicit_include_directories: false,
  c_args: kernel_c_args)
