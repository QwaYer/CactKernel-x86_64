# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

# Per-machine quirk blacklist: the one table a hardware workaround is declared
# in (see quirks.h).  Drivers only read the bits it returns, so the table is
# the only file that grows when a new broken machine shows up.
kernel_libs += static_library('cact_quirks',
  files('quirks.c'),
  include_directories: cact_includes,
  implicit_include_directories: false,
  c_args: kernel_c_args)
