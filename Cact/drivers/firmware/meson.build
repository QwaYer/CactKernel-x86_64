# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

kernel_libs += static_library('cact_firmware',
  files('firmware.c'),
  include_directories: [cact_includes, include_directories('../zstd')],
  implicit_include_directories: false,
  c_args: kernel_c_args)
