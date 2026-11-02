# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

# The board identity itself lives in Cact/drivers/dmi; what stays here is the
# per-machine policy applied on top of it.
kernel_libs += static_library('cact_quirks_acpi',
  files('acpi_quirks.c'),
  include_directories: cact_includes,
  implicit_include_directories: false,
  c_args: kernel_c_args)
