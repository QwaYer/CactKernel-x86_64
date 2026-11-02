# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

# SMBIOS/DMI board identification.  Not a quirk: the quirk layer
# (drivers/quirks/acpi) asks this what board it is running on and decides what
# to do about it.
kernel_libs += static_library('cact_dmi',
  files('dmi.c'),
  include_directories: cact_includes,
  implicit_include_directories: false,
  c_args: kernel_c_args)
