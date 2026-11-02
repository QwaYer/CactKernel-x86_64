# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

# task.asm owns the context-switch entry points; there are no C sources of our
# own in this directory (the scheduler itself lives in proc/sched).
kernel_objects += custom_target('asm-task',
  input: 'task.asm',
  output: 'task_asm.o',
  command: [nasm, '-f', 'elf64', '@INPUT@', '-o', '@OUTPUT@'])
