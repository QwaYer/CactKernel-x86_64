/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef SYM_H
#define SYM_H

#include <stdint.h>

const char* sym_resolve_addr(uint64_t addr, uint64_t* offset);

#endif
