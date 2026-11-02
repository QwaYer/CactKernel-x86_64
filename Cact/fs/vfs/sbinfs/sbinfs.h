/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef SBINFS_H
#define SBINFS_H

#include <stdint.h>
#include "vfs.h"

void        sbinfs_init    (vfs_node_t *ext4_root);
vfs_node_t *sbinfs_get_root(void);

#endif
