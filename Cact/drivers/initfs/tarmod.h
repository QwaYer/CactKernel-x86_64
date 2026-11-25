/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef TARMOD_H
#define TARMOD_H

#include <stdint.h>

#include "multiboot2.h"

/* Read one member out of a ustar+zstd Multiboot2 archive (drvrepo / netdrvrepo)
 * on demand and in place: the archive is never staged, only the member that is
 * asked for is decompressed and copied out.
 *
 * On a hit *out_data points into a static scratch buffer that the next call
 * overwrites — the same contract as initfs_modblob_get().  The member is
 * matched by basename, so both "/usr/lib/modules/ahci.cctk" and "ahci.cctk"
 * find the archive's usr/lib/modules/ahci.cctk.
 *
 * Returns 0 on hit, -1 on miss or a malformed archive. */
int tarmod_get(const mb2_module_info_t *mod, const char *path,
               const uint8_t **out_data, uint32_t *out_size);

/* Resolve a loadable module image the way every loader wants it: the staged
 * localbinrepo image first, then the drvrepo and netdrvrepo archives (each
 * streamed on demand).  This is the single front door for pci_load_module /
 * fs_mod / usb_mod, so `modload <name>.cctk` works whichever archive carries
 * the module; firmware and the console font deliberately do NOT go through it
 * (they only ever live in localbinrepo). */
int modsrc_get(const char *path, const uint8_t **out_data, uint32_t *out_size);

#endif /* TARMOD_H */
