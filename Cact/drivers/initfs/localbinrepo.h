/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/* localbinrepo — flat in-memory archive for Cact .cctk modules.
 *
 * Layout (little-endian, contiguous bytes):
 *   localbinrepo_hdr_t          (32 bytes, file offset 0)
 *   localbinrepo_entry_t[count] (24 bytes each, immediately after header)
 *   name blob             (NUL-separated UTF-8 paths, 8-byte aligned)
 *   data blobs            (each entry's payload, 16-byte aligned)
 *
 * Reader walks entries[], indexes name_off into the name blob and
 * data_off as a byte offset from the *image base* (offset 0).
 */

#ifndef LOCALBINREPO_H
#define LOCALBINREPO_H

#include <stdint.h>

#define LOCALBINREPO_MAGIC    0x5052424Cu   /* 'L','B','R','P' little-endian */
#define LOCALBINREPO_VERSION  1u

/* Offset of the checksum field within localbinrepo_hdr_t (byte offset 28). */
#define LOCALBINREPO_CKSUM_OFF  28u

typedef struct {
    uint32_t magic;        /* LOCALBINREPO_MAGIC */
    uint32_t version;      /* LOCALBINREPO_VERSION */
    uint32_t total_size;   /* size of the entire image, including header */
    uint32_t count;        /* number of entries */
    uint32_t entries_off;  /* file offset to entries[] */
    uint32_t names_off;    /* file offset to name blob */
    uint32_t names_size;   /* bytes in name blob */
    uint32_t checksum;     /* CRC-32 over the image with this field zeroed */
} localbinrepo_hdr_t;

typedef struct {
    uint32_t name_off;     /* offset within names blob (0-based) */
    uint32_t name_len;     /* bytes (no trailing NUL counted) */
    uint32_t data_off;     /* file offset to payload (from image base) */
    uint32_t data_size;    /* payload size in bytes */
    uint32_t flags;        /* reserved, 0 */
    uint32_t reserved;
} localbinrepo_entry_t;

/* Compile-time assertions for struct layout and crypto constants. */
#define CACT_STATIC_ASSERT(cond) \
    extern int __cact_sa_line_##__LINE__[(cond) ? 1 : -1] __attribute__((unused))

CACT_STATIC_ASSERT(sizeof(localbinrepo_hdr_t)   == 32);
CACT_STATIC_ASSERT(sizeof(localbinrepo_entry_t) == 24);
CACT_STATIC_ASSERT(LOCALBINREPO_CKSUM_OFF      == 28);
CACT_STATIC_ASSERT(LOCALBINREPO_MAGIC          == 0x5052424Cu);
CACT_STATIC_ASSERT(LOCALBINREPO_VERSION        == 1);

#endif
