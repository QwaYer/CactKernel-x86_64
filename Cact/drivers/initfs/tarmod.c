/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * tarmod.c — read one .cctk out of a compressed driver archive, on demand.
 *
 * drvrepo.tar.zst / netdrvrepo.tar.zst are ustar archives of usr/lib/modules/
 * that GRUB hands over as Multiboot2 modules and the kernel serves in place.
 * They are far too big to stage (and would have to be decompressed whole), so a
 * loader asks for one member by name: this streams the compressed archive with
 * the in-kernel zstd decoder, walks the ustar headers, and copies out only the
 * member that matched.
 *
 * The extracted member lands in a static scratch buffer — one lookup is in
 * flight at a time (module loading is sequential), and callers copy the image
 * out at once, exactly as they do for the localbinrepo staging buffer.
 */

#include <stdint.h>
#include <stddef.h>

#include "tarmod.h"
#include "initfs_modblob.h"
#include "cact_zstd.h"
#include "memory.h"
#include "vfs.h"

/* Largest driver module is well under this; the buffer dominates tarmod's bss. */
#define TARMOD_MAX_MEMBER  (128u * 1024u)
/* Decompressed bytes pulled out of zstd in one go. */
#define TARMOD_OUT_CHUNK   8192u

static uint8_t tar_scratch[TARMOD_MAX_MEMBER];

typedef struct {
    void           *dc;                     /* zstd streaming decoder */
    const uint8_t  *in;
    size_t          in_size;
    size_t          in_pos;
    uint8_t         out[TARMOD_OUT_CHUNK];
    size_t          out_pos;
    size_t          out_len;
    int             frame_done;
} tar_stream_t;

/* Refill the output window.  Returns 0 when out[] holds bytes (or the frame
 * ended cleanly), -1 on a truncated or corrupt stream. */
static int ts_fill(tar_stream_t *s) {
    for (;;) {
        size_t op;

        if (s->in_pos >= s->in_size) {
            s->out_pos = s->out_len = 0;
            return s->frame_done ? 0 : -1;
        }

        op = 0;
        int r = cact_zstd_dstream_step(s->dc, s->in, s->in_size, &s->in_pos,
                                       s->out, sizeof(s->out), &op);
        if (r < 0)
            return -1;

        s->out_pos = 0;
        s->out_len = op;
        if (op)
            return 0;
        if (r == 1)
            s->frame_done = 1;
    }
}

/* Read exactly n decompressed bytes into dst. */
static int ts_read(tar_stream_t *s, void *dst, size_t n) {
    uint8_t *d = (uint8_t *)dst;

    while (n) {
        size_t take;

        if (s->out_pos >= s->out_len) {
            if (ts_fill(s) != 0 || s->out_len == 0)
                return -1;
        }

        take = s->out_len - s->out_pos;
        if (take > n)
            take = n;

        __builtin_memcpy(d, s->out + s->out_pos, take);
        s->out_pos += take;
        d += take;
        n -= take;
    }
    return 0;
}

static int ts_skip(tar_stream_t *s, size_t n) {
    uint8_t tmp[128];

    while (n) {
        size_t take = n > sizeof(tmp) ? sizeof(tmp) : n;
        if (ts_read(s, tmp, take) != 0)
            return -1;
        n -= take;
    }
    return 0;
}

static const char *base_of(const char *p) {
    const char *b = p;
    for (; *p; p++)
        if (*p == '/')
            b = p + 1;
    return b;
}

/* Does the archive member name end in the requested basename? */
static int base_eq(const char *name, const char *want) {
    const char *b = base_of(name);
    size_t i;

    for (i = 0; want[i]; i++)
        if (b[i] != want[i])
            return 0;
    return b[i] == '\0';
}

/* ustar stores the octal size (and other numbers) as NUL/space-terminated
 * ASCII; both forms appear in the wild. */
static size_t octal(const uint8_t *p, int n) {
    size_t v = 0;
    int i;

    for (i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (c == '\0' || c == ' ')
            break;
        if (c < '0' || c > '7')
            return 0;
        v = (v << 3) + (size_t)(c - '0');
    }
    return v;
}

int tarmod_get(const mb2_module_info_t *mod, const char *path,
               const uint8_t **out_data, uint32_t *out_size) {
    size_t ws_size;
    void *ws, *dc;
    const char *want;
    tar_stream_t s;
    uint8_t hdr[512];
    int rc = -1;

    if (!mod || !mod->mod_start || !mod->mod_size || !path || !out_data || !out_size)
        return -1;

    ws_size = cact_zstd_dstream_ws_size();
    ws = kmalloc_aligned(ws_size, 16);
    if (!ws)
        return -1;

    dc = cact_zstd_dstream_init(ws, ws_size);
    if (!dc) {
        kfree(ws);
        return -1;
    }

    want = base_of(path);

    s.dc = dc;
    s.in = (const uint8_t *)vmm_p2v((uint64_t)mod->mod_start);
    s.in_size = mod->mod_size;
    s.in_pos = 0;
    s.out_pos = 0;
    s.out_len = 0;
    s.frame_done = 0;

    for (;;) {
        char name[101];
        size_t size;

        if (ts_read(&s, hdr, sizeof(hdr)) != 0)
            break;
        if (hdr[0] == '\0')             /* end-of-archive block */
            break;

        __builtin_memcpy(name, hdr, 100);
        name[100] = '\0';
        size = octal(hdr + 124, 12);

        if (base_eq(name, want)) {
            if (size == 0 || size > sizeof(tar_scratch))
                break;
            if (ts_read(&s, tar_scratch, size) != 0)
                break;
            *out_data = tar_scratch;
            *out_size = (uint32_t)size;
            rc = 0;
            break;
        }

        /* Skip the payload, padded to a 512-byte block boundary. */
        if (ts_skip(&s, (size + 511u) & ~(size_t)511u) != 0)
            break;
    }

    kfree(ws);
    return rc;
}

/* VFS-sourced module staging: a .cctk that lives as a file (an extracted
 * module, or one the image still carries) is read here and stays valid until
 * the next modsrc_get(), the same contract as the archive scratch.  The buffer
 * grows to the largest module and is kept for the kernel's lifetime. */
static uint8_t *modsrc_vfs_buf;
static uint32_t modsrc_vfs_cap;

static int modsrc_vfs_get(const char *path, const uint8_t **out_data,
                          uint32_t *out_size) {
    struct vfs_node *node;
    uint32_t fsz;
    int br;

    if (!path)
        return -1;
    node = vfs_resolve_path(path);
    if (!node)
        return -1;

    fsz = node->size;
    if (!fsz) {
        vfs_node_unref(node);
        return -1;
    }
    if (fsz > modsrc_vfs_cap) {
        uint8_t *nb = (uint8_t *)kmalloc(fsz);
        if (!nb) {
            vfs_node_unref(node);
            return -1;
        }
        if (modsrc_vfs_buf)
            kfree(modsrc_vfs_buf);
        modsrc_vfs_buf = nb;
        modsrc_vfs_cap = fsz;
    }

    br = read_vfs(node, 0, fsz, (char *)modsrc_vfs_buf);
    vfs_node_unref(node);
    if (br <= 0)
        return -1;

    *out_data = modsrc_vfs_buf;
    *out_size = (uint32_t)br;
    return 0;
}

int modsrc_get(const char *path, const uint8_t **out_data, uint32_t *out_size) {
    /* The staged userland image first (a disk-booted system still carries its
     * modules there), then the two driver archives, then the VFS — so
     * modload can name a module wherever it lives, and a *detect* probe sees
     * exactly what the loader would load (they share this one door). */
    if (initfs_modblob_get(path, out_data, out_size) == 0)
        return 0;
    if (tarmod_get(&mb2_drvrepo_module, path, out_data, out_size) == 0)
        return 0;
    if (tarmod_get(&mb2_netdrvrepo_module, path, out_data, out_size) == 0)
        return 0;
    return modsrc_vfs_get(path, out_data, out_size);
}
