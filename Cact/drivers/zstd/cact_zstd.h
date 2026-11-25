/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_ZSTD_H
#define CACT_ZSTD_H

#include <stdint.h>
#include <stddef.h>

/*
 * In-kernel zstd decompressor (ported from Linux 7.3.0-rc4, lib/zstd + xxhash).
 *
 * The firmware loader stages compressed blobs (*.zst) out of the localbinrepo image
 * and unpacks them here.  Only single-frame, whole-buffer decompression is
 * exposed: a firmware blob is small and read in one piece, so the streaming
 * API is not needed.
 */

/* Uncompressed size declared by the frame header, or 0 when it is absent or
 * the input is not a valid zstd frame. */
size_t cact_zstd_frame_size(const void *src, size_t src_size);

/* Decompress one zstd frame from src into dst.  Returns the number of bytes
 * written, or 0 on any failure (bad frame, truncation, dst too small). */
size_t cact_zstd_decompress(const void *src, size_t src_size,
                            void *dst, size_t dst_capacity);

/*
 * Streaming single-frame decompression, for the drvrepo/netdrvrepo reader: it
 * pulls one member out of a compressed archive without staging the whole thing
 * in RAM.  The decoder lives in a caller-owned workspace, so nothing here
 * allocates and there is no persistent decoder state.
 */

/* Bytes a streaming decoder needs in its workspace (>= this, 16-byte aligned). */
size_t cact_zstd_dstream_ws_size(void);

/* Initialise a streaming decoder inside ws.  Returns the handle, or NULL when
 * the workspace is too small. */
void *cact_zstd_dstream_init(void *ws, size_t ws_size);

/* One step: consume *in_pos of in, produce *out_pos of out.  Returns 1 when the
 * frame is complete, 0 when more input/output is needed, -1 on error. */
int cact_zstd_dstream_step(void *ctx, const void *in, size_t in_size,
                           size_t *in_pos, void *out, size_t out_size,
                           size_t *out_pos);

#endif /* CACT_ZSTD_H */
