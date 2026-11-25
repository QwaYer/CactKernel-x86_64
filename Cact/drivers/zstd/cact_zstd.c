/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * cact_zstd.c — glue between the Cact kernel and the vendored zstd
 * decompressor.
 *
 * The decompressor is linked directly (not through Linux's exported zstd_*
 * wrappers in zstd_decompress_module.c), so the full static-linking API from
 * zstd_lib.h is available here.  A DCtx is placed in an aligned kmalloc'd
 * workspace for the duration of one call, mirroring Linux's decompress_single().
 */

#include <stdint.h>
#include <stddef.h>

#define ZSTD_STATIC_LINKING_ONLY
#include "compat/zstd.h"

#include "memory.h"
#include "cact_zstd.h"

size_t cact_zstd_frame_size(const void *src, size_t src_size)
{
	unsigned long long size;

	if (!src || !src_size)
		return 0;

	size = ZSTD_getFrameContentSize(src, src_size);
	if (size == ZSTD_CONTENTSIZE_UNKNOWN || size == ZSTD_CONTENTSIZE_ERROR)
		return 0;

	return (size_t)size;
}

size_t cact_zstd_decompress(const void *src, size_t src_size,
			    void *dst, size_t dst_capacity)
{
	size_t ws_size;
	void *ws;
	ZSTD_DCtx *dctx;
	size_t ret;

	if (!src || !src_size || !dst || !dst_capacity)
		return 0;

	ws_size = ZSTD_estimateDCtxSize();
	/* zstd requires the workspace 8-byte aligned; kmalloc() only guarantees
	 * the heap's block alignment, so ask for an explicitly aligned block. */
	ws = kmalloc_aligned(ws_size, 16);
	if (!ws)
		return 0;

	dctx = ZSTD_initStaticDCtx(ws, ws_size);
	if (!dctx) {
		kfree(ws);
		return 0;
	}

	ret = ZSTD_decompressDCtx(dctx, dst, dst_capacity, src, src_size);
	kfree(ws);

	if (ZSTD_isError(ret))
		return 0;

	return ret;
}

size_t cact_zstd_dstream_ws_size(void)
{
	return ZSTD_estimateDCtxSize();
}

void *cact_zstd_dstream_init(void *ws, size_t ws_size)
{
	ZSTD_DCtx *dctx;

	if (!ws || ws_size < ZSTD_estimateDCtxSize())
		return 0;

	dctx = ZSTD_initStaticDCtx(ws, ws_size);
	if (!dctx)
		return 0;

	/* Same as ZSTD_initDStream(): begin a fresh session. */
	ZSTD_DCtx_reset(dctx, ZSTD_reset_session_only);
	return dctx;
}

int cact_zstd_dstream_step(void *ctx, const void *in, size_t in_size,
			   size_t *in_pos, void *out, size_t out_size,
			   size_t *out_pos)
{
	ZSTD_inBuffer ib;
	ZSTD_outBuffer ob;
	size_t ret;

	if (!ctx || !in_pos || !out_pos)
		return -1;

	ib.src = in;
	ib.size = in_size;
	ib.pos = *in_pos;
	ob.dst = out;
	ob.size = out_size;
	ob.pos = *out_pos;

	ret = ZSTD_decompressStream((ZSTD_DCtx *)ctx, &ob, &ib);
	*in_pos = ib.pos;
	*out_pos = ob.pos;

	if (ZSTD_isError(ret))
		return -1;

	return ret == 0 ? 1 : 0;
}
