# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

# ==============================================================================
# Cact/drivers/zstd — in-kernel zstd compressor + decompressor
# ==============================================================================
#
# Imported from Linux 7.3.0-rc4 (object set of lib/zstd/Makefile, minus the
# non-vendored *_module.c wrappers):
#   lib/zstd/{common,compress,decompress}  — zstd_compress + zstd_decompress +
#                                            zstd_common
#   lib/xxhash.c                  — zstd's only source dependency
#   include/linux/zstd*.h, xxhash.h
#
# The imported sources are unmodified apart from their includes, which point at
# the Cact compat headers in compat/ instead of <linux/...>.  cact_zstd.c is the
# Cact glue: single-frame (de)compression into an aligned kmalloc'd workspace.
# ==============================================================================

zstd_includes = include_directories('.', 'common', 'compress', 'decompress')

kernel_libs += static_library('cact_zstd',
  files(
    'common/debug.c',
    'common/entropy_common.c',
    'common/error_private.c',
    'common/fse_decompress.c',
    'common/zstd_common.c',
    'compress/fse_compress.c',
    'compress/hist.c',
    'compress/huf_compress.c',
    'compress/zstd_compress.c',
    'compress/zstd_compress_literals.c',
    'compress/zstd_compress_sequences.c',
    'compress/zstd_compress_superblock.c',
    'compress/zstd_double_fast.c',
    'compress/zstd_fast.c',
    'compress/zstd_lazy.c',
    'compress/zstd_ldm.c',
    'compress/zstd_opt.c',
    'compress/zstd_preSplit.c',
    'decompress/huf_decompress.c',
    'decompress/zstd_ddict.c',
    'decompress/zstd_decompress.c',
    'decompress/zstd_decompress_block.c',
    'xxhash.c',
    'cact_zstd.c',
  ),
  include_directories: [zstd_includes, cact_includes],
  implicit_include_directories: false,
  c_args: kernel_c_args)
