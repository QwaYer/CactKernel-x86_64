# Vendored zstd — provenance and re-sync

`Cact/drivers/zstd/` links the zstd decompressor into the kernel.  Most of it is
a verbatim copy of the **Linux kernel's** zstd tree, relocated into this layout
and adapted to CactOS's headers by the include rewrite below; a thin CactOS layer
(`compat/`, `cact_zstd.*`) plugs it into this kernel.

| | |
|---|---|
| Upstream | <https://github.com/torvalds/linux> |
| Ref | tag `v7.3-rc4` — commit `93f51579e7df248780214094418f205253383cc5` |
| Sync tool | `python3 tools/vendor_sync.py check zstd` |

The tree is *exactly* "upstream + the edits recorded in the tool's manifest" —
`check` proves it, and `update` reproduces it bit for bit.

## Where each vendored file comes from

| Repo path | Upstream path | SPDX |
|---|---|---|
| `common/`, `compress/`, `decompress/` | `lib/zstd/{common,compress,decompress}/` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `xxhash.c` | `lib/xxhash.c` | `BSD-2-Clause OR GPL-2.0-only` (© Yann Collet) |
| `compat/zstd.h` | `include/linux/zstd.h` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `compat/zstd_lib.h` | `include/linux/zstd_lib.h` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `compat/zstd_errors.h` | `include/linux/zstd_errors.h` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `compat/xxhash.h` | `include/linux/xxhash.h` | `BSD-2-Clause OR GPL-2.0-only` (© Yann Collet) |
| `cact_zstd.c`, `cact_zstd.h`, `meson.build`, `compat/{compiler,errno,kernel,limits,math64,module,printk,stddef,string,swab,types,unaligned}.h` | — CactOS's own | `GPL-3.0-or-later` |

Linux ships a few more files under `lib/zstd/` that CactOS does not link
(`Makefile`, `decompress_sources.h`, `zstd_{common,compress,decompress}_module.c`);
they are not vendored.

## Recorded edits

1. **Include rewrite** — every `#include <linux/X.h>` becomes the path to
   `<repo>/compat/X.h` relative to the including file:
   `common/`, `compress/`, `decompress/` get `"../compat/X.h"`, the root file
   `xxhash.c` gets `"compat/X.h"`, and files already in `compat/` get `"X.h"`.
   Nothing else in those files is touched.
2. **Guard rename** — `compat/zstd.h`'s include guard `LINUX_ZSTD_H` →
   `CACT_ZSTD_H` (it is no longer the Linux header).
3. **SPDX for xxhash** — upstream `lib/xxhash.c` / `include/linux/xxhash.h` carry
   no `SPDX-License-Identifier` (only the inline BSD-2-Clause/GPL-2 text), so one
   line was added inside their existing licence comment.  These two are the only
   place where CactOS's files differ from upstream beyond rules 1–2.

## Re-sync

```sh
python3 tools/vendor_sync.py check zstd     # read-only; "in sync" means the above holds
python3 tools/vendor_sync.py update zstd    # after bumping the ref in the tool
```

`update` fetches the ref (a blobless sparse clone of the Linux tree, cached under
`~/.cache/cact-vendor-sync`), applies rules 1–3, and leaves the result for review
in `git diff`.  To move to a newer Linux, bump `ref` in `tools/vendor_sync.py`
and the table above, then `check`/`update` again.

The decompressor is linked directly (not through Linux's `zstd_*` module
wrappers), so the full static-linking API from `compat/zstd_lib.h` is available;
the DCtx workspace setup mirroring Linux's `decompress_single()` lives in
`cact_zstd.c`.
