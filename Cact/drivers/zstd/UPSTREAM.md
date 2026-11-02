# Vendored zstd — provenance and re-sync

`Cact/drivers/zstd/` links the zstd decompressor into the kernel.  Most of it
is a verbatim copy of the **Linux kernel's** zstd tree; a thin CactOS layer
(`compat/`, `cact_zstd.*`) adapts it to this kernel's headers.

Source snapshot: **Linux 7.3.0-rc4** (`lib/zstd/`, `lib/xxhash.c`,
`include/linux/zstd{,_lib,_errors}.h`, `include/linux/xxhash.h`).

## What is upstream and what is ours

| Path | Origin | SPDX |
|---|---|---|
| `common/`, `compress/`, `decompress/` | Linux `lib/zstd/*` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `xxhash.c` | Linux `lib/xxhash.c` | `BSD-2-Clause OR GPL-2.0` (© Yann Collet) |
| `compat/xxhash.h` | Linux `include/linux/xxhash.h` | `BSD-2-Clause OR GPL-2.0` (© Yann Collet) |
| `compat/zstd.h` | Linux `include/linux/zstd.h` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `compat/zstd_lib.h` | Linux `include/linux/zstd_lib.h` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `compat/zstd_errors.h` | Linux `include/linux/zstd_errors.h` | `GPL-2.0+ OR BSD-3-Clause` (© Meta Platforms) |
| `cact_zstd.c`, `cact_zstd.h`, `meson.build` | CactOS | `GPL-3.0-or-later` |
| `compat/{compiler,errno,kernel,limits,math64,module,printk,stddef,string,swab,types,unaligned}.h` | CactOS kernel shims | `GPL-3.0-or-later` |

## Local modifications to the upstream files

Two, both mechanical:

1. The Linux licence header had been stripped when the tree was copied in;
   it has been restored verbatim (SPDX + copyright block) so the files match
   upstream byte-for-byte apart from the include paths below.
2. Kernel `<linux/…>` includes are rewritten to the local `compat/` shims, e.g.
   `#include <linux/zstd.h>` → `"../compat/zstd.h"`,
   `#include <linux/xxhash.h>` → `"../compat/xxhash.h"`,
   `#include <linux/types.h>` → `"../compat/types.h"`, and likewise for
   `limits.h`, `math64.h`, `printk.h`, `swab.h`, `unaligned.h`, `zstd_errors.h`.

Nothing else differs — the algorithms are untouched.

## Re-sync procedure

```sh
LS="$HOME/Projects/linux import/linux/linux-master"   # a Linux source tree
C="$PWD/Cact/drivers/zstd"

# lib/zstd/*  (kernel-side zstd)  -- only the stripped header + includes differ
for p in common compress decompress; do
    for f in "$C/$p"/*; do
        b=$(basename "$f")
        diff <(tail -n +12 "$LS/lib/zstd/$p/$b") "$f"   # expect: include rewrites only
    done
done

diff "$LS/lib/xxhash.c"            "$C/xxhash.c"
diff "$LS/include/linux/xxhash.h"  "$C/compat/xxhash.h"
diff "$LS/include/linux/zstd.h"    "$C/compat/zstd.h"
diff "$LS/include/linux/zstd_lib.h" "$C/compat/zstd_lib.h"
diff "$LS/include/linux/zstd_errors.h" "$C/compat/zstd_errors.h"
```

To pull in a newer Linux: re-copy those files, re-apply the `compat/` include
rewrites, and re-add the licence header from the same file in the new tree.
`cact_zstd.*` and everything under `compat/` that is CactOS's own is left
untouched.  The default `frame_size` fast path and the DCtx workspace setup
(mirroring Linux's `decompress_single()`) live in `cact_zstd.c`.
