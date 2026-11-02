# The ACPI platform layer: ACPICA's own, not ours

This file used to document a vendored pair of platform headers,
`Cact/drivers/acpi/include/platform/{acenv.h,acintel.h}`.  **Those two files were
deleted on 2026-11-02: they were never compiled.**

## Why they were dead

ACPICA's `source/include/acpi.h` does `#include "platform/acenv.h"`, and for a
quoted include the compiler searches the *including file's* directory first — so
it always resolved to
`Cact/drivers/acpi/acpica/source/include/platform/acenv.h` (the git-ignored
checkout), never to ours, whatever the `-I` order.  Preprocessing all 168 ACPI
`.c` files with the real flags (`-E -H`) confirmed it: not one opened
`Cact/drivers/acpi/include/platform/`.  The `-I Cact/drivers/acpi/include` entry
that used to sit in `cact_includes` (meson.build) resolved nothing and is gone
too.

This mattered in practice: a whole investigation concluded from that file that
`ACPI_MACHINE_WIDTH 32` was truncating firmware addresses above 4 GiB.  It was
false — the live config already has 64-bit types.

## What is compiled instead

```
acenv.h  ->  acgcc.h + aclinux.h + aclinuxex.h      (all from acpica/source/include/platform/)
```

built with `-DCACT_ACPI_FREESTANDING -DACPI_MUTEX_TYPE=0`.  `aclinux.h:338` sets
`ACPI_MACHINE_WIDTH 64` for `__x86_64__`, and types come out 64-bit
(`sizeof(ACPI_PHYSICAL_ADDRESS) == 8`, `ACPI_MAX_PTR == 0xffffffffffffffff`).
The tree is cloned on demand and patched for freestanding use at configure time
by [`tools/cact_acpica_patch.py`](../../../tools/cact_acpica_patch.py), which is
idempotent — so re-cloning `acpica/` is safe, the patch is re-applied.

## What the deleted files had, that the live config does not

If one of these ever matters, take the file from git history
(`git show 1375682:Cact/drivers/acpi/include/platform/acenv.h`) and wire it in
deliberately — replacing ACPICA's platform layer, with its own boot test:

| | deleted file | live (ACPICA) |
|---|---|---|
| `ACPI_FLUSH_CPU_CACHE()` | `wbinvd` | empty (`acenv.h:415`) |
| FACS global lock | real acquire/release | stub, `Acquired = 1` (`acenv.h:399`) |
| `ACPI_SEMAPHORE_NULL` | `-1` | `NULL` |
| `acpi_save_flags`/`restore_flags`, `cli`/`sti`, `BREAKPOINT3` | inline asm in `acintel.h` | `acgcc.h`/`acenv.h` defaults |

The first two are the ones with possible behavioural consequences (S-state /
resume cache coherency, and firmware methods that use the ACPI global lock).
