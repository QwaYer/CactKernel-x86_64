# The ACPI platform layer

ACPICA is configured through `acpica/source/include/platform/`, which lives in
the **git-ignored checkout** (`acpica/`, cloned on demand).  Nothing in the
tracked tree is that layer — for a while a pair of headers did live here
(`include/platform/{acenv.h,acintel.h}`), but they were never compiled (see
*History*) and were deleted.

## How the layer is chosen

`acpi.h` does `#include "platform/acenv.h"`; for a quoted include the compiler
searches the *including file's* directory first, so it always resolves to the
clone's `source/include/platform/acenv.h`, whatever the `-I` order.  That header
then pulls in:

```
acenv.h -> acgcc.h + aclinux.h + aclinuxex.h      (-DCACT_ACPI_FREESTANDING)
```

`aclinux.h` is chosen because the compiler target defines `__linux__`, and it
happens to give the right widths for us (`ACPI_MACHINE_WIDTH 64` for
`__x86_64__`; `sizeof(ACPI_PHYSICAL_ADDRESS) == 8`).

`tools/cact_acpica_patch.py` runs at configure time (from `meson.build`) and
edits the checkout, idempotently:

1. gates the host-libc includes in `acenv.h`/`aclinux.h` on
   `!CACT_ACPI_FREESTANDING` (a re-cloned `acpica/` is re-patched, so nothing
   there is hand-maintained);
2. injects `#include "cact_acenv.h"` at the **end** of `acenv.h` — after
   `aclinux.h` and after acenv.h's own `#ifndef` defaults, so the overrides win.
   If that anchor ever disappears the configure **fails**, deliberately: a
   silently inactive override is the trap the previous arrangement had.

## What CactOS overrides — `Cact/drivers/acpi/cact_acenv.h` (live)

| Macro | ACPICA default | Ours | Why |
|---|---|---|---|
| `ACPI_FLUSH_CPU_CACHE()` | empty | `wbinvd` | called by `hwsleep.c`/`hwesleep.c` for every sleep state below S4; the ACPI spec requires the flush, and leaving dirty write-back lines across an S-state transition is not safe |
| `ACPI_ACQUIRE_GLOBAL_LOCK` / `ACPI_RELEASE_GLOBAL_LOCK` | `Acquired = 1` / `Pending = 0` — pretend | bit-exact port of ACPICA's own x86 `acwin.h`, with atomics | the caller (`evglock.c`) would believe it owns a lock it never took and would skip the GBL_RLS handshake. The macro's pointer argument is the **FACS table** (`&GLptr->GlobalLock`), not the lock word |

Both are `#undef` + `#define`, so no "macro redefined" warnings.  For a free lock
word (`GlobalLock == 0`, the normal case, including QEMU) the acquire reports
success exactly like the old stub did, so nothing about the tested path changes;
the difference shows up when firmware leaves the pending bit or state in that
word.

Not overridden, with the evidence:

| Setting | Live value | Why it is left alone |
|---|---|---|
| `ACPI_SEMAPHORE_NULL` | `NULL` | our OSL handles are `semaphore_t *` (`osl_sync.c`), so `NULL` is the correct sentinel — the `-1` of the old file is the integer-handle convention of the Linux kernel |
| `ACPI_MACHINE_WIDTH` | `64` | already right via `aclinux.h` |
| `ACPI_USE_LOCAL_CACHE` | not defined | we do provide `AcpiOsCreateCache`/`AcpiOsDeleteCache` (`osl.c`), so the OSL-backed cache is the one in use |
| `ACPI_USE_NATIVE_DIVIDE`/`_MATH64` | set by `actypes.h` | its 64-bit branch defines them itself |
| `acpi_save_flags`, `acpi_disable_int`, `ACPI_ASM_MACROS`, `BREAKPOINT3` (old `acintel.h`) | — | no compiled ACPICA component uses them (the only `BREAKPOINT` is the debugger's command table, which is not built); they would be dead weight |

## History

`Cact/drivers/acpi/include/platform/{acenv.h,acintel.h}` were tracked, looked
authoritative, and were **never included by any of the 168 ACPI translation
units** (verified with `-E -H` against every entry in
`compile-commands.json`).  They cost a wrong diagnosis once — "ACPI_MACHINE_WIDTH
32 truncates addresses above 4 GiB", which was never true.  They were deleted in
`93cc176`; recover one with
`git show 93cc176^:Cact/drivers/acpi/include/platform/acenv.h` if its remaining
tailoring is ever wanted.

## How to verify a change here

```sh
# what the platform layer really says (mirrors the build's include resolution)
cc -I Cact/drivers/acpi -I Cact/drivers/acpi/acpica/source/include -dM -E probe.c | grep ACPI_

# ...and that it reached the objects
objdump -d build-meson/Cact/drivers/acpi/libacpica.a.p/*hwsleep.c.o | grep wbinvd
objdump -d build-meson/Cact/drivers/acpi/libacpica.a.p/*evglock.c.o | grep cmpxchg

# ...and that it still boots: the check target boots a PREBUILT ISO from
# ../CactBridge-x86/build/ if one exists, so name the fresh one explicitly
ninja -C build-meson iso-full
CACT_CHECK_ISO=$PWD/build-meson/cact-full.iso ninja -C build-meson check
```

**Not covered by any test here:** contention on the FACS global lock with real
firmware (QEMU never takes it).  The algorithm is a port of ACPICA's own
reference, but that path only exercises on hardware that uses `Acquire(GL)`.
