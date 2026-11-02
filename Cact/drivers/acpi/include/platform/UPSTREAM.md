# ACPICA platform headers — provenance and re-sync

`acenv.h` and `acintel.h` are CactOS's own hand-written platform headers, derived
from ACPICA's `source/include/platform/`.  They are the only ACPICA files tracked
in this repository; the rest is a git-ignored checkout under
[`../acpica/`](../acpica/).

| | |
|---|---|
| Upstream | <https://github.com/acpica/acpica> |
| Ref (pinned) | commit `bc7b8aad0613f03a968d93a92ea025a517936350` (2026-08-19) |
| Sync tool | `python3 tools/vendor_sync.py check acpica-platform` |

The ref is **pinned to a commit** rather than the branch tip on purpose: it is
the ACPICA revision whose licence is the one these files declare (below).
Upstream has since migrated its licensing — at the current tip
(`e85aa3bebaae81ed1e6d163511ac7e1eafe732cf`) the root `LICENSE` is gone, replaced
by `LICENSE.BSD-3-Clause` + `LICENSE.GPL-2.0-only`, and every source file now
carries `SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only`.  Re-pinning the
ref therefore means updating the SPDX line in both tracked files.

## Licensing

At the pinned commit ACPICA is dual-licensed `BSD-2-Clause-Patent OR
GPL-2.0-only`, © 1999-2026 Intel Corporation.  CactOS takes the
**BSD-2-Clause-Patent** option, which is GPLv3-compatible, so the tracked files
ship under

```
SPDX-License-Identifier: (BSD-2-Clause-Patent OR GPL-2.0-only) AND GPL-3.0-or-later
```

with both the Intel and the CactOS copyright lines.  (The `BSD-3-Clause` variant
upstream uses today is equally GPLv3-compatible — only the identifier would
change.)

## These files are hand-merged

They are not patches of upstream text but hand-written replacements: upstream's
`acenv.h` is ~525 lines (mostly the long Intel licence block, which CactOS
replaced with the SPDX header above), CactOS's is ~77.  What remains is a
kernel-specific tailoring — `ACPI_MACHINE_WIDTH`, the machine-select defines,
`ACPI_ASM_MACROS` (`acpi_save_flags`/`acpi_restore_flags`/`acpi_disable_int`/
`acpi_enable_int` via inline `pushfq`/`pop`/`cli`/`sti`), `BREAKPOINT3`,
`ACPI_CACHE_LINE_SIZE`, and a trimmed `acintel.h`.  `check` prints the drift
(upstream-only lines, then ours-only) and the tool never rewrites them.

## The ignored `acpica/` checkout is NOT pristine

`git -C Cact/drivers/acpi/acpica status` shows **two uncommitted local patches**
on top of `bc7b8aa`, both a one-line guard change:

```
source/include/platform/acenv.h:491
source/include/platform/aclinux.h:309
-#ifdef ACPI_USE_STANDARD_HEADERS
+#if defined(ACPI_USE_STANDARD_HEADERS) && !defined(CACT_ACPI_FREESTANDING)
```

**Re-cloning or `git checkout`-ing that tree silently destroys them.**  Keep
them (or re-apply them after any refresh) — they are what lets the CactOS OSL
build ACPICA without libc.

## Re-sync

```sh
python3 tools/vendor_sync.py check acpica-platform           # drift vs the pinned commit
python3 tools/vendor_sync.py check --refresh acpica-platform
```

`update acpica-platform` will not rewrite the two files.  A real re-sync is a
manual merge: read upstream's `acenv.h`/`acintel.h` at the new commit, port what
matters to this kernel, keep the licence header (and update its identifier if
the pin moved past the licensing migration).  The OSL side
(`Cact/drivers/acpi/osl*.c`) is CactOS code and is untouched by any of this.
