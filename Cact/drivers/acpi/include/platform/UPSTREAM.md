# ACPICA platform headers — provenance and re-sync

`acenv.h` and `acintel.h` are CactOS's edited copies of ACPICA's
`source/include/platform/` headers.  They are the only ACPICA files tracked in
this repository — the rest of ACPICA lives, unmodified and git-ignored, under
[`../acpica/`](../acpica/) (a checkout of <https://github.com/acpica/acpica>).

Upstream revision the copies were taken from:
`bc7b8aad0613f03a968d93a92ea025a517936350` (2026-08-19).

## Licensing

ACPICA is dual-licensed `BSD-2-Clause-Patent OR GPL-2.0-only`, © 1999-2026 Intel
Corporation (see `../acpica/LICENSE`).  CactOS takes the **BSD-2-Clause-Patent**
option, which is GPLv3-compatible, so the modified files ship under

```
SPDX-License-Identifier: (BSD-2-Clause-Patent OR GPL-2.0-only) AND GPL-3.0-or-later
```

with both the Intel and the CactOS copyright lines.

## Local modifications

The Intel copyright/licence block was dropped when the headers were copied in
and the files were then tailored to this kernel:

* `acenv.h`: `ACPI_MACHINE_WIDTH`, the machine-select defines, `ACPI_ASM_MACROS`
  (`acpi_save_flags`/`acpi_restore_flags`/`acpi_disable_int`/`acpi_enable_int`
  via inline `pushfq`/`cli`/`sti`), `BREAKPOINT3`, `ACPI_CACHE_LINE_SIZE`.
* `acintel.h`: trimmed to the parts that matter for a GCC/Clang build.

Both files differ substantially from the ACPICA originals — re-syncing them is
a manual, careful merge, not a copy.

## Re-sync procedure

```sh
A=Cact/drivers/acpi/acpica/source/include/platform
diff "$A/acenv.h"   Cact/drivers/acpi/include/platform/acenv.h
diff "$A/acintel.h" Cact/drivers/acpi/include/platform/acintel.h
```

When updating the `acpica/` checkout, re-read the upstream headers, port the
CactOS edit on top, and keep the licence header above.  The OSL side
(`Cact/drivers/acpi/osl*.c`) is CactOS code and is not touched by this.
