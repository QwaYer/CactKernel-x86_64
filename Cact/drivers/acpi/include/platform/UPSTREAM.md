# ACPICA platform headers — provenance and re-sync

`acenv.h` and `acintel.h` are CactOS's edited copies of ACPICA's
`source/include/platform/` headers.  They are the only ACPICA files tracked in
this repository — the rest of ACPICA is a git-ignored checkout under
[`../acpica/`](../acpica/) (see below).

| | |
|---|---|
| Upstream | <https://github.com/acpica/acpica> |
| Ref | `HEAD` (unpinned: whatever the default branch is at fetch time) |
| Commit seen by the last `check` | `e85aa3bebaae81ed1e6d163511ac7e1eafe732cf` |
| Local ignored checkout | `../acpica`, commit `bc7b8aad0613f03a968d93a92ea025a517936350` (2026-08-19) — **older** than upstream |
| Sync tool | `python3 tools/vendor_sync.py check acpica-platform` |

## Licensing

ACPICA is dual-licensed `BSD-2-Clause-Patent OR GPL-2.0-only`, © 1999-2026 Intel
Corporation (see `../acpica/LICENSE`).  CactOS takes the **BSD-2-Clause-Patent**
option, which is GPLv3-compatible, so the modified files ship under

```
SPDX-License-Identifier: (BSD-2-Clause-Patent OR GPL-2.0-only) AND GPL-3.0-or-later
```

with both the Intel and the CactOS copyright lines.

## These files are hand-merged

They differ substantially from the ACPICA originals — the tool reports
`acenv.h +381/-71` and `acintel.h +50/-18`, most of the `-N` being the Intel
copyright/licence block, which CactOS removed and replaced with the SPDX header
above.  The rest is a kernel-specific tailoring: `ACPI_MACHINE_WIDTH`, the
machine-select defines, `ACPI_ASM_MACROS` (`acpi_save_flags`/`acpi_restore_flags`/
`acpi_disable_int`/`acpi_enable_int` via inline `pushfq`/`cli`/`sti`),
`BREAKPOINT3`, `ACPI_CACHE_LINE_SIZE`, and a trimmed `acintel.h`.

## Re-sync

```sh
python3 tools/vendor_sync.py check acpica-platform        # drift vs upstream HEAD
python3 tools/vendor_sync.py check --refresh acpica-platform
```

`update acpica-platform` will not rewrite these two files (marked hand-merged).
A real re-sync is a manual merge: skim the upstream `acenv.h`/`acintel.h` for
changes that matter to this kernel, port them on top of the CactOS version, and
keep the licence header.  When refreshing the ignored `acpica/` checkout, note
that only these two headers are community-visible in this repo — the OSL side
(`Cact/drivers/acpi/osl*.c`) is CactOS code and is not touched by any of this.
