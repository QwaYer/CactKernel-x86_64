#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

"""Idempotent ACPICA patch for the Cact kernel.

Two things happen here, both re-applied on every configure (so a re-cloned
acpica/ tree is fine — nothing here is hand-edited):

1. ACPICA auto-detects Linux (aclinux.h) and, in its user-space (!__KERNEL__)
   mode, defines ACPI_USE_STANDARD_HEADERS, which pulls host <stdlib.h>,
   <string.h>, <ctype.h>.  Those conflict with the kernel's freestanding
   klib.h declarations (atoi/strncpy/strncmp/strlen/strlcpy/strlcat).

   For a freestanding kernel we build ACPICA with -DCACT_ACPI_FREESTANDING and
   gate the system-header includes on that macro, so ACPICA uses its own
   minimal string/memory helpers instead of host libc headers.

2. The end of acenv.h gets `#include "cact_acenv.h"`, which is where CactOS
   overrides ACPICA platform settings that its defaults get wrong (the S-state
   cache flush and the FACS global lock).  See
   Cact/drivers/acpi/PLATFORM.md.

Usage: python3 tools/cact_acpica_patch.py <ACPICA_DIR>
"""

import os
import sys

BUILD_MARK = "CACT_ACPI_FREESTANDING"

OLD_IFDEF = "#ifdef ACPI_USE_STANDARD_HEADERS"
NEW_IFDEF = "#if defined(ACPI_USE_STANDARD_HEADERS) && !defined(CACT_ACPI_FREESTANDING)"

OVERRIDE_MARK = "CACT_ACPI_PLATFORM_OVERRIDES"
OVERRIDE_ANCHOR = "#endif /* __ACENV_H__ */"


def patch_file(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if BUILD_MARK in text:
        return False
    if OLD_IFDEF not in text:
        return False
    text = text.replace(OLD_IFDEF, NEW_IFDEF)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return True


def inject_overrides(path: str) -> bool:
    """Append the CactOS platform overrides to acenv.h, before its guard end."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if OVERRIDE_MARK in text:
        return False
    if OVERRIDE_ANCHOR not in text:
        # Failing the configure is deliberate: silently losing the overrides is
        # exactly the "config that is not live" trap this replaced.
        raise SystemExit(
            f"{path}: {OVERRIDE_ANCHOR!r} not found — ACPICA changed acenv.h; "
            f"update tools/cact_acpica_patch.py")
    block = (f"/* {OVERRIDE_MARK}: CactOS platform overrides "
             f"(see Cact/drivers/acpi/PLATFORM.md) */\n"
             f'#include "cact_acenv.h"\n\n')
    text = text.replace(OVERRIDE_ANCHOR, block + OVERRIDE_ANCHOR, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ACPICA_DIR>", file=sys.stderr)
        return 1
    acpica = sys.argv[1]

    # acenv.h: gate the <stdlib.h>/<string.h>/<ctype.h> block, then include the
    # CactOS platform overrides.
    acenv = os.path.join(acpica, "source", "include", "platform", "acenv.h")
    # aclinux.h: gate the <stddef.h>/<unistd.h>/<stdint.h>/offsetof block.
    aclinux = os.path.join(acpica, "source", "include", "platform", "aclinux.h")

    changed = False
    if patch_file(acenv):
        changed = True
        print(f"[cact_acpica] patched {acenv}")
    if patch_file(aclinux):
        changed = True
        print(f"[cact_acpica] patched {aclinux}")
    if os.path.isfile(acenv) and inject_overrides(acenv):
        changed = True
        print(f"[cact_acpica] injected platform overrides into {acenv}")
    if not changed:
        print("[cact_acpica] already patched (or targets missing) — nothing to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
