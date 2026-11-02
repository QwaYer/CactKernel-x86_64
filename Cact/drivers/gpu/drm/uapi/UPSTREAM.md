# DRM uapi headers — provenance and re-sync

`Cact/drivers/gpu/drm/uapi/` is the DRM ioctl ABI that the in-tree `cact_drm`
core and out-of-tree `.cctk` display drivers agree on.

| Repo path | Origin | SPDX |
|---|---|---|
| `drm.h` | Linux `include/uapi/drm/drm.h`, **body = v6.12** | `MIT` (© Precision Insight / VA Linux) |
| `drm_mode.h` | Linux `include/uapi/drm/drm_mode.h`, **body = v6.13–v6.17** | `MIT` (© Dave Airlie, Red Hat, Tungsten Graphics, Intel) |
| `drm_fourcc.h` | Linux `include/uapi/drm/drm_fourcc.h`, **body = v6.18** | `MIT` (© Intel) |
| `drm_ioctl.h`, `drm_types.h` | — CactOS's own | `GPL-3.0-or-later` |

| | |
|---|---|
| Sync tool | `python3 tools/vendor_sync.py check drm-uapi` |
| Ref the tool diffs against | tag `v7.3-rc4` — commit `93f51579e7df248780214094418f205253383cc5` |

**The three bodies are not a snapshot of one Linux version.** They were imported
from `CactKernel-x86_32` (its commit `43179a3`, 2026-09-18) and copied byte for
byte into the x86_64 fork, and each one is a different vintage: `drm.h` is
v6.12 (v6.10/11/12 are byte-identical), `drm_mode.h` matches v6.13–v6.17
(identical across that range), `drm_fourcc.h` matches v6.18.  The licence blocks
CactOS added (commit `3e2bcd7`) are the **v7.2+/v7.3-rc4** form — `SPDX-License-
Identifier: MIT` plus the copyright lines; the v6.12–v6.18 originals used the
older form with the full MIT permission paragraph.  Both are MIT with the same
holders, so nothing turns on the difference, but do not expect the header text
to match the body's vintage.

## Local edits, per file

Beyond the version lag, these are CactOS's own changes:

* `drm.h`
  * the `#if defined(__KERNEL__) … #elif defined(__linux__) … #else /* BSDs */ …`
    include/typedef block (`<linux/types.h>`, `<asm/ioctl.h>`, `stdint.h`,
    `<sys/ioccom.h>`, …) is replaced by `drm_types.h` + `drm_ioctl.h`;
  * every `__user` annotation is dropped (15 sites);
  * the `#ifndef __KERNEL__` / `#endif` pair around the typedef area is dropped.
* `drm_mode.h`
  * drops `<linux/bits.h>` / `<linux/const.h>`;
  * **adds** `struct drm_color_ctm_3x4` (upstream only gained it in v6.19; it is
    defined but not used anywhere in this repo);
  * **removes** `struct drm_plane_size_hint` and its kernel-doc (present
    upstream in every tag from v6.11 on).
* `drm_fourcc.h`
  * **adds** `DRM_FORMAT_MOD_ARM_INTERLEAVED_64K` (upstream gained it in v6.19).

`python3 tools/vendor_sync.py check drm-uapi` prints how far each file is from
`v7.3-rc4` — currently a few hundred additive lines each, i.e. 6–7 releases of
new `DRM_FORMAT_*` / `DRM_MODE_*` defines this ABI has not taken yet.

## Why this tree is hand-merged, not auto-synced

The tool keeps these three files as ours and reports the drift rather than
rewriting them: they are an ABI, every adaptation above is a deliberate local
edit, and upstream's delta is additive.  Refreshing means *taking upstream and
re-applying the edits* — and then rebuilding `cact_drm` and every `.cctk`
display driver against the new structs, keeping the `DRM_IOCTL_*` numbers put.

## Re-sync

```sh
python3 tools/vendor_sync.py check drm-uapi            # drift vs v7.3-rc4
python3 tools/vendor_sync.py check --refresh drm-uapi  # re-fetch (sparse clone)
```

`update drm-uapi` will not touch these three files; it only refreshes what the
manifest maps.  To move to a newer Linux, pick the per-file base you want, copy
the header in, restore its licence block, re-apply that file's edits from the
list above, and update the vintage recorded in this table.
