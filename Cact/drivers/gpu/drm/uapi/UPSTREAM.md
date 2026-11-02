# DRM uapi headers — provenance and re-sync

`Cact/drivers/gpu/drm/uapi/` holds the DRM ioctl ABI the kernel's `cact_drm`
core and its out-of-tree display drivers agree on.

| File | Origin | SPDX |
|---|---|---|
| `drm.h` | Linux `include/uapi/drm/drm.h` | `MIT` (© Precision Insight / VA Linux) |
| `drm_mode.h` | Linux `include/uapi/drm/drm_mode.h` | `MIT` (© Dave Airlie, Red Hat, Tungsten Graphics, Intel) |
| `drm_fourcc.h` | Linux `include/uapi/drm/drm_fourcc.h` | `MIT` (© Intel) |
| `drm_ioctl.h` | CactOS | `GPL-3.0-or-later` |
| `drm_types.h` | CactOS | `GPL-3.0-or-later` |

Source snapshot: **Linux 7.3.0-rc4**.

## Local modifications

* The `/* SPDX-License-Identifier: MIT */` line and the original copyright
  blocks had been dropped when the headers were copied in; they are restored
  verbatim from the Linux tree, so the licence of these files is explicit again.
* Includes are adapted to this kernel: `drm.h` pulls CactOS's `drm_types.h` and
  `drm_ioctl.h` instead of `<linux/types.h>` / `<asm/ioctl.h>`; `drm_mode.h`
  drops `<linux/bits.h>` / `<linux/const.h>`.
* The contents lag the current Linux tree slightly — a handful of newer
  `DRM_FORMAT_*` / `DRM_MODE_*` defines are not present.  They are not used by
  CactOS yet, so this is deliberate, not drift to preserve blindly.

## Re-sync procedure

```sh
LS="$HOME/Projects/linux import/linux/linux-master"
diff "$LS/include/uapi/drm/drm.h"        Cact/drivers/gpu/drm/uapi/drm.h
diff "$LS/include/uapi/drm/drm_mode.h"   Cact/drivers/gpu/drm/uapi/drm_mode.h
diff "$LS/include/uapi/drm/drm_fourcc.h" Cact/drivers/gpu/drm/uapi/drm_fourcc.h
```

To pick up a new Linux: copy the header, restore its MIT + copyright block,
re-apply the CactOS `#include` adaptation, and keep `drm_ioctl.h` /
`drm_types.h` as they are (they define the `_IOC`-style ioctl encoding and the
fixed-width aliases CactOS uses).  ABI breakage is real here: `cact_drm` and
any `.cctk` display driver must be rebuilt together with a change to these
structs.
