# DRM uapi headers — provenance and re-sync

`Cact/drivers/gpu/drm/uapi/` is the DRM ioctl ABI that the in-tree `cact_drm`
core and out-of-tree `.cctk` display drivers agree on.

| | |
|---|---|
| Upstream | <https://github.com/torvalds/linux> `include/uapi/drm/` |
| Ref | tag `v7.3-rc4` — commit `93f51579e7df248780214094418f205253383cc5` |
| Sync tool | `python3 tools/vendor_sync.py check drm-uapi` |

| Repo path | Origin | SPDX |
|---|---|---|
| `drm.h` | Linux `include/uapi/drm/drm.h` | `MIT` (© Precision Insight / VA Linux) |
| `drm_mode.h` | Linux `include/uapi/drm/drm_mode.h` | `MIT` (© Dave Airlie, Red Hat, Tungsten Graphics, Intel) |
| `drm_fourcc.h` | Linux `include/uapi/drm/drm_fourcc.h` | `MIT` (© Intel) |
| `drm_ioctl.h`, `drm_types.h` | — CactOS's own | `GPL-3.0-or-later` |

## These three files are hand-merged, not auto-synced

They are **older than the pinned ref and adapted**, so the tool keeps them as
ours and reports the drift instead of rewriting them:

```
drm.h         +140/-31 lines vs upstream
drm_mode.h    +281/-1  lines vs upstream
drm_fourcc.h  +229/-28 lines vs upstream
```

The `+N` is upstream having moved on: newer `DRM_FORMAT_*` / `DRM_MODE_*` defines
that CactOS does not use yet (the copies are roughly a 6.12–6.15-era selection).
The `-N` is CactOS's own adaptation:

* `drm.h` — the `#if defined(__KERNEL__) … #elif defined(__linux__) … #else /* BSDs */ …`
  include/typedef block (which pulls `<linux/types.h>`, `<asm/ioctl.h>`,
  `stdint.h`, …) is replaced by CactOS's `drm_types.h` + `drm_ioctl.h`, and the
  `__user` annotations are dropped.  The licence header is identical to upstream.
* `drm_mode.h` — drops `<linux/bits.h>` / `<linux/const.h>`; otherwise identical
  to upstream apart from the newer defines.
* `drm_fourcc.h` — licence header identical; only the newer format defines differ.

Because the upstream delta is purely additive, a refresh is "take upstream and
re-apply the two adaptations above" — but it is a deliberate act: this is an ABI,
so `cact_drm` and every `.cctk` display driver must be rebuilt with it, and the
`DRM_IOCTL_*` numbers must stay put.

## Re-sync

```sh
python3 tools/vendor_sync.py check drm-uapi       # shows the drift above
python3 tools/vendor_sync.py check --refresh drm-uapi
```

`update drm-uapi` will not touch these three files (they are marked hand-merged);
it only refreshes what the manifest maps.  To actually take a newer Linux, copy
the header in, restore its MIT + copyright block, re-apply the include/`__user`
adaptation, and keep `drm_ioctl.h` / `drm_types.h` as they are.
